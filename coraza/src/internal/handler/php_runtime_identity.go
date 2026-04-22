package handler

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

type phpRuntimeResolvedIdentity struct {
	ConfiguredUser  string
	ConfiguredGroup string
	EffectiveUser   string
	EffectiveGroup  string
	UID             uint32
	GID             uint32
}

func resolvePHPRuntimeIdentity(mat PHPRuntimeMaterializedStatus) (phpRuntimeResolvedIdentity, error) {
	currentUID := uint32(os.Geteuid())
	currentGID := uint32(os.Getegid())
	currentUser := lookupUserLabel(currentUID)
	currentGroup := lookupGroupLabel(currentGID)
	out := phpRuntimeResolvedIdentity{
		ConfiguredUser:  strings.TrimSpace(mat.RunUser),
		ConfiguredGroup: strings.TrimSpace(mat.RunGroup),
		EffectiveUser:   currentUser,
		EffectiveGroup:  currentGroup,
		UID:             currentUID,
		GID:             currentGID,
	}

	if out.ConfiguredUser != "" {
		uid, label, primaryGID, err := resolvePHPRuntimeUserSpec(out.ConfiguredUser)
		if err != nil {
			return phpRuntimeResolvedIdentity{}, fmt.Errorf("runtime %q run_user: %w", mat.RuntimeID, err)
		}
		out.UID = uid
		out.EffectiveUser = label
		if out.ConfiguredGroup == "" {
			if primaryGID == nil {
				return phpRuntimeResolvedIdentity{}, fmt.Errorf("runtime %q run_group is required when run_user %q has no passwd entry", mat.RuntimeID, out.ConfiguredUser)
			}
			out.GID = *primaryGID
			out.EffectiveGroup = lookupGroupLabel(*primaryGID)
		}
	}

	if out.ConfiguredGroup != "" {
		gid, label, err := resolvePHPRuntimeGroupSpec(out.ConfiguredGroup)
		if err != nil {
			return phpRuntimeResolvedIdentity{}, fmt.Errorf("runtime %q run_group: %w", mat.RuntimeID, err)
		}
		out.GID = gid
		out.EffectiveGroup = label
	}
	return out, nil
}

func resolvePHPRuntimeUserSpec(spec string) (uint32, string, *uint32, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return 0, "", nil, fmt.Errorf("is required")
	}
	if numeric, ok := parseRuntimeUint32(spec); ok {
		if entry, err := user.LookupId(spec); err == nil {
			primaryGID, _ := parseRuntimeUint32(entry.Gid)
			return numeric, entry.Username, &primaryGID, nil
		}
		return numeric, spec, nil, nil
	}
	entry, err := user.Lookup(spec)
	if err != nil {
		return 0, "", nil, fmt.Errorf("lookup failed: %w", err)
	}
	uid, ok := parseRuntimeUint32(entry.Uid)
	if !ok {
		return 0, "", nil, fmt.Errorf("uid for %q is invalid", spec)
	}
	primaryGID, ok := parseRuntimeUint32(entry.Gid)
	if !ok {
		return 0, "", nil, fmt.Errorf("primary gid for %q is invalid", spec)
	}
	return uid, entry.Username, &primaryGID, nil
}

func resolvePHPRuntimeGroupSpec(spec string) (uint32, string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return 0, "", fmt.Errorf("is required")
	}
	if numeric, ok := parseRuntimeUint32(spec); ok {
		if entry, err := user.LookupGroupId(spec); err == nil {
			return numeric, entry.Name, nil
		}
		return numeric, spec, nil
	}
	entry, err := user.LookupGroup(spec)
	if err != nil {
		return 0, "", fmt.Errorf("lookup failed: %w", err)
	}
	gid, ok := parseRuntimeUint32(entry.Gid)
	if !ok {
		return 0, "", fmt.Errorf("gid for %q is invalid", spec)
	}
	return gid, entry.Name, nil
}

func validatePHPRuntimeLaunch(mat PHPRuntimeMaterializedStatus, identity phpRuntimeResolvedIdentity) error {
	if err := validatePHPRuntimePrivilegeTransition(identity); err != nil {
		return err
	}
	if err := ensurePHPRuntimeRuntimeDirAccess(mat, identity); err != nil {
		return err
	}
	if err := validatePHPRuntimeDocumentRoots(mat, identity); err != nil {
		return err
	}
	return nil
}

func validatePHPRuntimePrivilegeTransition(identity phpRuntimeResolvedIdentity) error {
	currentUID := uint32(os.Geteuid())
	currentGID := uint32(os.Getegid())
	if currentUID == identity.UID && currentGID == identity.GID {
		return nil
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("current process uid=%d gid=%d cannot switch to runtime uid=%d gid=%d without root privileges", currentUID, currentGID, identity.UID, identity.GID)
	}
	return nil
}

func ensurePHPRuntimeRuntimeDirAccess(mat PHPRuntimeMaterializedStatus, identity phpRuntimeResolvedIdentity) error {
	runtimeDir := strings.TrimSpace(mat.RuntimeDir)
	if runtimeDir == "" {
		runtimeDir = filepath.Dir(mat.ConfigFile)
	}
	if runtimeDir == "" {
		return fmt.Errorf("runtime %q runtime_dir is empty", mat.RuntimeID)
	}
	if os.Geteuid() == 0 && (identity.UID != 0 || identity.GID != 0) {
		if err := filepath.Walk(runtimeDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			return os.Chown(path, int(identity.UID), int(identity.GID))
		}); err != nil {
			return fmt.Errorf("runtime %q runtime_dir ownership update failed: %w", mat.RuntimeID, err)
		}
	}
	if err := validateRuntimePathAccess(runtimeDir, identity.UID, identity.GID, 0o7); err != nil {
		return fmt.Errorf("runtime %q runtime_dir %q: %w", mat.RuntimeID, runtimeDir, err)
	}
	if err := validateRuntimePathAccess(mat.ConfigFile, identity.UID, identity.GID, 0o4); err != nil {
		return fmt.Errorf("runtime %q config_file %q: %w", mat.RuntimeID, mat.ConfigFile, err)
	}
	for _, poolFile := range mat.PoolFiles {
		if err := validateRuntimePathAccess(poolFile, identity.UID, identity.GID, 0o4); err != nil {
			return fmt.Errorf("runtime %q pool file %q: %w", mat.RuntimeID, poolFile, err)
		}
	}
	return nil
}

func validatePHPRuntimeDocumentRoots(mat PHPRuntimeMaterializedStatus, identity phpRuntimeResolvedIdentity) error {
	docroots := append([]string(nil), mat.DocumentRoots...)
	sort.Strings(docroots)
	for _, docroot := range docroots {
		info, err := os.Stat(docroot)
		if err != nil {
			return fmt.Errorf("runtime %q document_root %q: %w", mat.RuntimeID, docroot, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("runtime %q document_root %q must be a directory", mat.RuntimeID, docroot)
		}
		if err := validateRuntimePathAccess(docroot, identity.UID, identity.GID, 0o5); err != nil {
			return fmt.Errorf("runtime %q document_root %q: %w", mat.RuntimeID, docroot, err)
		}
	}
	return nil
}

func validateRuntimePathAccess(path string, uid uint32, gid uint32, need os.FileMode) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if uid == 0 {
		return nil
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	perms := info.Mode().Perm()
	var granted os.FileMode
	switch {
	case stat.Uid == uid:
		granted = (perms >> 6) & 0o7
	case stat.Gid == gid:
		granted = (perms >> 3) & 0o7
	default:
		granted = perms & 0o7
	}
	if granted&need != need {
		return fmt.Errorf("permission denied; need %03o for uid=%d gid=%d", need, uid, gid)
	}
	return nil
}

func parseRuntimeUint32(value string) (uint32, bool) {
	n, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(n), true
}

func lookupUserLabel(uid uint32) string {
	if entry, err := user.LookupId(strconv.FormatUint(uint64(uid), 10)); err == nil && strings.TrimSpace(entry.Username) != "" {
		return entry.Username
	}
	return strconv.FormatUint(uint64(uid), 10)
}

func lookupGroupLabel(gid uint32) string {
	if entry, err := user.LookupGroupId(strconv.FormatUint(uint64(gid), 10)); err == nil && strings.TrimSpace(entry.Name) != "" {
		return entry.Name
	}
	return strconv.FormatUint(uint64(gid), 10)
}
