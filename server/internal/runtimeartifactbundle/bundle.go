package runtimeartifactbundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	SchemaVersion = 1

	RuntimeFamilyPHPFPM = "php-fpm"

	MaxCompressedBytes   = 512 * 1024 * 1024
	MaxUncompressedBytes = 2 * 1024 * 1024 * 1024
	MaxManifestBytes     = 2 * 1024 * 1024
	MaxMetadataFileBytes = 1 * 1024 * 1024
	MaxFiles             = 100000
)

var (
	ErrNoFiles        = errors.New("runtime artifact has no files")
	hex64Pattern      = regexp.MustCompile(`^[a-f0-9]{64}$`)
	idPattern         = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)
	fileKindPattern   = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)
	metadataPattern   = regexp.MustCompile(`^[ -~]{0,128}$`)
	moduleNamePattern = regexp.MustCompile(`^[A-Za-z0-9._:+-]{1,128}$`)
)

type TargetKey struct {
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	KernelVersion string `json:"kernel_version,omitempty"`
	DistroID      string `json:"distro_id"`
	DistroIDLike  string `json:"distro_id_like,omitempty"`
	DistroVersion string `json:"distro_version"`
}

type FileManifest struct {
	ArchivePath string `json:"archive_path"`
	FileKind    string `json:"file_kind"`
	SHA256      string `json:"sha256"`
	SizeBytes   int64  `json:"size_bytes"`
	Mode        int64  `json:"mode"`
}

type Manifest struct {
	SchemaVersion    int            `json:"schema_version"`
	ArtifactRevision string         `json:"artifact_revision"`
	GeneratedAt      string         `json:"generated_at"`
	RuntimeFamily    string         `json:"runtime_family"`
	RuntimeID        string         `json:"runtime_id"`
	DisplayName      string         `json:"display_name,omitempty"`
	DetectedVersion  string         `json:"detected_version"`
	Target           TargetKey      `json:"target"`
	BuilderVersion   string         `json:"builder_version,omitempty"`
	BuilderProfile   string         `json:"builder_profile,omitempty"`
	Files            []FileManifest `json:"files"`
}

type File struct {
	ArchivePath string
	FileKind    string
	Mode        int64
	Body        []byte
}

type BuildInput struct {
	RuntimeFamily   string
	RuntimeID       string
	DisplayName     string
	DetectedVersion string
	Target          TargetKey
	BuilderVersion  string
	BuilderProfile  string
	GeneratedAt     time.Time
	Files           []File
}

type Build struct {
	Revision         string
	ArtifactHash     string
	Compressed       []byte
	CompressedSize   int64
	UncompressedSize int64
	FileCount        int
	Manifest         Manifest
}

type ParsedFile struct {
	FileManifest
}

type Parsed struct {
	Manifest         Manifest
	Files            []ParsedFile
	Revision         string
	ArtifactHash     string
	CompressedSize   int64
	UncompressedSize int64
	FileCount        int
}

type runtimeJSON struct {
	RuntimeID       string `json:"runtime_id"`
	DisplayName     string `json:"display_name,omitempty"`
	DetectedVersion string `json:"detected_version"`
	Source          string `json:"source,omitempty"`
}

type actualFile struct {
	SHA256    string
	SizeBytes int64
	Mode      int64
	Body      []byte
}

func BuildBundle(input BuildInput) (Build, error) {
	normalized, err := normalizeBuildInput(input)
	if err != nil {
		return Build{}, err
	}
	if len(normalized.Files) == 0 {
		return Build{}, ErrNoFiles
	}
	if normalized.GeneratedAt.IsZero() {
		normalized.GeneratedAt = time.Now().UTC()
	}
	files := make([]File, len(normalized.Files))
	copy(files, normalized.Files)
	sort.Slice(files, func(i, j int) bool {
		return files[i].ArchivePath < files[j].ArchivePath
	})

	manifest := Manifest{
		SchemaVersion:   SchemaVersion,
		GeneratedAt:     normalized.GeneratedAt.UTC().Format(time.RFC3339Nano),
		RuntimeFamily:   normalized.RuntimeFamily,
		RuntimeID:       normalized.RuntimeID,
		DisplayName:     normalized.DisplayName,
		DetectedVersion: normalized.DetectedVersion,
		Target:          normalized.Target,
		BuilderVersion:  normalized.BuilderVersion,
		BuilderProfile:  normalized.BuilderProfile,
		Files:           make([]FileManifest, 0, len(files)),
	}
	for _, file := range files {
		sum := sha256.Sum256(file.Body)
		manifest.Files = append(manifest.Files, FileManifest{
			ArchivePath: file.ArchivePath,
			FileKind:    file.FileKind,
			SHA256:      hex.EncodeToString(sum[:]),
			SizeBytes:   int64(len(file.Body)),
			Mode:        file.Mode,
		})
	}
	if err := validateManifest(manifest); err != nil {
		return Build{}, err
	}
	revision, err := Revision(manifest)
	if err != nil {
		return Build{}, err
	}
	manifest.ArtifactRevision = revision

	var uncompressedSize int64
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		return Build{}, fmt.Errorf("marshal runtime artifact manifest: %w", err)
	}
	if err := writeTarFile(tw, "manifest.json", manifestRaw, 0o644); err != nil {
		return Build{}, err
	}
	uncompressedSize += int64(len(manifestRaw))
	for _, file := range files {
		if err := writeTarFile(tw, file.ArchivePath, file.Body, file.Mode); err != nil {
			return Build{}, err
		}
		uncompressedSize += int64(len(file.Body))
		if uncompressedSize > MaxUncompressedBytes {
			_ = tw.Close()
			return Build{}, fmt.Errorf("runtime artifact exceeds %d uncompressed bytes", MaxUncompressedBytes)
		}
	}
	if err := tw.Close(); err != nil {
		return Build{}, fmt.Errorf("close runtime artifact tar: %w", err)
	}

	var compressed bytes.Buffer
	gw, err := gzip.NewWriterLevel(&compressed, gzip.BestCompression)
	if err != nil {
		return Build{}, err
	}
	gw.ModTime = time.Unix(0, 0).UTC()
	if _, err := gw.Write(tarBuf.Bytes()); err != nil {
		return Build{}, fmt.Errorf("compress runtime artifact: %w", err)
	}
	if err := gw.Close(); err != nil {
		return Build{}, fmt.Errorf("close runtime artifact gzip: %w", err)
	}
	if compressed.Len() > MaxCompressedBytes {
		return Build{}, fmt.Errorf("runtime artifact exceeds %d compressed bytes", MaxCompressedBytes)
	}
	artifactHash := sha256.Sum256(compressed.Bytes())
	return Build{
		Revision:         revision,
		ArtifactHash:     hex.EncodeToString(artifactHash[:]),
		Compressed:       append([]byte(nil), compressed.Bytes()...),
		CompressedSize:   int64(compressed.Len()),
		UncompressedSize: uncompressedSize,
		FileCount:        len(files),
		Manifest:         manifest,
	}, nil
}

func Parse(compressed []byte) (Parsed, error) {
	if len(compressed) == 0 || len(compressed) > MaxCompressedBytes {
		return Parsed{}, fmt.Errorf("invalid runtime artifact compressed size")
	}
	hash := sha256.Sum256(compressed)
	gr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return Parsed{}, fmt.Errorf("open runtime artifact gzip: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	var manifestRaw []byte
	filesByArchivePath := map[string]actualFile{}
	var uncompressedSize int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Parsed{}, fmt.Errorf("read runtime artifact tar: %w", err)
		}
		if hdr == nil {
			continue
		}
		if hdr.Typeflag == tar.TypeDir {
			if _, err := cleanArchivePath(hdr.Name); err != nil {
				return Parsed{}, err
			}
			continue
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			return Parsed{}, fmt.Errorf("runtime artifact contains non-regular entry %q", hdr.Name)
		}
		if hdr.Size < 0 {
			return Parsed{}, fmt.Errorf("runtime artifact contains invalid entry size")
		}
		name, err := cleanArchivePath(hdr.Name)
		if err != nil {
			return Parsed{}, err
		}
		if name == "manifest.json" {
			if manifestRaw != nil {
				return Parsed{}, fmt.Errorf("runtime artifact contains duplicate manifest")
			}
			body, err := readLimitedEntry(tr, MaxManifestBytes)
			if err != nil {
				return Parsed{}, err
			}
			manifestRaw = body
			uncompressedSize += int64(len(body))
			continue
		}
		if !allowedRuntimeArchivePath(name) {
			return Parsed{}, fmt.Errorf("runtime artifact contains unexpected archive path %q", name)
		}
		if _, exists := filesByArchivePath[name]; exists {
			return Parsed{}, fmt.Errorf("runtime artifact contains duplicate archive path %q", name)
		}
		actual, err := hashEntry(tr, hdr.Size, int64(hdr.Mode)&0o777, keepMetadataBody(name))
		if err != nil {
			return Parsed{}, err
		}
		filesByArchivePath[name] = actual
		uncompressedSize += actual.SizeBytes
		if uncompressedSize > MaxUncompressedBytes {
			return Parsed{}, fmt.Errorf("runtime artifact exceeds %d uncompressed bytes", MaxUncompressedBytes)
		}
		if len(filesByArchivePath) > MaxFiles {
			return Parsed{}, fmt.Errorf("runtime artifact exceeds %d files", MaxFiles)
		}
	}
	if len(manifestRaw) == 0 {
		return Parsed{}, fmt.Errorf("runtime artifact manifest is missing")
	}
	var manifest Manifest
	dec := json.NewDecoder(bytes.NewReader(manifestRaw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&manifest); err != nil {
		return Parsed{}, fmt.Errorf("decode runtime artifact manifest: %w", err)
	}
	if err := validateManifest(manifest); err != nil {
		return Parsed{}, err
	}
	revision, err := Revision(manifest)
	if err != nil {
		return Parsed{}, err
	}
	if !secureEqualHex(revision, manifest.ArtifactRevision) {
		return Parsed{}, fmt.Errorf("runtime artifact revision mismatch")
	}
	if len(manifest.Files) != len(filesByArchivePath) {
		return Parsed{}, fmt.Errorf("runtime artifact manifest file count mismatch")
	}
	out := Parsed{
		Manifest:         manifest,
		Files:            make([]ParsedFile, 0, len(manifest.Files)),
		Revision:         revision,
		ArtifactHash:     hex.EncodeToString(hash[:]),
		CompressedSize:   int64(len(compressed)),
		UncompressedSize: uncompressedSize,
		FileCount:        len(manifest.Files),
	}
	for _, entry := range manifest.Files {
		actual, exists := filesByArchivePath[entry.ArchivePath]
		if !exists {
			return Parsed{}, fmt.Errorf("runtime artifact file %q is missing", entry.ArchivePath)
		}
		if actual.SizeBytes != entry.SizeBytes || !secureEqualHex(actual.SHA256, entry.SHA256) || actual.Mode != entry.Mode {
			return Parsed{}, fmt.Errorf("runtime artifact file metadata mismatch for %q", entry.ArchivePath)
		}
		switch entry.ArchivePath {
		case "runtime.json":
			if err := validateRuntimeJSON(actual.Body, manifest); err != nil {
				return Parsed{}, err
			}
		case "modules.json":
			if err := validateModulesJSON(actual.Body); err != nil {
				return Parsed{}, err
			}
		}
		out.Files = append(out.Files, ParsedFile{FileManifest: entry})
	}
	return out, nil
}

func Revision(manifest Manifest) (string, error) {
	normalized := manifest
	normalized.ArtifactRevision = ""
	normalized.GeneratedAt = ""
	sort.Slice(normalized.Files, func(i, j int) bool {
		return normalized.Files[i].ArchivePath < normalized.Files[j].ArchivePath
	})
	raw, err := json.Marshal(normalized)
	if err != nil {
		return "", fmt.Errorf("marshal runtime artifact revision material: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func normalizeBuildInput(input BuildInput) (BuildInput, error) {
	input.RuntimeFamily = strings.TrimSpace(input.RuntimeFamily)
	input.RuntimeID = strings.TrimSpace(input.RuntimeID)
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	input.DetectedVersion = strings.TrimSpace(input.DetectedVersion)
	input.Target = normalizeTarget(input.Target)
	input.BuilderVersion = strings.TrimSpace(input.BuilderVersion)
	input.BuilderProfile = strings.TrimSpace(input.BuilderProfile)
	if err := validateRuntimeIdentity(input.RuntimeFamily, input.RuntimeID); err != nil {
		return BuildInput{}, err
	}
	if err := validateTarget(input.Target); err != nil {
		return BuildInput{}, err
	}
	if !metadataPattern.MatchString(input.DisplayName) || len(input.DisplayName) > 128 ||
		!metadataPattern.MatchString(input.DetectedVersion) || len(input.DetectedVersion) > 128 ||
		!metadataPattern.MatchString(input.BuilderVersion) || len(input.BuilderVersion) > 128 ||
		!metadataPattern.MatchString(input.BuilderProfile) || len(input.BuilderProfile) > 128 {
		return BuildInput{}, fmt.Errorf("invalid runtime artifact metadata")
	}
	files, err := normalizeFiles(input.Files)
	if err != nil {
		return BuildInput{}, err
	}
	input.Files = files
	return input, nil
}

func normalizeFiles(files []File) ([]File, error) {
	if len(files) == 0 || len(files) > MaxFiles {
		return nil, fmt.Errorf("invalid runtime artifact file count")
	}
	out := make([]File, 0, len(files))
	seen := map[string]struct{}{}
	for _, file := range files {
		archivePath, err := cleanArchivePath(file.ArchivePath)
		if err != nil {
			return nil, err
		}
		if !allowedRuntimeArchivePath(archivePath) {
			return nil, fmt.Errorf("runtime artifact contains unexpected archive path %q", archivePath)
		}
		file.ArchivePath = archivePath
		file.FileKind = strings.TrimSpace(file.FileKind)
		if !fileKindPattern.MatchString(file.FileKind) {
			return nil, fmt.Errorf("invalid runtime artifact file kind")
		}
		if len(file.Body) == 0 {
			return nil, fmt.Errorf("runtime artifact file %q is empty", file.ArchivePath)
		}
		if file.Mode == 0 {
			file.Mode = 0o644
		}
		file.Mode &= 0o777
		if _, ok := seen[file.ArchivePath]; ok {
			return nil, fmt.Errorf("duplicate runtime artifact archive path %q", file.ArchivePath)
		}
		seen[file.ArchivePath] = struct{}{}
		out = append(out, file)
	}
	return out, nil
}

func validateManifest(manifest Manifest) error {
	if manifest.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported runtime artifact schema_version")
	}
	if manifest.ArtifactRevision != "" && !hex64Pattern.MatchString(manifest.ArtifactRevision) {
		return fmt.Errorf("invalid runtime artifact revision")
	}
	if _, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(manifest.GeneratedAt)); err != nil {
		return fmt.Errorf("invalid runtime artifact generated_at")
	}
	if err := validateRuntimeIdentity(manifest.RuntimeFamily, manifest.RuntimeID); err != nil {
		return err
	}
	if err := validateTarget(normalizeTarget(manifest.Target)); err != nil {
		return err
	}
	if !metadataPattern.MatchString(manifest.DisplayName) || len(manifest.DisplayName) > 128 ||
		!metadataPattern.MatchString(manifest.DetectedVersion) || len(manifest.DetectedVersion) > 128 ||
		!metadataPattern.MatchString(manifest.BuilderVersion) || len(manifest.BuilderVersion) > 128 ||
		!metadataPattern.MatchString(manifest.BuilderProfile) || len(manifest.BuilderProfile) > 128 {
		return fmt.Errorf("invalid runtime artifact metadata")
	}
	if len(manifest.Files) == 0 || len(manifest.Files) > MaxFiles {
		return fmt.Errorf("invalid runtime artifact file count")
	}
	required := map[string]bool{
		"runtime.json": false,
		"modules.json": false,
		"php-fpm":      false,
		"php":          false,
	}
	seen := map[string]struct{}{}
	for _, file := range manifest.Files {
		if err := validateManifestFile(file); err != nil {
			return err
		}
		if _, ok := seen[file.ArchivePath]; ok {
			return fmt.Errorf("duplicate runtime artifact archive path %q", file.ArchivePath)
		}
		seen[file.ArchivePath] = struct{}{}
		if _, ok := required[file.ArchivePath]; ok {
			required[file.ArchivePath] = true
		}
	}
	for name, found := range required {
		if !found {
			return fmt.Errorf("runtime artifact required file %q is missing", name)
		}
	}
	return nil
}

func validateManifestFile(file FileManifest) error {
	archivePath, err := cleanArchivePath(file.ArchivePath)
	if err != nil {
		return err
	}
	if archivePath != file.ArchivePath || !allowedRuntimeArchivePath(archivePath) {
		return fmt.Errorf("runtime artifact contains unexpected archive path %q", file.ArchivePath)
	}
	if !fileKindPattern.MatchString(file.FileKind) || !hex64Pattern.MatchString(strings.ToLower(strings.TrimSpace(file.SHA256))) {
		return fmt.Errorf("invalid runtime artifact file metadata")
	}
	if err := validateFileKindForPath(archivePath, file.FileKind); err != nil {
		return err
	}
	if file.SHA256 != strings.ToLower(file.SHA256) {
		return fmt.Errorf("invalid runtime artifact file hash")
	}
	if file.SizeBytes <= 0 || file.SizeBytes > MaxUncompressedBytes {
		return fmt.Errorf("invalid runtime artifact file size")
	}
	if file.Mode < 0 || file.Mode > 0o777 {
		return fmt.Errorf("invalid runtime artifact file mode")
	}
	return nil
}

func validateFileKindForPath(archivePath, fileKind string) error {
	switch archivePath {
	case "runtime.json", "modules.json":
		if fileKind != "metadata" {
			return fmt.Errorf("invalid runtime artifact metadata file kind")
		}
	case "php-fpm", "php":
		if fileKind != "binary" {
			return fmt.Errorf("invalid runtime artifact binary file kind")
		}
	default:
		if strings.HasPrefix(archivePath, "rootfs/") && fileKind == "rootfs" {
			return nil
		}
		return fmt.Errorf("invalid runtime artifact support file kind")
	}
	return nil
}

func validateRuntimeIdentity(runtimeFamily, runtimeID string) error {
	if strings.TrimSpace(runtimeFamily) != RuntimeFamilyPHPFPM {
		return fmt.Errorf("unsupported runtime artifact family")
	}
	switch strings.TrimSpace(runtimeID) {
	case "php83", "php84", "php85":
		return nil
	default:
		return fmt.Errorf("unsupported runtime artifact id")
	}
}

func validateTarget(target TargetKey) error {
	if target.OS == "" || target.Arch == "" || target.DistroID == "" || target.DistroVersion == "" {
		return fmt.Errorf("runtime artifact target is incomplete")
	}
	if !metadataPattern.MatchString(target.OS) || len(target.OS) > 32 ||
		!metadataPattern.MatchString(target.Arch) || len(target.Arch) > 32 ||
		!metadataPattern.MatchString(target.KernelVersion) || len(target.KernelVersion) > 128 ||
		!metadataPattern.MatchString(target.DistroID) || len(target.DistroID) > 64 ||
		!metadataPattern.MatchString(target.DistroIDLike) || len(target.DistroIDLike) > 128 ||
		!metadataPattern.MatchString(target.DistroVersion) || len(target.DistroVersion) > 64 {
		return fmt.Errorf("invalid runtime artifact target")
	}
	return nil
}

func validateRuntimeJSON(raw []byte, manifest Manifest) error {
	if len(raw) == 0 || len(raw) > MaxMetadataFileBytes {
		return fmt.Errorf("invalid runtime.json size")
	}
	var meta runtimeJSON
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&meta); err != nil {
		return fmt.Errorf("decode runtime.json: %w", err)
	}
	if strings.TrimSpace(meta.RuntimeID) != manifest.RuntimeID {
		return fmt.Errorf("runtime.json runtime_id mismatch")
	}
	if strings.TrimSpace(meta.DetectedVersion) != manifest.DetectedVersion {
		return fmt.Errorf("runtime.json detected_version mismatch")
	}
	if !metadataPattern.MatchString(meta.DisplayName) || len(meta.DisplayName) > 128 ||
		!metadataPattern.MatchString(meta.Source) || len(meta.Source) > 32 {
		return fmt.Errorf("invalid runtime.json metadata")
	}
	return nil
}

func validateModulesJSON(raw []byte) error {
	if len(raw) == 0 || len(raw) > MaxMetadataFileBytes {
		return fmt.Errorf("invalid modules.json size")
	}
	var modules []string
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&modules); err != nil {
		return fmt.Errorf("decode modules.json: %w", err)
	}
	if len(modules) > MaxFiles {
		return fmt.Errorf("modules.json has too many modules")
	}
	seen := map[string]struct{}{}
	for _, module := range modules {
		module = strings.TrimSpace(module)
		if !moduleNamePattern.MatchString(module) {
			return fmt.Errorf("modules.json contains invalid module name")
		}
		if _, ok := seen[module]; ok {
			return fmt.Errorf("modules.json contains duplicate module name")
		}
		seen[module] = struct{}{}
	}
	return nil
}

func normalizeTarget(target TargetKey) TargetKey {
	return TargetKey{
		OS:            strings.TrimSpace(target.OS),
		Arch:          strings.TrimSpace(target.Arch),
		KernelVersion: strings.TrimSpace(target.KernelVersion),
		DistroID:      strings.TrimSpace(target.DistroID),
		DistroIDLike:  strings.TrimSpace(target.DistroIDLike),
		DistroVersion: strings.TrimSpace(target.DistroVersion),
	}
}

func allowedRuntimeArchivePath(name string) bool {
	switch name {
	case "runtime.json", "modules.json", "php-fpm", "php":
		return true
	default:
		return strings.HasPrefix(name, "rootfs/")
	}
}

func cleanArchivePath(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.Contains(raw, "\x00") || strings.HasPrefix(raw, "/") || strings.Contains(raw, "\\") {
		return "", fmt.Errorf("runtime artifact contains unsafe archive path")
	}
	parts := strings.Split(raw, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("runtime artifact contains unsafe archive path")
		}
	}
	cleaned := path.Clean(raw)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || len(cleaned) > 512 {
		return "", fmt.Errorf("runtime artifact contains unsafe archive path")
	}
	return cleaned, nil
}

func keepMetadataBody(name string) bool {
	return name == "runtime.json" || name == "modules.json"
}

func hashEntry(r io.Reader, expectedSize int64, mode int64, keepBody bool) (actualFile, error) {
	h := sha256.New()
	var body bytes.Buffer
	limit := expectedSize + 1
	if keepBody && expectedSize > MaxMetadataFileBytes {
		return actualFile{}, fmt.Errorf("runtime artifact metadata file is too large")
	}
	reader := io.LimitReader(r, limit)
	var written int64
	var err error
	if keepBody {
		written, err = io.Copy(io.MultiWriter(h, &body), reader)
	} else {
		written, err = io.Copy(h, reader)
	}
	if err != nil {
		return actualFile{}, fmt.Errorf("read runtime artifact file: %w", err)
	}
	if written != expectedSize {
		return actualFile{}, fmt.Errorf("runtime artifact file size mismatch")
	}
	return actualFile{
		SHA256:    hex.EncodeToString(h.Sum(nil)),
		SizeBytes: written,
		Mode:      mode,
		Body:      body.Bytes(),
	}, nil
}

func readLimitedEntry(r io.Reader, max int64) ([]byte, error) {
	var buf bytes.Buffer
	n, err := io.Copy(&buf, io.LimitReader(r, max+1))
	if err != nil {
		return nil, fmt.Errorf("read runtime artifact entry: %w", err)
	}
	if n > max {
		return nil, fmt.Errorf("runtime artifact entry exceeds %d bytes", max)
	}
	return buf.Bytes(), nil
}

func writeTarFile(tw *tar.Writer, name string, body []byte, mode int64) error {
	if mode == 0 {
		mode = 0o644
	}
	hdr := &tar.Header{
		Name:    name,
		Mode:    mode & 0o777,
		Size:    int64(len(body)),
		ModTime: time.Unix(0, 0).UTC(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("write runtime artifact header %q: %w", name, err)
	}
	if _, err := tw.Write(body); err != nil {
		return fmt.Errorf("write runtime artifact body %q: %w", name, err)
	}
	return nil
}

func secureEqualHex(a, b string) bool {
	a = strings.ToLower(strings.TrimSpace(a))
	b = strings.ToLower(strings.TrimSpace(b))
	if !hex64Pattern.MatchString(a) || !hex64Pattern.MatchString(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
