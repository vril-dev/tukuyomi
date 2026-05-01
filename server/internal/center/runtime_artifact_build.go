package center

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tukuyomi/internal/buildinfo"
	"tukuyomi/internal/runtimeartifactbundle"
)

const (
	RuntimeBuildStatusQueued    = "queued"
	RuntimeBuildStatusRunning   = "running"
	RuntimeBuildStatusSucceeded = "succeeded"
	RuntimeBuildStatusFailed    = "failed"

	runtimeBuildLogLimit      = 64 * 1024
	runtimeBuildTimeout       = 60 * time.Minute
	runtimeBuilderRootEnv     = "TUKUYOMI_CENTER_RUNTIME_BUILDER_ROOT"
	runtimeBuildDataDirEnv    = "TUKUYOMI_RUNTIME_DATA_DIR"
	runtimeBuildDockerTimeout = 3 * time.Second
)

var (
	ErrRuntimeBuilderUnavailable = errors.New("runtime builder is unavailable")
	ErrRuntimeBuildInProgress    = errors.New("runtime build is already running")

	runtimeBuildJobSeq uint64
	runtimeBuildMu     sync.Mutex
	runtimeBuildJobs                            = map[string]RuntimeBuildJob{}
	runtimeBuildLocks                           = map[string]string{}
	runtimeBuildRunner centerRuntimeBuildRunner = dockerCenterRuntimeBuildRunner{}
)

type RuntimeBuilderCapabilities struct {
	Available       bool                       `json:"available"`
	DockerAvailable bool                       `json:"docker_available"`
	PHPFPMSupported bool                       `json:"php_fpm_supported"`
	PSGISupported   bool                       `json:"psgi_supported"`
	Message         string                     `json:"message,omitempty"`
	Runtimes        []RuntimeBuildRuntimeState `json:"runtimes"`
}

type RuntimeBuildRuntimeState struct {
	RuntimeFamily string `json:"runtime_family"`
	RuntimeID     string `json:"runtime_id"`
	Supported     bool   `json:"supported"`
	Message       string `json:"message,omitempty"`
}

type RuntimeBuildStart struct {
	DeviceID      string
	RuntimeFamily string
	RuntimeID     string
	Assign        bool
	Reason        string
	Actor         string
}

type RuntimeBuildJob struct {
	JobID          string                   `json:"job_id"`
	Status         string                   `json:"status"`
	DeviceID       string                   `json:"device_id"`
	RuntimeFamily  string                   `json:"runtime_family"`
	RuntimeID      string                   `json:"runtime_id"`
	Target         RuntimeTargetKey         `json:"target"`
	Assign         bool                     `json:"assign"`
	Reason         string                   `json:"reason,omitempty"`
	Artifact       *RuntimeArtifactRecord   `json:"artifact,omitempty"`
	Assignment     *RuntimeAssignmentRecord `json:"assignment,omitempty"`
	Error          string                   `json:"error,omitempty"`
	Log            string                   `json:"log,omitempty"`
	QueuedAtUnix   int64                    `json:"queued_at_unix"`
	StartedAtUnix  int64                    `json:"started_at_unix"`
	FinishedAtUnix int64                    `json:"finished_at_unix"`
	UpdatedAtUnix  int64                    `json:"updated_at_unix"`
}

type centerRuntimeBuildExecution struct {
	RuntimeFamily string
	RuntimeID     string
	Target        RuntimeTargetKey
}

type centerRuntimeBuildRunner interface {
	Capabilities(context.Context) RuntimeBuilderCapabilities
	Build(context.Context, centerRuntimeBuildExecution) (runtimeartifactbundle.Build, string, error)
}

type dockerCenterRuntimeBuildRunner struct{}

type centerRuntimeBuilderRoot struct {
	Root       string
	ScriptPath string
	Dockerfile string
}

type phpRuntimeBuildMetadata struct {
	RuntimeID       string `json:"runtime_id"`
	DisplayName     string `json:"display_name"`
	DetectedVersion string `json:"detected_version"`
	BinaryPath      string `json:"binary_path,omitempty"`
	CLIBinaryPath   string `json:"cli_binary_path,omitempty"`
	PerlPath        string `json:"perl_path,omitempty"`
	StarmanPath     string `json:"starman_path,omitempty"`
	Source          string `json:"source,omitempty"`
}

type limitedRuntimeBuildLog struct {
	buf       bytes.Buffer
	truncated bool
}

func RuntimeBuilderCapabilityStatus(ctx context.Context) RuntimeBuilderCapabilities {
	return runtimeBuildRunner.Capabilities(ctx)
}

func StartRuntimeBuild(ctx context.Context, req RuntimeBuildStart) (RuntimeBuildJob, error) {
	req.DeviceID = strings.TrimSpace(req.DeviceID)
	req.Reason = clampString(req.Reason, 1024)
	req.Actor = clampString(req.Actor, 191)
	if req.Actor == "" {
		req.Actor = "unknown"
	}
	family, runtimeID, err := normalizeRuntimeBuildIdentity(req.RuntimeFamily, req.RuntimeID)
	if err != nil {
		return RuntimeBuildJob{}, err
	}
	req.RuntimeFamily = family
	req.RuntimeID = runtimeID
	if !deviceIDPattern.MatchString(req.DeviceID) {
		return RuntimeBuildJob{}, ErrDeviceStatusNotFound
	}
	device, err := loadRuntimeBuildDevice(ctx, req.DeviceID)
	if err != nil {
		return RuntimeBuildJob{}, err
	}
	if device.Status != DeviceStatusApproved || !device.RuntimeDeploymentSupported {
		return RuntimeBuildJob{}, ErrRuntimeArtifactIncompatible
	}
	target := runtimeTargetFromDevice(device)
	if err := validateRuntimeBuildTarget(target); err != nil {
		return RuntimeBuildJob{}, err
	}
	capability := runtimeBuildRunner.Capabilities(ctx)
	if !runtimeBuildCapabilitySupports(capability, req.RuntimeFamily, req.RuntimeID) {
		return RuntimeBuildJob{}, ErrRuntimeBuilderUnavailable
	}

	lockKey := runtimeBuildLockKey(req.RuntimeFamily, req.RuntimeID, target)
	now := time.Now().UTC().Unix()
	jobID := "rtb-" + strconv.FormatUint(atomic.AddUint64(&runtimeBuildJobSeq, 1), 36) + "-" + strconv.FormatInt(now, 36)
	job := RuntimeBuildJob{
		JobID:         jobID,
		Status:        RuntimeBuildStatusQueued,
		DeviceID:      req.DeviceID,
		RuntimeFamily: req.RuntimeFamily,
		RuntimeID:     req.RuntimeID,
		Target:        target,
		Assign:        req.Assign,
		Reason:        req.Reason,
		QueuedAtUnix:  now,
		UpdatedAtUnix: now,
	}

	runtimeBuildMu.Lock()
	if existing := runtimeBuildLocks[lockKey]; existing != "" {
		runtimeBuildMu.Unlock()
		return RuntimeBuildJob{}, ErrRuntimeBuildInProgress
	}
	runtimeBuildLocks[lockKey] = jobID
	runtimeBuildJobs[jobID] = job
	runtimeBuildMu.Unlock()

	go runRuntimeBuildJob(jobID, lockKey, req, target)
	return job, nil
}

func RuntimeBuildJobStatus(jobID string) (RuntimeBuildJob, bool) {
	jobID = strings.TrimSpace(jobID)
	runtimeBuildMu.Lock()
	defer runtimeBuildMu.Unlock()
	job, ok := runtimeBuildJobs[jobID]
	return job, ok
}

func RuntimeBuildJobsForDevice(deviceID string, limit int) ([]RuntimeBuildJob, error) {
	deviceID = strings.TrimSpace(deviceID)
	if !deviceIDPattern.MatchString(deviceID) {
		return nil, ErrDeviceStatusNotFound
	}
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	runtimeBuildMu.Lock()
	out := make([]RuntimeBuildJob, 0, len(runtimeBuildJobs))
	for _, job := range runtimeBuildJobs {
		if job.DeviceID != deviceID {
			continue
		}
		job.Log = ""
		out = append(out, job)
	}
	runtimeBuildMu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].UpdatedAtUnix != out[j].UpdatedAtUnix {
			return out[i].UpdatedAtUnix > out[j].UpdatedAtUnix
		}
		if out[i].QueuedAtUnix != out[j].QueuedAtUnix {
			return out[i].QueuedAtUnix > out[j].QueuedAtUnix
		}
		return out[i].JobID > out[j].JobID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (dockerCenterRuntimeBuildRunner) Capabilities(ctx context.Context) RuntimeBuilderCapabilities {
	out := RuntimeBuilderCapabilities{
		Runtimes: []RuntimeBuildRuntimeState{
			{RuntimeFamily: RuntimeFamilyPHPFPM, RuntimeID: "php83"},
			{RuntimeFamily: RuntimeFamilyPHPFPM, RuntimeID: "php84"},
			{RuntimeFamily: RuntimeFamilyPHPFPM, RuntimeID: "php85"},
			{RuntimeFamily: RuntimeFamilyPSGI, RuntimeID: "perl536"},
			{RuntimeFamily: RuntimeFamilyPSGI, RuntimeID: "perl538"},
			{RuntimeFamily: RuntimeFamilyPSGI, RuntimeID: "perl540"},
		},
	}
	if err := checkDockerBuilder(ctx); err != nil {
		out.Message = err.Error()
		return out
	}
	out.DockerAvailable = true
	unsupported := make([]string, 0, 2)
	if _, err := findCenterRuntimeBuilderRoot(RuntimeFamilyPHPFPM); err == nil {
		out.PHPFPMSupported = true
	} else {
		unsupported = append(unsupported, err.Error())
	}
	if _, err := findCenterRuntimeBuilderRoot(RuntimeFamilyPSGI); err == nil {
		out.PSGISupported = true
	} else {
		unsupported = append(unsupported, err.Error())
	}
	out.Available = out.PHPFPMSupported || out.PSGISupported
	if !out.Available && len(unsupported) > 0 {
		out.Message = unsupported[0]
	}
	for i := range out.Runtimes {
		switch out.Runtimes[i].RuntimeFamily {
		case RuntimeFamilyPHPFPM:
			out.Runtimes[i].Supported = out.PHPFPMSupported
			if !out.PHPFPMSupported {
				out.Runtimes[i].Message = "PHP-FPM build is not available."
			}
		case RuntimeFamilyPSGI:
			out.Runtimes[i].Supported = out.PSGISupported
			if !out.PSGISupported {
				out.Runtimes[i].Message = "PSGI build is not available."
			}
		}
	}
	return out
}

func (dockerCenterRuntimeBuildRunner) Build(ctx context.Context, req centerRuntimeBuildExecution) (runtimeartifactbundle.Build, string, error) {
	root, err := findCenterRuntimeBuilderRoot(req.RuntimeFamily)
	if err != nil {
		return runtimeartifactbundle.Build{}, "", err
	}
	tempDir, err := os.MkdirTemp("", "tukuyomi-runtime-build-*")
	if err != nil {
		return runtimeartifactbundle.Build{}, "", fmt.Errorf("create runtime build workspace: %w", err)
	}
	defer os.RemoveAll(tempDir)

	dataDir := filepath.Join(tempDir, "data")
	dockerConfigDir := filepath.Join(tempDir, "docker-config")
	if err := os.MkdirAll(dockerConfigDir, 0o700); err != nil {
		return runtimeartifactbundle.Build{}, "", fmt.Errorf("create docker build config workspace: %w", err)
	}
	cmd := exec.CommandContext(ctx, root.ScriptPath)
	cmd.Dir = root.Root
	cmd.Env = append(os.Environ(),
		"HOME="+tempDir,
		"DOCKER_CONFIG="+dockerConfigDir,
		"RUNTIME="+req.RuntimeID,
		runtimeBuildDataDirEnv+"="+dataDir,
		"DOCKER_BUILDKIT=1",
	)
	var buildLog limitedRuntimeBuildLog
	cmd.Stdout = &buildLog
	cmd.Stderr = &buildLog
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return runtimeartifactbundle.Build{}, buildLog.String(), ctx.Err()
		}
		return runtimeartifactbundle.Build{}, buildLog.String(), fmt.Errorf("runtime builder failed: %w", err)
	}

	runtimeDir := filepath.Join(dataDir, runtimeBuildDataFamilyDir(req.RuntimeFamily), "binaries", req.RuntimeID)
	built, err := buildRuntimeArtifactFromDirectory(runtimeDir, req, buildLog.String())
	if err != nil {
		return runtimeartifactbundle.Build{}, buildLog.String(), err
	}
	return built, buildLog.String(), nil
}

func runRuntimeBuildJob(jobID, lockKey string, req RuntimeBuildStart, target RuntimeTargetKey) {
	defer func() {
		runtimeBuildMu.Lock()
		delete(runtimeBuildLocks, lockKey)
		runtimeBuildMu.Unlock()
	}()
	now := time.Now().UTC().Unix()
	updateRuntimeBuildJob(jobID, func(job *RuntimeBuildJob) {
		job.Status = RuntimeBuildStatusRunning
		job.StartedAtUnix = now
		job.UpdatedAtUnix = now
	})

	ctx, cancel := context.WithTimeout(context.Background(), runtimeBuildTimeout)
	defer cancel()
	built, logText, err := runtimeBuildRunner.Build(ctx, centerRuntimeBuildExecution{
		RuntimeFamily: req.RuntimeFamily,
		RuntimeID:     req.RuntimeID,
		Target:        target,
	})
	if err != nil {
		finishRuntimeBuildJobFailed(jobID, err, logText)
		return
	}
	artifact, err := StoreRuntimeArtifactBundle(context.Background(), built.Compressed, req.Actor)
	if err != nil {
		finishRuntimeBuildJobFailed(jobID, err, logText)
		return
	}
	var assignment *RuntimeAssignmentRecord
	if req.Assign {
		assigned, err := AssignRuntimeArtifactToDevice(context.Background(), RuntimeAssignmentUpdate{
			DeviceID:         req.DeviceID,
			RuntimeFamily:    req.RuntimeFamily,
			RuntimeID:        req.RuntimeID,
			ArtifactRevision: artifact.ArtifactRevision,
			Reason:           req.Reason,
			AssignedBy:       req.Actor,
		})
		if err != nil {
			finishRuntimeBuildJobFailed(jobID, err, logText)
			return
		}
		assignment = &assigned
	}
	finished := time.Now().UTC().Unix()
	updateRuntimeBuildJob(jobID, func(job *RuntimeBuildJob) {
		job.Status = RuntimeBuildStatusSucceeded
		job.Artifact = &artifact
		job.Assignment = assignment
		job.Log = clampString(logText, runtimeBuildLogLimit)
		job.FinishedAtUnix = finished
		job.UpdatedAtUnix = finished
	})
}

func finishRuntimeBuildJobFailed(jobID string, err error, logText string) {
	finished := time.Now().UTC().Unix()
	updateRuntimeBuildJob(jobID, func(job *RuntimeBuildJob) {
		job.Status = RuntimeBuildStatusFailed
		job.Error = clampString(err.Error(), 1024)
		job.Log = clampString(logText, runtimeBuildLogLimit)
		job.FinishedAtUnix = finished
		job.UpdatedAtUnix = finished
	})
}

func updateRuntimeBuildJob(jobID string, fn func(*RuntimeBuildJob)) {
	runtimeBuildMu.Lock()
	defer runtimeBuildMu.Unlock()
	job, ok := runtimeBuildJobs[jobID]
	if !ok {
		return
	}
	fn(&job)
	runtimeBuildJobs[jobID] = job
}

func loadRuntimeBuildDevice(ctx context.Context, deviceID string) (DeviceRecord, error) {
	var device DeviceRecord
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		return loadDeviceByIDTx(ctx, db, driver, deviceID, &device)
	})
	return device, err
}

func runtimeTargetFromDevice(device DeviceRecord) RuntimeTargetKey {
	return RuntimeTargetKey{
		OS:            strings.TrimSpace(device.OS),
		Arch:          strings.TrimSpace(device.Arch),
		KernelVersion: strings.TrimSpace(device.KernelVersion),
		DistroID:      strings.TrimSpace(device.DistroID),
		DistroIDLike:  strings.TrimSpace(device.DistroIDLike),
		DistroVersion: strings.TrimSpace(device.DistroVersion),
	}
}

func validateRuntimeBuildTarget(target RuntimeTargetKey) error {
	if target.OS != "linux" || target.Arch == "" || target.DistroID == "" || target.DistroVersion == "" {
		return ErrRuntimeArtifactIncompatible
	}
	if target.Arch != goruntime.GOARCH {
		return fmt.Errorf("%w: target architecture requires a matching Center builder", ErrRuntimeArtifactIncompatible)
	}
	return nil
}

func normalizeRuntimeBuildIdentity(runtimeFamily, runtimeID string) (string, string, error) {
	family, id, err := normalizeAssignableRuntimeIdentity(runtimeFamily, runtimeID)
	if err != nil {
		return "", "", err
	}
	return family, id, nil
}

func runtimeBuildCapabilitySupports(capability RuntimeBuilderCapabilities, runtimeFamily, runtimeID string) bool {
	if !capability.Available {
		return false
	}
	for _, item := range capability.Runtimes {
		if item.RuntimeFamily == runtimeFamily && item.RuntimeID == runtimeID {
			return item.Supported
		}
	}
	switch runtimeFamily {
	case RuntimeFamilyPHPFPM:
		return capability.PHPFPMSupported
	case RuntimeFamilyPSGI:
		return capability.PSGISupported
	default:
		return false
	}
}

func runtimeBuildLockKey(runtimeFamily, runtimeID string, target RuntimeTargetKey) string {
	return strings.Join([]string{
		strings.TrimSpace(runtimeFamily),
		strings.TrimSpace(runtimeID),
		target.OS,
		target.Arch,
		target.DistroID,
		target.DistroVersion,
	}, "\x00")
}

func findCenterRuntimeBuilderRoot(runtimeFamily string) (centerRuntimeBuilderRoot, error) {
	scriptName := ""
	dockerfileName := ""
	switch runtimeFamily {
	case RuntimeFamilyPHPFPM:
		scriptName = "php_fpm_runtime_build.sh"
		dockerfileName = "Dockerfile.php-fpm-runtime"
	case RuntimeFamilyPSGI:
		scriptName = "psgi_runtime_build.sh"
		dockerfileName = "Dockerfile.psgi-runtime"
	default:
		return centerRuntimeBuilderRoot{}, fmt.Errorf("%w: unsupported runtime family", ErrRuntimeArtifactInvalid)
	}
	candidates := []string{}
	if envRoot := strings.TrimSpace(os.Getenv(runtimeBuilderRootEnv)); envRoot != "" {
		candidates = append(candidates, envRoot)
	}
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, cwd)
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Dir(exe))
	}
	for _, candidate := range candidates {
		root, err := filepath.Abs(filepath.Clean(candidate))
		if err != nil {
			continue
		}
		scriptPath := filepath.Join(root, "scripts", scriptName)
		dockerfilePath := filepath.Join(root, "build", dockerfileName)
		if fileExecutable(scriptPath) && fileReadable(dockerfilePath) {
			return centerRuntimeBuilderRoot{Root: root, ScriptPath: scriptPath, Dockerfile: dockerfilePath}, nil
		}
	}
	return centerRuntimeBuilderRoot{}, fmt.Errorf("%w: runtime builder script or Dockerfile is not available", ErrRuntimeBuilderUnavailable)
}

func checkDockerBuilder(ctx context.Context) error {
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("%w: docker command is not available", ErrRuntimeBuilderUnavailable)
	}
	checkCtx, cancel := context.WithTimeout(ctx, runtimeBuildDockerTimeout)
	defer cancel()
	cmd := exec.CommandContext(checkCtx, "docker", "version", "--format", "{{.Server.Version}}")
	if err := cmd.Run(); err != nil {
		if checkCtx.Err() != nil {
			return fmt.Errorf("%w: docker daemon check timed out", ErrRuntimeBuilderUnavailable)
		}
		return fmt.Errorf("%w: docker daemon is not reachable", ErrRuntimeBuilderUnavailable)
	}
	return nil
}

func fileExecutable(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && info.Mode()&0o111 != 0
}

func fileReadable(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func runtimeBuildDataFamilyDir(runtimeFamily string) string {
	switch strings.TrimSpace(runtimeFamily) {
	case RuntimeFamilyPSGI:
		return "psgi"
	default:
		return "php-fpm"
	}
}

func buildRuntimeArtifactFromDirectory(runtimeDir string, req centerRuntimeBuildExecution, buildLog string) (runtimeartifactbundle.Build, error) {
	metadata, err := readRuntimeBuildMetadata(filepath.Join(runtimeDir, "runtime.json"))
	if err != nil {
		return runtimeartifactbundle.Build{}, err
	}
	if metadata.RuntimeID != req.RuntimeID {
		return runtimeartifactbundle.Build{}, fmt.Errorf("built runtime id mismatch")
	}
	files, err := runtimeArtifactFilesFromDirectory(runtimeDir)
	if err != nil {
		return runtimeartifactbundle.Build{}, err
	}
	builderVersion := buildinfo.Version
	if strings.TrimSpace(builderVersion) == "" {
		builderVersion = "local"
	}
	return runtimeartifactbundle.BuildBundle(runtimeartifactbundle.BuildInput{
		RuntimeFamily:   req.RuntimeFamily,
		RuntimeID:       req.RuntimeID,
		DisplayName:     metadata.DisplayName,
		DetectedVersion: metadata.DetectedVersion,
		Target: runtimeartifactbundle.TargetKey{
			OS:            req.Target.OS,
			Arch:          req.Target.Arch,
			KernelVersion: req.Target.KernelVersion,
			DistroID:      req.Target.DistroID,
			DistroIDLike:  req.Target.DistroIDLike,
			DistroVersion: req.Target.DistroVersion,
		},
		BuilderVersion: builderVersion,
		BuilderProfile: runtimeBuildBuilderProfile(req, buildLog),
		GeneratedAt:    time.Now().UTC(),
		Files:          files,
	})
}

func readRuntimeBuildMetadata(path string) (phpRuntimeBuildMetadata, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return phpRuntimeBuildMetadata{}, fmt.Errorf("read runtime metadata: %w", err)
	}
	var metadata phpRuntimeBuildMetadata
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&metadata); err != nil {
		return phpRuntimeBuildMetadata{}, fmt.Errorf("decode runtime metadata: %w", err)
	}
	metadata.RuntimeID = strings.TrimSpace(metadata.RuntimeID)
	metadata.DisplayName = strings.TrimSpace(metadata.DisplayName)
	metadata.DetectedVersion = strings.TrimSpace(metadata.DetectedVersion)
	if metadata.RuntimeID == "" || metadata.DetectedVersion == "" {
		return phpRuntimeBuildMetadata{}, fmt.Errorf("runtime metadata is incomplete")
	}
	return metadata, nil
}

func runtimeArtifactFilesFromDirectory(runtimeDir string) ([]runtimeartifactbundle.File, error) {
	root, err := filepath.Abs(filepath.Clean(runtimeDir))
	if err != nil {
		return nil, err
	}
	rootfsDir := filepath.Join(root, "rootfs")
	out := []runtimeartifactbundle.File{}
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		archivePath := filepath.ToSlash(rel)
		info, resolvedPath, err := runtimeArtifactBuildFileInfo(root, rootfsDir, path, entry)
		if err != nil {
			if strings.HasPrefix(archivePath, "rootfs/") {
				return nil
			}
			return err
		}
		if info == nil || info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			if strings.HasPrefix(archivePath, "rootfs/") {
				return nil
			}
			return fmt.Errorf("runtime build contains unsupported file %q", path)
		}
		body, err := os.ReadFile(resolvedPath)
		if err != nil {
			return fmt.Errorf("read runtime build file %q: %w", archivePath, err)
		}
		out = append(out, runtimeartifactbundle.File{
			ArchivePath: archivePath,
			FileKind:    runtimeArtifactFileKind(archivePath),
			Mode:        int64(info.Mode() & 0o777),
			Body:        body,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ArchivePath < out[j].ArchivePath })
	return out, nil
}

func runtimeArtifactBuildFileInfo(root, rootfsDir, path string, entry fs.DirEntry) (fs.FileInfo, string, error) {
	if entry.Type()&os.ModeSymlink == 0 {
		info, err := entry.Info()
		return info, path, err
	}
	resolved, err := resolveRuntimeBuildSymlink(root, rootfsDir, path)
	if err != nil {
		return nil, "", err
	}
	info, err := os.Stat(resolved)
	return info, resolved, err
}

func resolveRuntimeBuildSymlink(root, rootfsDir, linkPath string) (string, error) {
	current := linkPath
	for i := 0; i < 16; i++ {
		info, err := os.Lstat(current)
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink == 0 {
			cleaned, err := filepath.Abs(filepath.Clean(current))
			if err != nil {
				return "", err
			}
			if !pathWithin(root, cleaned) {
				return "", fmt.Errorf("runtime build symlink escapes runtime root")
			}
			return cleaned, nil
		}
		target, err := os.Readlink(current)
		if err != nil {
			return "", err
		}
		if filepath.IsAbs(target) {
			current = filepath.Join(rootfsDir, strings.TrimPrefix(filepath.Clean(target), string(filepath.Separator)))
		} else {
			current = filepath.Join(filepath.Dir(current), target)
		}
	}
	return "", fmt.Errorf("runtime build symlink chain is too deep")
}

func pathWithin(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != "" && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel))
}

func runtimeArtifactFileKind(archivePath string) string {
	switch archivePath {
	case "runtime.json", "modules.json":
		return "metadata"
	case "php-fpm", "php", "perl", "starman":
		return "binary"
	default:
		return "rootfs"
	}
}

func runtimeBuildBuilderProfile(req centerRuntimeBuildExecution, buildLog string) string {
	_ = buildLog
	return strings.Join([]string{
		"docker",
		req.RuntimeFamily,
		req.RuntimeID,
		req.Target.OS,
		req.Target.Arch,
		req.Target.DistroID,
		req.Target.DistroVersion,
	}, ":")
}

func (l *limitedRuntimeBuildLog) Write(p []byte) (int, error) {
	if l.buf.Len() < runtimeBuildLogLimit {
		remaining := runtimeBuildLogLimit - l.buf.Len()
		if len(p) <= remaining {
			_, _ = l.buf.Write(p)
		} else {
			_, _ = l.buf.Write(p[:remaining])
			l.truncated = true
		}
	} else {
		l.truncated = true
	}
	return len(p), nil
}

func (l *limitedRuntimeBuildLog) String() string {
	out := l.buf.String()
	if l.truncated {
		out += "\n[truncated]\n"
	}
	return out
}
