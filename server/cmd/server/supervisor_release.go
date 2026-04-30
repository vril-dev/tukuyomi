package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	supervisorReleasesDirEnv            = "TUKUYOMI_SUPERVISOR_RELEASES_DIR"
	defaultSupervisorReleasesDir        = "data/releases"
	supervisorWorkerGenerationsDirName  = "worker-generations"
	supervisorStagedMetadataFileName    = "metadata.json"
	supervisorReleaseCommandTimeout     = 15 * time.Second
	supervisorReleaseMaxArtifactBytes   = int64(1024 * 1024 * 1024)
	supervisorReleaseMaxBinaryBytes     = int64(512 * 1024 * 1024)
	supervisorReleaseMaxCommandOutBytes = int64(64 * 1024)
	defaultSupervisorReleasePruneKeep   = 3
)

type supervisorReleaseManager struct {
	root    string
	timeNow func() time.Time
}

type supervisorReleaseStageRequest struct {
	ArtifactPath  string `json:"artifact_path"`
	SHA256        string `json:"sha256"`
	SignaturePath string `json:"signature_path,omitempty"`
}

type supervisorReleaseStageResult struct {
	Version        string                `json:"version,omitempty"`
	Generation     string                `json:"generation"`
	Executable     string                `json:"executable"`
	ArtifactSHA256 string                `json:"artifact_sha256"`
	BinarySHA256   string                `json:"binary_sha256"`
	Metadata       releaseBinaryMetadata `json:"metadata"`
	StagedAt       string                `json:"staged_at"`
	AlreadyStaged  bool                  `json:"already_staged,omitempty"`
}

type supervisorStagedGeneration struct {
	Generation   string                `json:"generation"`
	Executable   string                `json:"executable"`
	BinarySHA256 string                `json:"binary_sha256,omitempty"`
	Metadata     releaseBinaryMetadata `json:"metadata"`
	StagedAt     string                `json:"staged_at,omitempty"`
}

func newSupervisorReleaseManager(root string) *supervisorReleaseManager {
	root = strings.TrimSpace(root)
	if root == "" {
		root = supervisorReleasesDirFromEnv()
	}
	return &supervisorReleaseManager{root: root}
}

func supervisorReleasesDirFromEnv() string {
	if value := strings.TrimSpace(os.Getenv(supervisorReleasesDirEnv)); value != "" {
		return value
	}
	return defaultSupervisorReleasesDir
}

func (m *supervisorReleaseManager) StageArtifact(ctx context.Context, req supervisorReleaseStageRequest) (supervisorReleaseStageResult, error) {
	if m == nil {
		return supervisorReleaseStageResult{}, fmt.Errorf("release manager is nil")
	}
	artifactPath := strings.TrimSpace(req.ArtifactPath)
	if artifactPath == "" {
		return supervisorReleaseStageResult{}, fmt.Errorf("artifact_path is required")
	}
	expectedArtifactSHA, err := normalizeSHA256(req.SHA256)
	if err != nil {
		return supervisorReleaseStageResult{}, err
	}
	if expectedArtifactSHA == "" {
		return supervisorReleaseStageResult{}, fmt.Errorf("sha256 is required")
	}
	if strings.TrimSpace(req.SignaturePath) != "" {
		return supervisorReleaseStageResult{}, fmt.Errorf("signature verification requires a configured trusted key")
	}
	artifactSHA, _, err := fileSHA256(artifactPath, supervisorReleaseMaxArtifactBytes)
	if err != nil {
		return supervisorReleaseStageResult{}, fmt.Errorf("hash artifact: %w", err)
	}
	if artifactSHA != expectedArtifactSHA {
		return supervisorReleaseStageResult{}, fmt.Errorf("artifact sha256 mismatch")
	}

	generationsDir := filepath.Join(m.root, supervisorWorkerGenerationsDirName)
	if err := os.MkdirAll(generationsDir, 0o750); err != nil {
		return supervisorReleaseStageResult{}, fmt.Errorf("create worker generations dir: %w", err)
	}
	tmpDir, err := os.MkdirTemp(generationsDir, ".stage-*")
	if err != nil {
		return supervisorReleaseStageResult{}, fmt.Errorf("create staging dir: %w", err)
	}
	removeTmp := true
	defer func() {
		if removeTmp {
			_ = os.RemoveAll(tmpDir)
		}
	}()
	if err := os.Chmod(tmpDir, 0o750); err != nil {
		return supervisorReleaseStageResult{}, fmt.Errorf("secure staging dir: %w", err)
	}
	tmpExecutable := filepath.Join(tmpDir, "tukuyomi")
	if isTarGzipArtifact(artifactPath) {
		if err := extractTukuyomiBinaryFromTarGzip(artifactPath, tmpExecutable); err != nil {
			return supervisorReleaseStageResult{}, err
		}
	} else if err := copyExecutableFile(artifactPath, tmpExecutable); err != nil {
		return supervisorReleaseStageResult{}, err
	}
	if err := os.Chmod(tmpExecutable, 0o755); err != nil {
		return supervisorReleaseStageResult{}, fmt.Errorf("mark staged binary executable: %w", err)
	}

	binarySHA, _, err := fileSHA256(tmpExecutable, supervisorReleaseMaxBinaryBytes)
	if err != nil {
		return supervisorReleaseStageResult{}, fmt.Errorf("hash staged binary: %w", err)
	}
	metadata, err := readReleaseMetadata(ctx, tmpExecutable)
	if err != nil {
		return supervisorReleaseStageResult{}, err
	}
	if err := validateReleaseMetadata(metadata); err != nil {
		return supervisorReleaseStageResult{}, err
	}
	if err := validateStagedBinaryConfig(ctx, tmpExecutable); err != nil {
		return supervisorReleaseStageResult{}, err
	}

	generation := releaseGenerationName(metadata.Version, binarySHA)
	finalDir := filepath.Join(generationsDir, generation)
	finalExecutable := filepath.Join(finalDir, "tukuyomi")
	stagedAt := m.now().Format(time.RFC3339Nano)
	result := supervisorReleaseStageResult{
		Version:        strings.TrimSpace(metadata.Version),
		Generation:     generation,
		Executable:     finalExecutable,
		ArtifactSHA256: artifactSHA,
		BinarySHA256:   binarySHA,
		Metadata:       metadata,
		StagedAt:       stagedAt,
	}
	if existingSHA, found, err := existingGenerationSHA(finalExecutable); err != nil {
		return supervisorReleaseStageResult{}, err
	} else if found {
		if existingSHA != binarySHA {
			return supervisorReleaseStageResult{}, fmt.Errorf("generation %q already exists with different binary", generation)
		}
		result.AlreadyStaged = true
		return result, nil
	}
	if err := writeStagedMetadata(filepath.Join(tmpDir, supervisorStagedMetadataFileName), result); err != nil {
		return supervisorReleaseStageResult{}, err
	}
	if err := syncDir(tmpDir); err != nil {
		return supervisorReleaseStageResult{}, fmt.Errorf("sync staging dir: %w", err)
	}
	if err := os.Rename(tmpDir, finalDir); err != nil {
		return supervisorReleaseStageResult{}, fmt.Errorf("publish staged generation: %w", err)
	}
	removeTmp = false
	if err := syncDir(generationsDir); err != nil {
		return supervisorReleaseStageResult{}, fmt.Errorf("sync worker generations dir: %w", err)
	}
	result.Executable = finalExecutable
	return result, nil
}

func (m *supervisorReleaseManager) StagedGenerations() ([]supervisorStagedGeneration, error) {
	if m == nil {
		return nil, nil
	}
	generationsDir := filepath.Join(m.root, supervisorWorkerGenerationsDirName)
	entries, err := os.ReadDir(generationsDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read worker generations dir: %w", err)
	}
	out := make([]supervisorStagedGeneration, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		metaPath := filepath.Join(generationsDir, entry.Name(), supervisorStagedMetadataFileName)
		raw, err := os.ReadFile(metaPath)
		if err != nil {
			continue
		}
		var staged supervisorReleaseStageResult
		if err := json.Unmarshal(raw, &staged); err != nil {
			continue
		}
		out = append(out, supervisorStagedGeneration{
			Generation:   staged.Generation,
			Executable:   staged.Executable,
			BinarySHA256: staged.BinarySHA256,
			Metadata:     staged.Metadata,
			StagedAt:     staged.StagedAt,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].StagedAt > out[j].StagedAt
	})
	return out, nil
}

func (m *supervisorReleaseManager) ResolveGeneration(generation string) (supervisorStagedGeneration, error) {
	generation = strings.TrimSpace(generation)
	if err := validateReleaseGenerationToken(generation); err != nil {
		return supervisorStagedGeneration{}, err
	}
	metaPath := filepath.Join(m.root, supervisorWorkerGenerationsDirName, generation, supervisorStagedMetadataFileName)
	raw, err := os.ReadFile(metaPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return supervisorStagedGeneration{}, fmt.Errorf("staged generation %q not found", generation)
		}
		return supervisorStagedGeneration{}, fmt.Errorf("read staged generation metadata: %w", err)
	}
	var staged supervisorReleaseStageResult
	if err := json.Unmarshal(raw, &staged); err != nil {
		return supervisorStagedGeneration{}, fmt.Errorf("decode staged generation metadata: %w", err)
	}
	if staged.Generation != generation {
		return supervisorStagedGeneration{}, fmt.Errorf("staged generation metadata mismatch")
	}
	if err := validateReleaseMetadata(staged.Metadata); err != nil {
		return supervisorStagedGeneration{}, err
	}
	if _, err := os.Stat(staged.Executable); err != nil {
		return supervisorStagedGeneration{}, fmt.Errorf("staged executable unavailable: %w", err)
	}
	return supervisorStagedGeneration{
		Generation:   staged.Generation,
		Executable:   staged.Executable,
		BinarySHA256: staged.BinarySHA256,
		Metadata:     staged.Metadata,
		StagedAt:     staged.StagedAt,
	}, nil
}

func (m *supervisorReleaseManager) PruneInactive(state supervisorWorkerRuntimeState, keepInactive int) ([]string, error) {
	if m == nil {
		return nil, nil
	}
	if keepInactive < 0 {
		return nil, fmt.Errorf("keepInactive must be >= 0")
	}
	protected := map[string]struct{}{}
	if state.Active.Executable != "" {
		protected[filepath.Clean(state.Active.Executable)] = struct{}{}
	}
	if state.Previous != nil && state.Previous.Executable != "" {
		protected[filepath.Clean(state.Previous.Executable)] = struct{}{}
	}
	generationsDir := filepath.Join(m.root, supervisorWorkerGenerationsDirName)
	entries, err := os.ReadDir(generationsDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read worker generations dir: %w", err)
	}
	type candidate struct {
		name    string
		path    string
		exe     string
		modTime time.Time
	}
	candidates := make([]candidate, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dirPath := filepath.Join(generationsDir, entry.Name())
		exePath := filepath.Join(dirPath, "tukuyomi")
		if _, ok := protected[filepath.Clean(exePath)]; ok {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("stat generation %q: %w", entry.Name(), err)
		}
		candidates = append(candidates, candidate{name: entry.Name(), path: dirPath, exe: exePath, modTime: info.ModTime()})
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].modTime.After(candidates[j].modTime)
	})
	var removed []string
	for i, item := range candidates {
		if i < keepInactive {
			continue
		}
		if err := os.RemoveAll(item.path); err != nil {
			return removed, fmt.Errorf("remove inactive generation %q: %w", item.name, err)
		}
		removed = append(removed, item.name)
	}
	if len(removed) > 0 {
		if err := syncDir(generationsDir); err != nil {
			return removed, fmt.Errorf("sync worker generations dir: %w", err)
		}
	}
	return removed, nil
}

func (m *supervisorReleaseManager) now() time.Time {
	if m != nil && m.timeNow != nil {
		return m.timeNow().UTC()
	}
	return time.Now().UTC()
}

func normalizeSHA256(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	fields := strings.Fields(value)
	if len(fields) > 0 {
		value = fields[0]
	}
	value = strings.ToLower(value)
	if len(value) != sha256.Size*2 {
		return "", fmt.Errorf("sha256 must be 64 hex characters")
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", fmt.Errorf("sha256 must be hex: %w", err)
	}
	return value, nil
}

func isTarGzipArtifact(path string) bool {
	name := strings.ToLower(strings.TrimSpace(path))
	return strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".tgz")
}

func fileSHA256(path string, maxBytes int64) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hash := sha256.New()
	limited := &io.LimitedReader{R: file, N: maxBytes + 1}
	n, err := io.Copy(hash, limited)
	if err != nil {
		return "", n, err
	}
	if n > maxBytes {
		return "", n, fmt.Errorf("file exceeds %d bytes", maxBytes)
	}
	return hex.EncodeToString(hash.Sum(nil)), n, nil
}

func copyExecutableFile(src string, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("stat artifact: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("artifact must be a regular file")
	}
	if info.Size() <= 0 || info.Size() > supervisorReleaseMaxBinaryBytes {
		return fmt.Errorf("artifact size must be between 1 and %d bytes", supervisorReleaseMaxBinaryBytes)
	}
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open artifact: %w", err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		return fmt.Errorf("create staged executable: %w", err)
	}
	limited := &io.LimitedReader{R: in, N: supervisorReleaseMaxBinaryBytes + 1}
	n, copyErr := io.Copy(out, limited)
	syncErr := out.Sync()
	closeErr := out.Close()
	if copyErr != nil {
		return fmt.Errorf("copy executable: %w", copyErr)
	}
	if n > supervisorReleaseMaxBinaryBytes {
		return fmt.Errorf("artifact exceeds %d bytes", supervisorReleaseMaxBinaryBytes)
	}
	if syncErr != nil {
		return fmt.Errorf("sync staged executable: %w", syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close staged executable: %w", closeErr)
	}
	return nil
}

func extractTukuyomiBinaryFromTarGzip(src string, dst string) error {
	file, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open release artifact: %w", err)
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("open gzip release artifact: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var found bool
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read release tar: %w", err)
		}
		if hdr == nil || hdr.Typeflag != tar.TypeReg {
			continue
		}
		clean := path.Clean(strings.TrimSpace(filepath.ToSlash(hdr.Name)))
		if clean == "." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") {
			return fmt.Errorf("release tar contains unsafe path %q", hdr.Name)
		}
		if path.Base(clean) != "tukuyomi" {
			continue
		}
		if strings.Count(clean, "/") > 1 {
			continue
		}
		if found {
			return fmt.Errorf("release tar contains multiple top-level tukuyomi binaries")
		}
		if hdr.Size <= 0 || hdr.Size > supervisorReleaseMaxBinaryBytes {
			return fmt.Errorf("release binary size must be between 1 and %d bytes", supervisorReleaseMaxBinaryBytes)
		}
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
		if err != nil {
			return fmt.Errorf("create staged executable: %w", err)
		}
		limited := &io.LimitedReader{R: tr, N: supervisorReleaseMaxBinaryBytes + 1}
		n, copyErr := io.Copy(out, limited)
		syncErr := out.Sync()
		closeErr := out.Close()
		if copyErr != nil {
			return fmt.Errorf("extract release binary: %w", copyErr)
		}
		if n > supervisorReleaseMaxBinaryBytes {
			return fmt.Errorf("release binary exceeds %d bytes", supervisorReleaseMaxBinaryBytes)
		}
		if syncErr != nil {
			return fmt.Errorf("sync staged executable: %w", syncErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close staged executable: %w", closeErr)
		}
		found = true
	}
	if !found {
		return fmt.Errorf("release tar does not contain a top-level tukuyomi binary")
	}
	return nil
}

func readReleaseMetadata(ctx context.Context, executable string) (releaseBinaryMetadata, error) {
	out, err := runReleaseCommandOutput(ctx, executable, "release-metadata")
	if err != nil {
		return releaseBinaryMetadata{}, fmt.Errorf("read release metadata: %w", err)
	}
	var metadata releaseBinaryMetadata
	if err := json.Unmarshal(out, &metadata); err != nil {
		return releaseBinaryMetadata{}, fmt.Errorf("decode release metadata: %w", err)
	}
	return metadata, nil
}

func validateStagedBinaryConfig(ctx context.Context, executable string) error {
	if _, err := runReleaseCommandOutput(ctx, executable, "validate-config"); err != nil {
		return fmt.Errorf("validate staged binary config compatibility: %w", err)
	}
	return nil
}

func runReleaseCommandOutput(ctx context.Context, executable string, arg string) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	cmdCtx, cancel := context.WithTimeout(ctx, supervisorReleaseCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, executable, arg)
	cmd.Env = workerProcessEnv(os.Environ())
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr limitBuffer
	stderr.max = supervisorReleaseMaxCommandOutBytes
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	limited := &io.LimitedReader{R: stdout, N: supervisorReleaseMaxCommandOutBytes + 1}
	out, readErr := io.ReadAll(limited)
	waitErr := cmd.Wait()
	if readErr != nil {
		return nil, readErr
	}
	if int64(len(out)) > supervisorReleaseMaxCommandOutBytes {
		return nil, fmt.Errorf("%s output exceeds %d bytes", arg, supervisorReleaseMaxCommandOutBytes)
	}
	if waitErr != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = waitErr.Error()
		}
		return nil, fmt.Errorf("%s failed: %s", arg, msg)
	}
	return bytes.TrimSpace(out), nil
}

type limitBuffer struct {
	buf bytes.Buffer
	max int64
}

func (b *limitBuffer) Write(p []byte) (int, error) {
	if b == nil {
		return len(p), nil
	}
	if b.max <= 0 {
		return len(p), nil
	}
	remaining := b.max - int64(b.buf.Len())
	if remaining <= 0 {
		return len(p), nil
	}
	if int64(len(p)) > remaining {
		_, _ = b.buf.Write(p[:remaining])
		return len(p), nil
	}
	_, _ = b.buf.Write(p)
	return len(p), nil
}

func (b *limitBuffer) String() string {
	if b == nil {
		return ""
	}
	return b.buf.String()
}

func validateReleaseMetadata(metadata releaseBinaryMetadata) error {
	if metadata.SchemaVersion != releaseMetadataSchemaVersion {
		return fmt.Errorf("unsupported release metadata schema %d", metadata.SchemaVersion)
	}
	if strings.TrimSpace(metadata.App) != "tukuyomi" {
		return fmt.Errorf("release metadata app must be tukuyomi")
	}
	if strings.TrimSpace(metadata.GOOS) != runtime.GOOS || strings.TrimSpace(metadata.GOARCH) != runtime.GOARCH {
		return fmt.Errorf("release platform mismatch: got %s/%s want %s/%s", metadata.GOOS, metadata.GOARCH, runtime.GOOS, runtime.GOARCH)
	}
	if strings.TrimSpace(metadata.GoVersion) == "" {
		return fmt.Errorf("release metadata go_version is required")
	}
	if strings.TrimSpace(metadata.WorkerProtocol) != workerReadinessProtocol {
		return fmt.Errorf("worker protocol mismatch: got %q want %q", metadata.WorkerProtocol, workerReadinessProtocol)
	}
	if len(strings.TrimSpace(metadata.Version)) > 128 {
		return fmt.Errorf("release metadata version is too long")
	}
	return nil
}

func releaseGenerationName(version string, binarySHA string) string {
	token := sanitizeReleaseGenerationToken(version)
	if token == "" {
		token = "sha256-" + binarySHA[:12]
	}
	return token
}

func sanitizeReleaseGenerationToken(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '.', r == '-', r == '_':
		default:
			r = '-'
		}
		b.WriteRune(r)
		if b.Len() >= 128 {
			break
		}
	}
	return strings.Trim(b.String(), ".-_")
}

func validateReleaseGenerationToken(value string) error {
	if value == "" {
		return fmt.Errorf("generation is required")
	}
	if len(value) > 128 {
		return fmt.Errorf("generation is too long")
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '.', r == '-', r == '_':
		default:
			return fmt.Errorf("generation contains an invalid character")
		}
	}
	return nil
}

func existingGenerationSHA(executable string) (string, bool, error) {
	if strings.TrimSpace(executable) == "" {
		return "", false, nil
	}
	if _, err := os.Stat(executable); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("stat existing generation: %w", err)
	}
	sha, _, err := fileSHA256(executable, supervisorReleaseMaxBinaryBytes)
	if err != nil {
		return "", false, fmt.Errorf("hash existing generation: %w", err)
	}
	return sha, true, nil
}

func writeStagedMetadata(path string, result supervisorReleaseStageResult) error {
	raw, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal staged metadata: %w", err)
	}
	raw = append(raw, '\n')
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create staged metadata: %w", err)
	}
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		return fmt.Errorf("write staged metadata: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync staged metadata: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close staged metadata: %w", err)
	}
	return nil
}
