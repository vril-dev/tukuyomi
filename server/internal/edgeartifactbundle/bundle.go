package edgeartifactbundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
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
	SchemaVersion        = 1
	MaxCompressedBytes   = 8 * 1024 * 1024
	MaxUncompressedBytes = 32 * 1024 * 1024
	MaxFileBytes         = 2 * 1024 * 1024
	MaxFiles             = 1000
)

var (
	ErrNoFiles       = errors.New("rule artifact bundle has no files")
	kindPattern      = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)
	archivePathRegex = regexp.MustCompile(`^files/[0-9]{6}\.conf$`)
	hex64Pattern     = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type RuleFile struct {
	Path     string
	Kind     string
	ETag     string
	Disabled bool
	Body     []byte
}

type FileManifest struct {
	Path        string `json:"path"`
	ArchivePath string `json:"archive_path"`
	Kind        string `json:"kind"`
	ETag        string `json:"etag,omitempty"`
	Disabled    bool   `json:"disabled"`
	SHA256      string `json:"sha256"`
	SizeBytes   int64  `json:"size_bytes"`
}

type Manifest struct {
	SchemaVersion  int            `json:"schema_version"`
	BundleRevision string         `json:"bundle_revision"`
	GeneratedAt    string         `json:"generated_at"`
	Files          []FileManifest `json:"files"`
}

type Build struct {
	Revision         string
	BundleHash       string
	Compressed       []byte
	CompressedSize   int64
	UncompressedSize int64
	FileCount        int
}

type ParsedFile struct {
	FileManifest
	Body []byte
}

type Parsed struct {
	Manifest         Manifest
	Files            []ParsedFile
	Revision         string
	BundleHash       string
	CompressedSize   int64
	UncompressedSize int64
	FileCount        int
}

func BuildBundle(files []RuleFile, generatedAt time.Time) (Build, error) {
	normalized, err := normalizeRuleFiles(files)
	if err != nil {
		return Build{}, err
	}
	if len(normalized) == 0 {
		return Build{}, ErrNoFiles
	}
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}

	manifest := Manifest{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   generatedAt.UTC().Format(time.RFC3339Nano),
		Files:         make([]FileManifest, 0, len(normalized)),
	}
	for i, file := range normalized {
		sum := sha256.Sum256(file.Body)
		manifest.Files = append(manifest.Files, FileManifest{
			Path:        file.Path,
			ArchivePath: fmt.Sprintf("files/%06d.conf", i+1),
			Kind:        file.Kind,
			ETag:        file.ETag,
			Disabled:    file.Disabled,
			SHA256:      hex.EncodeToString(sum[:]),
			SizeBytes:   int64(len(file.Body)),
		})
	}
	revision, err := Revision(manifest)
	if err != nil {
		return Build{}, err
	}
	manifest.BundleRevision = revision

	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		return Build{}, fmt.Errorf("marshal rule artifact manifest: %w", err)
	}
	if err := writeTarFile(tw, "manifest.json", manifestRaw); err != nil {
		return Build{}, err
	}
	for i, file := range normalized {
		if err := writeTarFile(tw, manifest.Files[i].ArchivePath, file.Body); err != nil {
			return Build{}, err
		}
	}
	if err := tw.Close(); err != nil {
		return Build{}, fmt.Errorf("close rule artifact tar: %w", err)
	}
	if tarBuf.Len() > MaxUncompressedBytes {
		return Build{}, fmt.Errorf("rule artifact bundle exceeds %d uncompressed bytes", MaxUncompressedBytes)
	}

	var compressed bytes.Buffer
	gw, err := gzip.NewWriterLevel(&compressed, gzip.BestCompression)
	if err != nil {
		return Build{}, err
	}
	gw.ModTime = time.Unix(0, 0).UTC()
	if _, err := gw.Write(tarBuf.Bytes()); err != nil {
		return Build{}, fmt.Errorf("compress rule artifact bundle: %w", err)
	}
	if err := gw.Close(); err != nil {
		return Build{}, fmt.Errorf("close rule artifact gzip: %w", err)
	}
	if compressed.Len() > MaxCompressedBytes {
		return Build{}, fmt.Errorf("rule artifact bundle exceeds %d compressed bytes", MaxCompressedBytes)
	}
	bundleHash := sha256.Sum256(compressed.Bytes())
	return Build{
		Revision:         revision,
		BundleHash:       hex.EncodeToString(bundleHash[:]),
		Compressed:       append([]byte(nil), compressed.Bytes()...),
		CompressedSize:   int64(compressed.Len()),
		UncompressedSize: int64(tarBuf.Len()),
		FileCount:        len(normalized),
	}, nil
}

func Parse(compressed []byte) (Parsed, error) {
	if len(compressed) == 0 || len(compressed) > MaxCompressedBytes {
		return Parsed{}, fmt.Errorf("invalid rule artifact bundle compressed size")
	}
	hash := sha256.Sum256(compressed)
	gr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return Parsed{}, fmt.Errorf("open rule artifact gzip: %w", err)
	}
	defer gr.Close()

	var tarBuf bytes.Buffer
	if _, err := io.Copy(&tarBuf, io.LimitReader(gr, MaxUncompressedBytes+1)); err != nil {
		return Parsed{}, fmt.Errorf("decompress rule artifact bundle: %w", err)
	}
	if tarBuf.Len() > MaxUncompressedBytes {
		return Parsed{}, fmt.Errorf("rule artifact exceeds %d uncompressed bytes", MaxUncompressedBytes)
	}

	tr := tar.NewReader(bytes.NewReader(tarBuf.Bytes()))
	var manifestRaw []byte
	filesByArchivePath := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Parsed{}, fmt.Errorf("read rule artifact tar: %w", err)
		}
		if hdr == nil {
			continue
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			return Parsed{}, fmt.Errorf("rule artifact contains non-regular entry %q", hdr.Name)
		}
		name := cleanArchivePath(hdr.Name)
		if name == "" {
			return Parsed{}, fmt.Errorf("rule artifact contains unsafe archive path")
		}
		if name != "manifest.json" && !archivePathRegex.MatchString(name) {
			return Parsed{}, fmt.Errorf("rule artifact contains unexpected archive path %q", name)
		}
		if _, exists := filesByArchivePath[name]; exists || (name == "manifest.json" && manifestRaw != nil) {
			return Parsed{}, fmt.Errorf("rule artifact contains duplicate archive path %q", name)
		}
		limit := int64(MaxFileBytes)
		if name == "manifest.json" {
			limit = 1024 * 1024
		}
		body, readErr := readLimitedEntry(tr, limit)
		if readErr != nil {
			return Parsed{}, readErr
		}
		if name == "manifest.json" {
			manifestRaw = body
		} else {
			filesByArchivePath[name] = body
			if len(filesByArchivePath) > MaxFiles {
				return Parsed{}, fmt.Errorf("rule artifact exceeds %d files", MaxFiles)
			}
		}
	}
	if len(manifestRaw) == 0 {
		return Parsed{}, fmt.Errorf("rule artifact manifest is missing")
	}
	var manifest Manifest
	dec := json.NewDecoder(bytes.NewReader(manifestRaw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&manifest); err != nil {
		return Parsed{}, fmt.Errorf("decode rule artifact manifest: %w", err)
	}
	if manifest.SchemaVersion != SchemaVersion {
		return Parsed{}, fmt.Errorf("unsupported rule artifact schema_version")
	}
	if len(manifest.Files) == 0 || len(manifest.Files) > MaxFiles {
		return Parsed{}, fmt.Errorf("invalid rule artifact file count")
	}
	if len(manifest.Files) != len(filesByArchivePath) {
		return Parsed{}, fmt.Errorf("rule artifact manifest file count mismatch")
	}
	revision, err := Revision(manifest)
	if err != nil {
		return Parsed{}, err
	}
	if !secureEqualHex(revision, manifest.BundleRevision) {
		return Parsed{}, fmt.Errorf("rule artifact bundle_revision mismatch")
	}
	out := Parsed{
		Manifest:         manifest,
		Files:            make([]ParsedFile, 0, len(manifest.Files)),
		Revision:         revision,
		BundleHash:       hex.EncodeToString(hash[:]),
		CompressedSize:   int64(len(compressed)),
		UncompressedSize: int64(tarBuf.Len()),
		FileCount:        len(manifest.Files),
	}
	seenLogical := map[string]struct{}{}
	seenArchive := map[string]struct{}{}
	for _, entry := range manifest.Files {
		if err := validateManifestFile(entry); err != nil {
			return Parsed{}, err
		}
		if _, exists := seenLogical[entry.Path]; exists {
			return Parsed{}, fmt.Errorf("duplicate rule artifact logical path %q", entry.Path)
		}
		seenLogical[entry.Path] = struct{}{}
		if _, exists := seenArchive[entry.ArchivePath]; exists {
			return Parsed{}, fmt.Errorf("duplicate rule artifact archive path %q", entry.ArchivePath)
		}
		seenArchive[entry.ArchivePath] = struct{}{}
		body, exists := filesByArchivePath[entry.ArchivePath]
		if !exists {
			return Parsed{}, fmt.Errorf("rule artifact file %q is missing", entry.ArchivePath)
		}
		if int64(len(body)) != entry.SizeBytes {
			return Parsed{}, fmt.Errorf("rule artifact file %q size mismatch", entry.Path)
		}
		sum := sha256.Sum256(body)
		if !secureEqualHex(hex.EncodeToString(sum[:]), entry.SHA256) {
			return Parsed{}, fmt.Errorf("rule artifact file %q sha256 mismatch", entry.Path)
		}
		out.Files = append(out.Files, ParsedFile{
			FileManifest: entry,
			Body:         append([]byte(nil), body...),
		})
	}
	return out, nil
}

func Revision(manifest Manifest) (string, error) {
	manifest.BundleRevision = ""
	manifest.GeneratedAt = ""
	sort.Slice(manifest.Files, func(i, j int) bool {
		return manifest.Files[i].Path < manifest.Files[j].Path
	})
	raw, err := json.Marshal(manifest)
	if err != nil {
		return "", fmt.Errorf("marshal rule artifact revision: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func normalizeRuleFiles(files []RuleFile) ([]RuleFile, error) {
	out := make([]RuleFile, 0, len(files))
	for _, file := range files {
		file.Path = normalizeLogicalPath(file.Path)
		file.Kind = strings.TrimSpace(file.Kind)
		file.ETag = strings.TrimSpace(file.ETag)
		if file.Path == "" {
			return nil, fmt.Errorf("rule artifact path is invalid")
		}
		if !kindPattern.MatchString(file.Kind) {
			return nil, fmt.Errorf("rule artifact kind is invalid")
		}
		if len(file.Body) > MaxFileBytes {
			return nil, fmt.Errorf("rule artifact file %q exceeds %d bytes", file.Path, MaxFileBytes)
		}
		if !isPrintableASCII(file.ETag, 256) {
			return nil, fmt.Errorf("rule artifact file %q has invalid etag", file.Path)
		}
		file.Body = append([]byte(nil), file.Body...)
		out = append(out, file)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Kind < out[j].Kind
	})
	for i := 1; i < len(out); i++ {
		if out[i].Path == out[i-1].Path {
			return nil, fmt.Errorf("duplicate rule artifact path %q", out[i].Path)
		}
	}
	if len(out) > MaxFiles {
		return nil, fmt.Errorf("rule artifact exceeds %d files", MaxFiles)
	}
	return out, nil
}

func validateManifestFile(file FileManifest) error {
	if normalizeLogicalPath(file.Path) != file.Path || file.Path == "" {
		return fmt.Errorf("rule artifact manifest has invalid path")
	}
	if !archivePathRegex.MatchString(file.ArchivePath) {
		return fmt.Errorf("rule artifact manifest has invalid archive path")
	}
	if !kindPattern.MatchString(file.Kind) {
		return fmt.Errorf("rule artifact manifest has invalid kind")
	}
	if !isPrintableASCII(file.ETag, 256) {
		return fmt.Errorf("rule artifact manifest has invalid etag")
	}
	if !hex64Pattern.MatchString(file.SHA256) {
		return fmt.Errorf("rule artifact manifest has invalid sha256")
	}
	if file.SizeBytes < 0 || file.SizeBytes > MaxFileBytes {
		return fmt.Errorf("rule artifact manifest has invalid size")
	}
	return nil
}

func writeTarFile(tw *tar.Writer, name string, body []byte) error {
	hdr := &tar.Header{
		Name:     name,
		Mode:     0o600,
		Size:     int64(len(body)),
		Typeflag: tar.TypeReg,
		ModTime:  time.Unix(0, 0).UTC(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("write rule artifact tar header %q: %w", name, err)
	}
	if _, err := tw.Write(body); err != nil {
		return fmt.Errorf("write rule artifact tar body %q: %w", name, err)
	}
	return nil
}

func readLimitedEntry(r io.Reader, max int64) ([]byte, error) {
	var buf bytes.Buffer
	limited := io.LimitReader(r, max+1)
	if _, err := io.Copy(&buf, limited); err != nil {
		return nil, fmt.Errorf("read rule artifact entry: %w", err)
	}
	if int64(buf.Len()) > max {
		return nil, fmt.Errorf("rule artifact entry exceeds %d bytes", max)
	}
	return buf.Bytes(), nil
}

func cleanArchivePath(raw string) string {
	raw = strings.TrimSpace(strings.ReplaceAll(raw, "\\", "/"))
	if raw == "" || strings.HasPrefix(raw, "/") || strings.Contains(raw, "\x00") {
		return ""
	}
	cleaned := path.Clean(raw)
	if cleaned == "." || strings.HasPrefix(cleaned, "../") || strings.Contains(cleaned, "/../") {
		return ""
	}
	return cleaned
}

func normalizeLogicalPath(raw string) string {
	raw = strings.TrimSpace(strings.ReplaceAll(raw, "\\", "/"))
	if raw == "" || len(raw) > 512 || strings.HasPrefix(raw, "/") || strings.Contains(raw, "\x00") {
		return ""
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			return ""
		}
	}
	cleaned := path.Clean(raw)
	if cleaned == "." || strings.HasPrefix(cleaned, "../") || strings.Contains(cleaned, "/../") {
		return ""
	}
	return cleaned
}

func isPrintableASCII(value string, max int) bool {
	if len(value) > max {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r > 0x7e {
			return false
		}
	}
	return true
}

func secureEqualHex(a, b string) bool {
	a = strings.ToLower(strings.TrimSpace(a))
	b = strings.ToLower(strings.TrimSpace(b))
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
