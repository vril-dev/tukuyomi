package appdeploybundle

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
)

const (
	MaxCompressedBytes   = 128 * 1024 * 1024
	MaxUncompressedBytes = 512 * 1024 * 1024
	MaxFileBytes         = 64 * 1024 * 1024
	MaxFiles             = 20000
	MaxScriptBytes       = 64 * 1024
	MaxScriptOutputBytes = 32 * 1024
)

var (
	ErrEmptyPackage = errors.New("app deploy package has no files")
	hex64Pattern    = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type File struct {
	Path      string
	SHA256    string
	SizeBytes int64
	Mode      int64
	Body      []byte
}

type Parsed struct {
	Revision         string
	PackageHash      string
	CompressedSize   int64
	UncompressedSize int64
	FileCount        int
	Files            []File
}

func ParseZIP(raw []byte) (Parsed, error) {
	return parseZIP(raw, true)
}

func ParseZIPPreservePaths(raw []byte) (Parsed, error) {
	return parseZIP(raw, false)
}

func parseZIP(raw []byte, stripWrapper bool) (Parsed, error) {
	if len(raw) == 0 || len(raw) > MaxCompressedBytes {
		return Parsed{}, fmt.Errorf("invalid app deploy package compressed size")
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return Parsed{}, fmt.Errorf("open app deploy zip: %w", err)
	}
	entries, err := readZIPEntries(zr)
	if err != nil {
		return Parsed{}, err
	}
	if len(entries) == 0 {
		return Parsed{}, ErrEmptyPackage
	}
	if stripWrapper {
		entries = stripSingleWrapperDirectory(entries)
		if len(entries) == 0 {
			return Parsed{}, ErrEmptyPackage
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Path < entries[j].Path
	})
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])
	var uncompressed int64
	files := make([]File, 0, len(entries))
	for _, entry := range entries {
		uncompressed += entry.SizeBytes
		if uncompressed > MaxUncompressedBytes {
			return Parsed{}, fmt.Errorf("app deploy package exceeds %d uncompressed bytes", MaxUncompressedBytes)
		}
		files = append(files, entry)
	}
	return Parsed{
		Revision:         hash,
		PackageHash:      hash,
		CompressedSize:   int64(len(raw)),
		UncompressedSize: uncompressed,
		FileCount:        len(files),
		Files:            files,
	}, nil
}

func ValidateRevision(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if !hex64Pattern.MatchString(value) {
		return ""
	}
	return value
}

func CleanArchivePath(raw string) (string, bool) {
	raw = strings.TrimSpace(strings.ReplaceAll(raw, "\\", "/"))
	if raw == "" || strings.HasPrefix(raw, "/") {
		return "", false
	}
	cleaned := path.Clean(raw)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", false
	}
	if strings.Contains(cleaned, "\x00") {
		return "", false
	}
	return cleaned, true
}

func readZIPEntries(zr *zip.Reader) ([]File, error) {
	if len(zr.File) > MaxFiles*2 {
		return nil, fmt.Errorf("app deploy package has too many zip entries")
	}
	files := make([]File, 0, len(zr.File))
	seen := make(map[string]struct{}, len(zr.File))
	for _, zf := range zr.File {
		if zf == nil {
			continue
		}
		mode := zf.FileInfo().Mode()
		if mode.IsDir() {
			continue
		}
		if mode&os.ModeType != 0 {
			return nil, fmt.Errorf("app deploy package contains unsupported entry %q", zf.Name)
		}
		name, ok := CleanArchivePath(zf.Name)
		if !ok {
			return nil, fmt.Errorf("app deploy package contains unsafe path")
		}
		if _, exists := seen[name]; exists {
			return nil, fmt.Errorf("app deploy package contains duplicate path %q", name)
		}
		seen[name] = struct{}{}
		if len(seen) > MaxFiles {
			return nil, fmt.Errorf("app deploy package exceeds %d files", MaxFiles)
		}
		if zf.UncompressedSize64 > MaxFileBytes {
			return nil, fmt.Errorf("app deploy package file %q exceeds %d bytes", name, MaxFileBytes)
		}
		rc, err := zf.Open()
		if err != nil {
			return nil, fmt.Errorf("open app deploy zip entry: %w", err)
		}
		body, readErr := readLimited(rc, MaxFileBytes)
		closeErr := rc.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if uint64(len(body)) != zf.UncompressedSize64 {
			return nil, fmt.Errorf("app deploy package file %q size mismatch", name)
		}
		sum := sha256.Sum256(body)
		files = append(files, File{
			Path:      name,
			SHA256:    hex.EncodeToString(sum[:]),
			SizeBytes: int64(len(body)),
			Mode:      int64(mode.Perm()),
			Body:      body,
		})
	}
	return files, nil
}

func readLimited(r io.Reader, max int64) ([]byte, error) {
	var buf bytes.Buffer
	written, err := io.Copy(&buf, io.LimitReader(r, max+1))
	if err != nil {
		return nil, fmt.Errorf("read app deploy zip entry: %w", err)
	}
	if written > max {
		return nil, fmt.Errorf("app deploy package file exceeds %d bytes", max)
	}
	return buf.Bytes(), nil
}

func stripSingleWrapperDirectory(files []File) []File {
	root := ""
	for _, file := range files {
		first, rest, ok := strings.Cut(file.Path, "/")
		if !ok || first == "" || rest == "" {
			return files
		}
		if root == "" {
			root = first
			continue
		}
		if first != root {
			return files
		}
	}
	out := make([]File, 0, len(files))
	prefix := root + "/"
	seen := make(map[string]struct{}, len(files))
	for _, file := range files {
		next := file
		next.Path = strings.TrimPrefix(file.Path, prefix)
		if next.Path == "" {
			return files
		}
		if _, exists := seen[next.Path]; exists {
			return files
		}
		seen[next.Path] = struct{}{}
		out = append(out, next)
	}
	return out
}
