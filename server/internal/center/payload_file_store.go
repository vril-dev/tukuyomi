package center

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"tukuyomi/internal/config"
)

const (
	centerPayloadRuntimeArtifacts  = "runtime-artifacts"
	centerPayloadAppDeploy         = "app-deploy-packages"
	centerPayloadDaemonLogArchives = "daemon-log-archives"

	centerPayloadRuntimeArtifactExt  = ".bundle"
	centerPayloadAppDeployExt        = ".zip"
	centerPayloadDaemonLogArchiveExt = ".log.gz"
)

var errCenterPayloadFileNotFound = errors.New("center payload file not found")

func writeCenterPayloadFile(kind, revision, ext string, body []byte, expectedSize int64, expectedHash string) (bool, error) {
	if err := validateCenterPayloadIdentity(kind, revision, ext); err != nil {
		return false, err
	}
	if expectedSize <= 0 || int64(len(body)) != expectedSize {
		return false, fmt.Errorf("payload size mismatch")
	}
	if !centerPayloadBytesHashMatches(body, expectedHash) {
		return false, fmt.Errorf("payload hash mismatch")
	}
	target, err := centerPayloadFilePath(kind, revision, ext)
	if err != nil {
		return false, err
	}
	if err := verifyCenterPayloadFile(target, expectedSize, expectedHash); err == nil {
		return true, nil
	} else if !errors.Is(err, errCenterPayloadFileNotFound) {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return false, err
	}
	tmp := target + ".tmp." + strconv.Itoa(os.Getpid()) + "." + strconv.FormatInt(time.Now().UTC().UnixNano(), 36)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return false, err
	}
	writeErr := func() error {
		if _, err := f.Write(body); err != nil {
			return err
		}
		return f.Close()
	}()
	if writeErr != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return false, writeErr
	}
	if err := os.Link(tmp, target); err != nil {
		_ = os.Remove(tmp)
		if errors.Is(err, os.ErrExist) {
			if verifyErr := verifyCenterPayloadFile(target, expectedSize, expectedHash); verifyErr == nil {
				return true, nil
			}
		}
		return false, err
	}
	_ = os.Remove(tmp)
	return false, nil
}

func readCenterPayloadFile(kind, revision, ext string, expectedSize int64, expectedHash string) ([]byte, error) {
	if err := validateCenterPayloadIdentity(kind, revision, ext); err != nil {
		return nil, err
	}
	target, err := centerPayloadFilePath(kind, revision, ext)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(target)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errCenterPayloadFileNotFound
		}
		return nil, err
	}
	if expectedSize <= 0 || int64(len(raw)) != expectedSize {
		return nil, fmt.Errorf("payload size mismatch")
	}
	if !centerPayloadBytesHashMatches(raw, expectedHash) {
		return nil, fmt.Errorf("payload hash mismatch")
	}
	return raw, nil
}

func removeCenterPayloadFile(kind, revision, ext string) {
	target, err := centerPayloadFilePath(kind, revision, ext)
	if err != nil {
		return
	}
	_ = os.Remove(target)
}

func centerPayloadFilePath(kind, revision, ext string) (string, error) {
	if err := validateCenterPayloadIdentity(kind, revision, ext); err != nil {
		return "", err
	}
	root, err := centerPayloadKindDir(kind)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, revision[:2], revision+ext), nil
}

func centerPayloadKindDir(kind string) (string, error) {
	switch kind {
	case centerPayloadRuntimeArtifacts, centerPayloadAppDeploy, centerPayloadDaemonLogArchives:
	default:
		return "", fmt.Errorf("invalid center payload kind")
	}
	base := strings.TrimSpace(config.PersistentStorageLocalBaseDir)
	if base == "" {
		base = config.DefaultPersistentStorageLocalDir
	}
	return filepath.Join(filepath.Clean(base), "center", kind), nil
}

func validateCenterPayloadIdentity(kind, revision, ext string) error {
	switch kind {
	case centerPayloadRuntimeArtifacts, centerPayloadAppDeploy, centerPayloadDaemonLogArchives:
	default:
		return fmt.Errorf("invalid center payload kind")
	}
	switch ext {
	case centerPayloadRuntimeArtifactExt, centerPayloadAppDeployExt, centerPayloadDaemonLogArchiveExt:
	default:
		return fmt.Errorf("invalid center payload extension")
	}
	if !hex64Pattern.MatchString(revision) {
		return fmt.Errorf("invalid center payload revision")
	}
	return nil
}

func verifyCenterPayloadFile(path string, expectedSize int64, expectedHash string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errCenterPayloadFileNotFound
		}
		return err
	}
	if expectedSize <= 0 || int64(len(raw)) != expectedSize {
		return fmt.Errorf("payload file size mismatch")
	}
	if !centerPayloadBytesHashMatches(raw, expectedHash) {
		return fmt.Errorf("payload file hash mismatch")
	}
	return nil
}

func centerPayloadBytesHashMatches(body []byte, expectedHash string) bool {
	expectedHash = strings.ToLower(strings.TrimSpace(expectedHash))
	if !hex64Pattern.MatchString(expectedHash) {
		return false
	}
	sum := sha256.Sum256(body)
	return secureEqualHex(hex.EncodeToString(sum[:]), expectedHash)
}
