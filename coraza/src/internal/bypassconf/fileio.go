package bypassconf

import (
	"io"
	"os"
	"path/filepath"
	"time"
)

func AtomicWriteWithBackup(path string, data []byte) error {
	if _, err := os.Stat(path); err == nil {
		_ = copyFile(path, path+"."+time.Now().Format("20060102-150405")+".bak")
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".waf.bypass.*")
	if err != nil {
		return err
	}

	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}

	if err := tmp.Sync(); err != nil {
		tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}

	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}

	return os.Rename(tmpPath, path)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}

	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}

	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}

	return out.Sync()
}
