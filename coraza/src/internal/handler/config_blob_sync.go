package handler

import (
	"bytes"
	"strings"
	"time"

	"tukuyomi/internal/bypassconf"
)

type configBlobSyncOptions struct {
	ConfigKey          string
	Path               string
	ValidateRaw        func(string) error
	WriteRaw           func(string, []byte) error
	Reload             func() error
	ComputeETag        func([]byte) string
	ForceUpsertOnFound bool
	SkipWriteIfEqual   bool
}

func syncConfigBlobFilePath(opts configBlobSyncOptions) error {
	store := getLogsStatsStore()
	if store == nil {
		return nil
	}

	path := strings.TrimSpace(opts.Path)
	if path == "" {
		return nil
	}

	writeRaw := opts.WriteRaw
	if writeRaw == nil {
		writeRaw = bypassconf.AtomicWriteWithBackup
	}
	computeETag := opts.ComputeETag
	if computeETag == nil {
		computeETag = bypassconf.ComputeETag
	}

	fileRaw, hadFile, err := readFileMaybe(path)
	if err != nil {
		return err
	}
	dbRaw, dbETag, found, err := store.GetConfigBlob(opts.ConfigKey)
	if err != nil {
		return err
	}

	if found {
		if opts.ValidateRaw != nil {
			if err := opts.ValidateRaw(string(dbRaw)); err != nil {
				return err
			}
		}
		changed := !hadFile || !bytes.Equal(fileRaw, dbRaw)
		if !(opts.SkipWriteIfEqual && !changed) {
			if err := writeRaw(path, dbRaw); err != nil {
				return err
			}
		}
		if changed && opts.Reload != nil {
			if err := opts.Reload(); err != nil {
				return err
			}
		}

		needsUpsert := opts.ForceUpsertOnFound
		if strings.TrimSpace(dbETag) == "" {
			dbETag = computeETag(dbRaw)
			needsUpsert = true
		}
		if needsUpsert {
			if err := store.UpsertConfigBlob(opts.ConfigKey, dbRaw, dbETag, time.Now().UTC()); err != nil {
				return err
			}
		}
		return nil
	}

	if len(fileRaw) == 0 {
		return nil
	}
	return store.UpsertConfigBlob(opts.ConfigKey, fileRaw, computeETag(fileRaw), time.Now().UTC())
}
