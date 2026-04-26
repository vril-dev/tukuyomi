package requestmeta

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

const (
	MMDBConfigDomain           = "request_country_mmdb_asset"
	MMDBConfigSchemaVersion    = 1
	MMDBStorageLabel           = "db:" + MMDBConfigDomain
	GeoIPConfigDomain          = "request_country_geoip_config"
	GeoIPConfigSchemaVersion   = 1
	GeoIPConfigStorageLabel    = "db:" + GeoIPConfigDomain
	UpdateStateTable           = "request_country_update_state"
	UpdateStateStorageLabel    = "db:" + UpdateStateTable
	UpdateStateDefaultStateKey = "default"
)

type MMDBAssetVersion struct {
	Present     bool
	Raw         []byte
	SizeBytes   int64
	ContentHash string
	ETag        string
}

type GeoIPConfigVersion struct {
	Present   bool
	Raw       []byte
	Summary   GeoIPConfigSummary
	SizeBytes int64
	ETag      string
}

func NormalizeMMDBAssetVersion(asset MMDBAssetVersion) MMDBAssetVersion {
	asset.Raw = append([]byte(nil), asset.Raw...)
	if !asset.Present {
		asset.Raw = nil
		asset.SizeBytes = 0
		asset.ContentHash = ""
		return asset
	}
	asset.SizeBytes = int64(len(asset.Raw))
	asset.ContentHash = sha256HexBytes(asset.Raw)
	return asset
}

func NormalizeGeoIPConfigVersion(cfg GeoIPConfigVersion) GeoIPConfigVersion {
	cfg.Raw = append([]byte(nil), cfg.Raw...)
	if !cfg.Present {
		cfg.Raw = nil
		cfg.SizeBytes = 0
		cfg.Summary = GeoIPConfigSummary{}
		return cfg
	}
	cfg.SizeBytes = int64(len(cfg.Raw))
	cfg.Summary.EditionIDs = append([]string(nil), cfg.Summary.EditionIDs...)
	return cfg
}

func MMDBAssetHash(asset MMDBAssetVersion) string {
	asset = NormalizeMMDBAssetVersion(asset)
	sum := sha256.New()
	if asset.Present {
		_, _ = sum.Write([]byte("present:1\n"))
		_, _ = sum.Write(asset.Raw)
	} else {
		_, _ = sum.Write([]byte("present:0\n"))
	}
	return hex.EncodeToString(sum.Sum(nil))
}

func GeoIPConfigHash(cfg GeoIPConfigVersion) string {
	cfg = NormalizeGeoIPConfigVersion(cfg)
	sum := sha256.New()
	if cfg.Present {
		_, _ = sum.Write([]byte("present:1\n"))
		_, _ = sum.Write(cfg.Raw)
	} else {
		_, _ = sum.Write([]byte("present:0\n"))
	}
	return hex.EncodeToString(sum.Sum(nil))
}

func NormalizeUpdateState(state UpdateState) UpdateState {
	state.LastAttempt = strings.TrimSpace(state.LastAttempt)
	state.LastSuccess = strings.TrimSpace(state.LastSuccess)
	state.LastResult = strings.TrimSpace(state.LastResult)
	state.LastError = strings.TrimSpace(state.LastError)
	return state
}

func sha256HexBytes(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}
