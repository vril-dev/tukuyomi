package bypassconf

import (
	"crypto/sha256"
	"encoding/hex"
)

func ComputeETag(b []byte) string {
	h := sha256.Sum256(b)
	return `W/"sha256:` + hex.EncodeToString(h[:]) + `"`
}
