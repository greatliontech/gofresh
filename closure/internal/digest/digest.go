// Package digest is the closure analyses' shared content-digest
// discipline: one function, one format, every consumer.
package digest

import (
	"crypto/sha256"
	"encoding/hex"
)

func Content(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])[:32]
}
