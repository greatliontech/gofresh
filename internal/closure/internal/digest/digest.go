// Package digest is the closure analyses' shared content-digest
// discipline: one function, one format, every consumer.
package digest

import (
	"crypto/sha256"
	"encoding/hex"
)

func Content(content []byte) string {
	return FromSum(sha256.Sum256(content))
}

// FromSum is Content over a sum already computed — the one truncation
// every consumer shares.
func FromSum(sum [32]byte) string {
	return hex.EncodeToString(sum[:])[:32]
}
