package closure

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"
	"sync"
)

// policyMemo bounds repeated expansion of immutable admission metadata to one
// retained scalar answer. Every ask captures and keys all inputs; even a private
// table replacement is observed. No selected source, listing, audit verdict or
// mutable filesystem fact lives here.
type policyMemo struct {
	mu     sync.Mutex
	key    [sha256.Size]byte
	result string
}

func (m *policyMemo) value(in policyInputs) string {
	key := in.key()
	m.mu.Lock()
	result := m.result
	hit := result != "" && m.key == key
	m.mu.Unlock()
	if hit {
		return result
	}
	result = in.derive()
	m.mu.Lock()
	m.key, m.result = key, result
	m.mu.Unlock()
	return result
}

// key preserves raw string bytes. Nil maps/slices and their empty non-nil forms
// also remain distinct. This is a process-local lookup encoding, never the
// published policy identity or a persisted format.
func (in policyInputs) key() [sha256.Size]byte {
	var data []byte
	count := func(n int) { data = binary.AppendUvarint(data, uint64(n)) }
	text := func(s string) {
		count(len(s))
		data = append(data, s...)
	}
	bools := func(values map[string]bool) {
		if values == nil {
			count(0)
			return
		}
		count(len(values) + 1)
		keys := make([]string, 0, len(values))
		for key := range values {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			text(key)
			if values[key] {
				data = append(data, 1)
			} else {
				data = append(data, 0)
			}
		}
	}
	text(in.verifier)
	text(in.audit)
	bools(in.packages)
	bools(in.linknames)
	if in.seeds == nil {
		count(0)
	} else {
		count(len(in.seeds) + 1)
		for _, seed := range in.seeds {
			text(seed)
		}
	}
	return sha256.Sum256(data)
}
