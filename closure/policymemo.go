package closure

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"
	"sync"
)

// policyMemo bounds repeated expansion of immutable admission metadata to one
// retained scalar answer. Every ask captures and keys all inputs; even a private
// table replacement is observed. The key is deliberately finer than the policy
// identity: documentary changes may miss, but never change the answer. No
// selected source, listing, audit verdict or mutable filesystem fact lives here.
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

// key preserves raw string bytes, including Label/Base values that rowChain
// compares before JSON encoding. JSON alone would coalesce invalid UTF-8 and
// could give different chain selections one lookup key. Nil maps/slices and
// their empty non-nil forms also remain distinct. This is a process-local
// lookup encoding, never the published policy identity or a persisted format.
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
	if in.rows == nil {
		count(0)
	} else {
		count(len(in.rows) + 1)
		for _, row := range in.rows {
			text(row.Label)
			text(row.Base)
			if row.Packages == nil {
				count(0)
				continue
			}
			count(len(row.Packages) + 1)
			keys := make([]string, 0, len(row.Packages))
			for key := range row.Packages {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				text(key)
				text(row.Packages[key])
			}
		}
	}
	return sha256.Sum256(data)
}
