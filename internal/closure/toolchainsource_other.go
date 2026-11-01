//go:build !unix

package closure

import "io/fs"

// changeTime is 0 where the platform's stat carries no change time;
// the stamp then rests on the name, size and modification time.
func changeTime(fs.FileInfo) int64 { return 0 }

// stampsTrusted: no change time here — a listing memo never serves;
// every construction lists.
const stampsTrusted = false
