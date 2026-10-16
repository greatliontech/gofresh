package runtimeinput

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestAliasRootListingAvailabilityDoesNotMixStatIdentities(t *testing.T) {
	dir := t.TempDir()
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(".", alias); err != nil {
		t.Fatal(err)
	}
	original := walkRuntimeDirectory
	t.Cleanup(func() { walkRuntimeDirectory = original })
	denied := false
	walkRuntimeDirectory = func(root string, visit fs.WalkDirFunc) error {
		if root != dir || !denied {
			return original(root, visit)
		}
		// filepath.WalkDir visits the root before attempting its listing, then
		// visits it again with the read error. Only that read is unavailable;
		// all actual namespace and followed-object stat observations stay live.
		info, err := os.Lstat(root)
		if err != nil {
			return err
		}
		entry := fs.FileInfoToDirEntry(info)
		if err := visit(root, entry, nil); err != nil {
			return err
		}
		return visit(root, entry, &os.PathError{Op: "readdir", Path: root, Err: fs.ErrPermission})
	}
	for _, before := range []bool{false, true} {
		for _, after := range []bool{false, true} {
			denied = before
			b := testBracket(t, dir, "alias")
			denied = after
			unchanged, moved, reason, err := b.revalidate(t.Context(), dir)
			if err != nil || moved || unchanged != (!before && !after) || (reason != "") != (before || after) {
				t.Fatalf("listing unavailable %t -> %t changed stat meaning: unchanged=%t moved=%t reason=%q err=%v", before, after, unchanged, moved, reason, err)
			}
		}
	}
}
