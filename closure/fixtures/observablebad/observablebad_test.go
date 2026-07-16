package observablebad

import (
	"os"
	"testing"
)

func TestOpenStat(*testing.T) {
	file, _ := os.Open("fixture.txt")
	if file != nil {
		_, _ = file.Stat()
		_ = file.Close()
	}
}

func ReadUnattributed(file *os.File) {
	buffer := make([]byte, 1)
	_, _ = file.Read(buffer)
}

func TestReadDirInfo(*testing.T) {
	entries, _ := os.ReadDir(".")
	if len(entries) != 0 {
		_, _ = entries[0].Info()
	}
}
