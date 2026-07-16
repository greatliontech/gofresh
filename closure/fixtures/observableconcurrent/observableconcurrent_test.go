package observableconcurrent

import (
	"os"
	"testing"
)

func TestConcurrentFileRead(*testing.T) {
	file, _ := os.Open("fixture.txt")
	if file != nil {
		buffer := make([]byte, 1)
		go file.Read(buffer)
		_ = file.Close()
	}
}
