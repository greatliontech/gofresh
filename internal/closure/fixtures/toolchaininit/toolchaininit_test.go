package toolchaininit

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// The accessor admission is subject-stage only: capturing it at package
// scope is a startup effect and blocks uniformly.
var root = runtime.GOROOT()

func TestReadThroughInitRoot(*testing.T) {
	_, _ = os.ReadFile(filepath.Join(root, "VERSION"))
}
