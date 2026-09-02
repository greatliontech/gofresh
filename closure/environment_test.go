package closure

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestNewAtContextEnvRejectsExternalPackageDriver(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	env := make([]string, 0, len(os.Environ())+1)
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "GOPACKAGESDRIVER=") {
			env = append(env, entry)
		}
	}
	env = append(env, "GOPACKAGESDRIVER=custom")
	if _, err := NewAtContextEnv(context.Background(), t.TempDir(), env); err == nil || !strings.Contains(err.Error(), "GOPACKAGESDRIVER") {
		t.Fatalf("external package driver accepted: %v", err)
	}
}
