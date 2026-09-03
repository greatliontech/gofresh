package closure

import (
	"context"
	"strings"
	"testing"
)

func TestNewAtContextEnvRejectsExternalPackageDriver(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	env := environmentWith("GOPACKAGESDRIVER=custom")
	if _, err := NewAtContextEnv(context.Background(), t.TempDir(), env); err == nil || !strings.Contains(err.Error(), "GOPACKAGESDRIVER") {
		t.Fatalf("external package driver accepted: %v", err)
	}
}
