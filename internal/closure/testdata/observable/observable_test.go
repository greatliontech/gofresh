package observable

import (
	"os"
	"testing"
)

func TestReadFile(*testing.T) {
	_, _ = os.ReadFile("fixture.txt")
}

func TestGetenv(*testing.T) {
	_ = os.Getenv("GOFRESH_OBSERVABLE")
}

func TestLookupEnv(*testing.T) {
	_, _ = os.LookupEnv("GOFRESH_OBSERVABLE")
}

func TestOpen(*testing.T) {
	file, _ := os.Open("fixture.txt")
	if file != nil {
		buffer := make([]byte, 1)
		_, _ = file.Read(buffer)
		_ = file.Close()
	}
}

func TestReadDir(*testing.T) {
	entries, _ := os.ReadDir(".")
	for _, entry := range entries {
		_ = entry.Name()
		_ = entry.IsDir()
		_ = entry.Type()
	}
}
