package config

import (
	"os"
	"strings"
	"testing"
)

func TestDirReturnsHomePath(t *testing.T) {
	dir := Dir()
	home, _ := os.UserHomeDir()
	if !strings.HasPrefix(dir, home) {
		t.Errorf("Dir() = %q, want prefix %q", dir, home)
	}
	if !strings.HasSuffix(dir, ".pdmcguard") {
		t.Errorf("Dir() = %q, want suffix .pdmcguard", dir)
	}
}

func TestFilePathJoins(t *testing.T) {
	path := FilePath("machine.id")
	if !strings.HasSuffix(path, ".pdmcguard/machine.id") {
		t.Errorf("FilePath(machine.id) = %q, want suffix .pdmcguard/machine.id", path)
	}
}
