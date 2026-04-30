package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCommandBuildsWithCGODisabled(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CGO-disabled build in short mode")
	}
	repoRoot := repoRootForTest(t)
	out := filepath.Join(t.TempDir(), "faultline")
	if runtime.GOOS == "windows" {
		out += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", out, "./cmd/faultline")
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if data, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("CGO_ENABLED=0 go build ./cmd/faultline: %v\n%s", err, string(data))
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("expected built binary: %v", err)
	}
}

func repoRootForTest(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
