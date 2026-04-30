package version

import (
	"runtime"
	"strings"
	"testing"
)

func TestDefaultsAreSane(t *testing.T) {
	info := Get()
	if info.Version == "" || info.Commit == "" || info.Date == "" {
		t.Fatalf("metadata defaults should be populated: %+v", info)
	}
	if info.GoVersion != runtime.Version() {
		t.Fatalf("GoVersion = %q, want %q", info.GoVersion, runtime.Version())
	}
	if info.OS != runtime.GOOS || info.Arch != runtime.GOARCH {
		t.Fatalf("os/arch = %s/%s, want %s/%s", info.OS, info.Arch, runtime.GOOS, runtime.GOARCH)
	}
}

func TestFullStringHasRequiredFields(t *testing.T) {
	out := FullString()
	for _, field := range []string{"version:", "commit:", "date:", "go:", "os/arch:"} {
		if !strings.Contains(out, field) {
			t.Fatalf("FullString missing %q:\n%s", field, out)
		}
	}
}
