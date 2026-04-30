package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersionCommandOutputHasRequiredFields(t *testing.T) {
	var out bytes.Buffer
	cmd := NewRootCommand()
	cmd.SetOut(&out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"version"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("version command: %v", err)
	}
	got := out.String()
	for _, field := range []string{"version:", "commit:", "date:", "go:", "os/arch:"} {
		if !strings.Contains(got, field) {
			t.Fatalf("version output missing %q:\n%s", field, got)
		}
	}
}
