package cli

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPRReviewCommandWorksLocallyAndWritesMarkdown(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "go.mod"), "module github.com/example/prfixture\n\ngo 1.26\n")
	writeTestFile(t, filepath.Join(dir, "pkg", "risk", "risk.go"), "package risk\n\nfunc Value() int { return 1 }\n")
	runTestGit(t, dir, "init")
	runTestGit(t, dir, "config", "user.email", "test@example.com")
	runTestGit(t, dir, "config", "user.name", "Test")
	runTestGit(t, dir, "add", ".")
	runTestGit(t, dir, "commit", "-m", "initial")
	writeTestFile(t, filepath.Join(dir, "pkg", "risk", "risk.go"), "package risk\n\nfunc Value() int { return 2 }\n")
	runTestGit(t, dir, "add", ".")
	runTestGit(t, dir, "commit", "-m", "change risk")

	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GITHUB_REPOSITORY", "")
	t.Setenv("GITHUB_REF", "")
	t.Setenv("GITHUB_BASE_REF", "")
	t.Setenv("GITHUB_SHA", "")

	restore := chdir(t, dir)
	defer restore()

	out := filepath.Join(t.TempDir(), "faultline-pr.md")
	cmd := NewRootCommand()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"pr", "review", "--base", "HEAD~1", "--head", "HEAD", "--comment-out", out})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("pr review: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	if !strings.Contains(body, "# Faultline PR Risk Review") || !strings.Contains(body, "Changed packages: 1") {
		t.Fatalf("unexpected markdown:\n%s", body)
	}
}

func TestPRReviewWorktreeFailureReturnsExitCode2(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "go.mod"), "module github.com/example/prfixture\n\ngo 1.26\n")
	writeTestFile(t, filepath.Join(dir, "pkg", "risk", "risk.go"), "package risk\n\nfunc Value() int { return 1 }\n")
	runTestGit(t, dir, "init")
	runTestGit(t, dir, "config", "user.email", "test@example.com")
	runTestGit(t, dir, "config", "user.name", "Test")
	runTestGit(t, dir, "add", ".")
	runTestGit(t, dir, "commit", "-m", "initial")

	restore := chdir(t, dir)
	defer restore()

	cmd := NewRootCommand()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"pr", "review", "--base", "refs/heads/does-not-exist", "--head", "HEAD", "--compare-mode", "worktree", "--comment-out", filepath.Join(t.TempDir(), "review.md")})
	err := cmd.Execute()
	var exitErr ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != 2 {
		t.Fatalf("expected exit code 2, got err=%v", err)
	}
}

func TestPRReviewInvalidExplicitHeadReturnsExitCode2(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "go.mod"), "module github.com/example/prfixture\n\ngo 1.26\n")
	writeTestFile(t, filepath.Join(dir, "pkg", "risk", "risk.go"), "package risk\n\nfunc Value() int { return 1 }\n")
	runTestGit(t, dir, "init")
	runTestGit(t, dir, "config", "user.email", "test@example.com")
	runTestGit(t, dir, "config", "user.name", "Test")
	runTestGit(t, dir, "add", ".")
	runTestGit(t, dir, "commit", "-m", "initial")

	restore := chdir(t, dir)
	defer restore()

	cmd := NewRootCommand()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"pr", "review", "--base", "HEAD", "--head", "refs/heads/does-not-exist", "--compare-mode", "auto", "--comment-out", filepath.Join(t.TempDir(), "review.md")})
	err := cmd.Execute()
	var exitErr ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != 2 {
		t.Fatalf("expected exit code 2, got err=%v", err)
	}
}

func runTestGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, string(out))
	}
}

func writeTestFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}
