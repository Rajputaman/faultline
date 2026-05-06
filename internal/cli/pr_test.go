package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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

func TestPRReviewEnterpriseUploadPostsHeadSnapshot(t *testing.T) {
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

	var requestPath string
	var authHeader string
	var schemaVersion string
	var packageCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath = r.URL.Path
		authHeader = r.Header.Get("Authorization")
		var body struct {
			SchemaVersion string            `json:"schema_version"`
			Packages      []json.RawMessage `json:"packages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode upload body: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		schemaVersion = body.SchemaVersion
		packageCount = len(body.Packages)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"snapshot_id":"snap_pr","repo_id":"repo_1","package_count":1,"finding_count":2,"created_at":"2026-05-06T00:00:00Z"}`))
	}))
	defer server.Close()

	restore := chdir(t, dir)
	defer restore()

	errOut := new(bytes.Buffer)
	cmd := NewRootCommand()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(errOut)
	cmd.SetArgs([]string{
		"pr", "review",
		"--base", "HEAD~1",
		"--head", "HEAD",
		"--comment-out", filepath.Join(t.TempDir(), "review.md"),
		"--enterprise-url", server.URL,
		"--enterprise-token", "flt_test_token",
		"--enterprise-org-id", "org_123",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("pr review: %v\nstderr:\n%s", err, errOut.String())
	}
	if requestPath != "/v1/orgs/org_123/snapshots" {
		t.Fatalf("upload path = %q", requestPath)
	}
	if authHeader != "Bearer flt_test_token" {
		t.Fatalf("Authorization header = %q", authHeader)
	}
	if schemaVersion != "faultline.snapshot.v1" {
		t.Fatalf("schema version = %q", schemaVersion)
	}
	if packageCount == 0 {
		t.Fatalf("expected uploaded snapshot packages")
	}
	if !strings.Contains(errOut.String(), "enterprise: snapshot uploaded (id: snap_pr") {
		t.Fatalf("missing upload success output:\n%s", errOut.String())
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
