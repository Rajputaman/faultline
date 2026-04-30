// Package git provides helpers for extracting history metadata from a git repository.
// All git access is read-only and limited to log commands.
package git

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// ErrNotRepo is returned when a directory is not inside a git repository.
var ErrNotRepo = errors.New("not a git repository")

// RepoRoot returns the absolute path to the root of the git repository
// that contains dir, or ErrNotRepo if dir is not inside a git repo.
func RepoRoot(ctx context.Context, dir string) (string, error) {
	out, err := run(ctx, dir, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", ErrNotRepo
	}
	return strings.TrimSpace(out), nil
}

// IsRepo reports whether dir is inside a git repository.
func IsRepo(ctx context.Context, dir string) bool {
	_, err := RepoRoot(ctx, dir)
	return err == nil
}

// IsShallow reports whether the repository is a shallow clone. Errors degrade
// to false because older git versions may not support the command.
func IsShallow(ctx context.Context, repoRoot string) bool {
	out, err := run(ctx, repoRoot, "rev-parse", "--is-shallow-repository")
	if err != nil {
		return false
	}
	return strings.TrimSpace(out) == "true"
}

// run executes a git subcommand in the given directory and returns its stdout.
// Stderr is suppressed; a non-zero exit is treated as an error.
func run(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %w (stderr: %s)",
			strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// RelPath returns the path of absDir relative to repoRoot, or "." if equal.
// Both paths must be absolute.
func RelPath(repoRoot, absDir string) string {
	rel, err := filepath.Rel(repoRoot, absDir)
	if err != nil {
		return "."
	}
	return rel
}
