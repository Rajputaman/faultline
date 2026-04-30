package git

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// ChurnStats holds file-change counts for a package directory.
type ChurnStats struct {
	// Churn30d is the number of file-level changes in the last 30 days.
	Churn30d int
	// Churn90d is the number of file-level changes in the last 90 days.
	Churn90d int
	// AuthorCount90d is the number of distinct commit authors in the last 90 days.
	AuthorCount90d int
}

const (
	Window30d = "30 days ago"
	Window90d = "90 days ago"
)

// PackageChurn returns churn statistics for the given package directory.
// repoRoot is the absolute path to the repository root.
// pkgDir is the absolute path to the package directory.
// If the directory has no git history, zero values are returned without error.
func PackageChurn(ctx context.Context, repoRoot, pkgDir string) (ChurnStats, error) {
	rel := RelPath(repoRoot, pkgDir)

	churn30, err := countChangedLines(ctx, repoRoot, rel, Window30d)
	if err != nil {
		return ChurnStats{}, fmt.Errorf("churn 30d for %s: %w", pkgDir, err)
	}

	churn90, err := countChangedLines(ctx, repoRoot, rel, Window90d)
	if err != nil {
		return ChurnStats{}, fmt.Errorf("churn 90d for %s: %w", pkgDir, err)
	}

	authors, err := countAuthors(ctx, repoRoot, rel, Window90d)
	if err != nil {
		return ChurnStats{}, fmt.Errorf("authors 90d for %s: %w", pkgDir, err)
	}

	return ChurnStats{
		Churn30d:       churn30,
		Churn90d:       churn90,
		AuthorCount90d: authors,
	}, nil
}

// PackageAuthorCounts returns the number of commits per author email in the
// package directory during the last 90 days. Missing history returns an empty map.
func PackageAuthorCounts(ctx context.Context, repoRoot, pkgDir string) (map[string]int, error) {
	rel := RelPath(repoRoot, pkgDir)
	args := []string{
		"log",
		"--since=" + Window90d,
		"--format=%ae",
		"--",
		rel,
	}
	out, err := run(ctx, repoRoot, args...)
	if err != nil {
		return map[string]int{}, nil
	}

	counts := make(map[string]int)
	for _, line := range strings.Split(out, "\n") {
		email := strings.TrimSpace(line)
		if email != "" {
			counts[email]++
		}
	}
	return counts, nil
}

// countChangedLines counts added+deleted lines in the given directory since the
// given git date string. Binary file changes are skipped.
func countChangedLines(ctx context.Context, repoRoot, relDir, since string) (int, error) {
	args := []string{
		"log",
		"--since=" + since,
		"--numstat",
		"--format=",
		"--",
		relDir,
	}
	out, err := run(ctx, repoRoot, args...)
	if err != nil {
		// No commits in range is not an error.
		return 0, nil
	}

	total := 0
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] == "-" || fields[1] == "-" {
			continue
		}
		added, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		deleted, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		total += added + deleted
	}
	return total, nil
}

// countAuthors counts distinct author email addresses in the given directory
// over the given time window.
func countAuthors(ctx context.Context, repoRoot, relDir, since string) (int, error) {
	args := []string{
		"log",
		"--since=" + since,
		"--format=%ae",
		"--",
		relDir,
	}
	out, err := run(ctx, repoRoot, args...)
	if err != nil {
		return 0, nil
	}

	seen := make(map[string]struct{})
	for _, line := range strings.Split(out, "\n") {
		email := strings.TrimSpace(line)
		if email != "" {
			seen[email] = struct{}{}
		}
	}
	return len(seen), nil
}
