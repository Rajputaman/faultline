// Package ownership resolves package owners from CODEOWNERS and computes ownership entropy.
package ownership

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Rule is a single parsed line from a CODEOWNERS file.
type Rule struct {
	Pattern string
	Owners  []string
	Line    int
	Raw     string
}

// Codeowners holds the parsed rules from a CODEOWNERS file.
type Codeowners struct {
	Rules       []Rule
	Path        string
	Diagnostics []Diagnostic
}

// Diagnostic is a non-fatal CODEOWNERS compatibility issue.
type Diagnostic struct {
	Line    int
	Pattern string
	Message string
}

// OwnerMatch describes the CODEOWNERS rule selected for a path.
type OwnerMatch struct {
	File    string
	Line    int
	Pattern string
	Owners  []string
}

// LoadCodeowners looks for a CODEOWNERS file in GitHub's standard location
// precedence: .github/CODEOWNERS, CODEOWNERS, docs/CODEOWNERS.
// Returns nil, nil if no file is found.
func LoadCodeowners(repoRoot string) (*Codeowners, error) {
	candidates := []string{
		filepath.Join(repoRoot, ".github", "CODEOWNERS"),
		filepath.Join(repoRoot, "CODEOWNERS"),
		filepath.Join(repoRoot, "docs", "CODEOWNERS"),
	}
	for _, p := range candidates {
		co, err := parseFile(p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return co, nil
	}
	return nil, nil
}

func parseFile(path string) (*Codeowners, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var rules []Rule
	var diagnostics []Diagnostic
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := scanner.Text()
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields, err := codeownersFields(line)
		if err != nil {
			diagnostics = append(diagnostics, Diagnostic{Line: lineNo, Message: err.Error()})
			continue
		}
		if len(fields) < 2 {
			pattern := ""
			if len(fields) == 1 {
				pattern = fields[0]
			}
			diagnostics = append(diagnostics, Diagnostic{Line: lineNo, Pattern: pattern, Message: "rule has no owners"})
			continue
		}
		pattern := fields[0]
		for _, warning := range unsupportedPatternWarnings(pattern) {
			diagnostics = append(diagnostics, Diagnostic{Line: lineNo, Pattern: pattern, Message: warning})
		}
		for _, owner := range fields[1:] {
			if !validOwnerToken(owner) {
				diagnostics = append(diagnostics, Diagnostic{Line: lineNo, Pattern: pattern, Message: fmt.Sprintf("owner %q is not a GitHub team/user or email-like value", owner)})
			}
		}
		rules = append(rules, Rule{
			Pattern: pattern,
			Owners:  fields[1:],
			Line:    lineNo,
			Raw:     raw,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read CODEOWNERS %s: %w", path, err)
	}

	return &Codeowners{Rules: rules, Path: path, Diagnostics: diagnostics}, nil
}

// OwnersForPath returns the owners that apply to repoRelPath (e.g. "internal/api/handler.go").
// Rules are evaluated last-to-first (GitHub semantics: last matching rule wins).
// Returns nil if no rule matches.
func (co *Codeowners) OwnersForPath(repoRelPath string) []string {
	match := co.MatchForPath(repoRelPath)
	return match.Owners
}

// ResolveFileOwner returns the exact file-level CODEOWNERS rule for a
// repository-relative path.
func (co *Codeowners) ResolveFileOwner(repoRelativePath string) OwnerMatch {
	return co.MatchForPath(repoRelativePath)
}

// MatchForPath returns the last matching rule for repoRelPath.
func (co *Codeowners) MatchForPath(repoRelPath string) OwnerMatch {
	repoRelPath = filepath.ToSlash(repoRelPath)

	for i := len(co.Rules) - 1; i >= 0; i-- {
		r := co.Rules[i]
		if matchPattern(r.Pattern, repoRelPath) {
			return OwnerMatch{
				File:    co.Path,
				Line:    r.Line,
				Pattern: r.Pattern,
				Owners:  append([]string{}, r.Owners...),
			}
		}
	}
	return OwnerMatch{}
}

// OwnersForPackage returns the owners for the package at pkgDir.
// repoRoot and pkgDir must be absolute paths.
func (co *Codeowners) OwnersForPackage(repoRoot, pkgDir string) []string {
	match := co.MatchForPackage(repoRoot, pkgDir)
	return match.Owners
}

// MatchForPackage returns the CODEOWNERS rule for a package directory.
func (co *Codeowners) MatchForPackage(repoRoot, pkgDir string) OwnerMatch {
	rel, err := filepath.Rel(repoRoot, pkgDir)
	if err != nil {
		return OwnerMatch{}
	}
	rel = filepath.ToSlash(rel)
	// Try matching the directory itself, then a representative file pattern.
	if match := co.MatchForPath(rel + "/"); len(match.Owners) > 0 {
		return match
	}
	return co.MatchForPath(rel)
}

func codeownersFields(line string) ([]string, error) {
	var fields []string
	var current strings.Builder
	escaped := false
	for _, r := range line {
		if escaped {
			switch r {
			case ' ':
				current.WriteRune(' ')
			case '\t':
				current.WriteRune('\t')
			default:
				current.WriteRune('\\')
				current.WriteRune(r)
			}
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if r == '#' && current.Len() == 0 {
			break
		}
		if r == ' ' || r == '\t' {
			if current.Len() > 0 {
				fields = append(fields, current.String())
				current.Reset()
			}
			continue
		}
		current.WriteRune(r)
	}
	if escaped {
		return nil, errors.New("malformed rule: trailing escape")
	}
	if current.Len() > 0 {
		fields = append(fields, current.String())
	}
	return fields, nil
}

func unsupportedPatternWarnings(pattern string) []string {
	var warnings []string
	if strings.HasPrefix(pattern, "!") {
		warnings = append(warnings, "unsupported pattern: negation with ! is not supported by GitHub CODEOWNERS")
	}
	if strings.ContainsAny(pattern, "[]") {
		warnings = append(warnings, "unsupported pattern: character ranges are not supported by GitHub CODEOWNERS")
	}
	if strings.Contains(pattern, "\\#") {
		warnings = append(warnings, "unsupported pattern: escaped # is not supported by GitHub CODEOWNERS")
	}
	return warnings
}

var emailLike = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

func validOwnerToken(owner string) bool {
	if strings.HasPrefix(owner, "@") {
		return len(owner) > 1
	}
	return emailLike.MatchString(owner)
}

// matchPattern implements basic CODEOWNERS glob matching against a repo-relative path.
// Supports * (not crossing /), ** (crossing /), leading / (anchored), trailing / (directories).
func matchPattern(pattern, path string) bool {
	pattern = filepath.ToSlash(pattern)

	// Strip leading /  — in CODEOWNERS a leading slash means repo root.
	anchored := strings.HasPrefix(pattern, "/")
	if anchored {
		pattern = pattern[1:]
	}

	// Trailing / means "this directory and everything under it".
	if strings.HasSuffix(pattern, "/") {
		pattern = pattern + "**"
	}

	if anchored {
		return globMatch(pattern, path)
	}

	// Un-anchored: match against the path itself OR any suffix component.
	if globMatch(pattern, path) {
		return true
	}
	// Try matching against each path component suffix.
	parts := strings.Split(path, "/")
	for i := 1; i < len(parts); i++ {
		if globMatch(pattern, strings.Join(parts[i:], "/")) {
			return true
		}
	}
	return false
}

// globMatch is a minimal glob that supports * and **.
func globMatch(pattern, name string) bool {
	// Fast paths.
	if pattern == "**" {
		return true
	}
	if pattern == "*" {
		return !strings.Contains(name, "/")
	}

	// Split pattern and name on "/" and match segment by segment.
	pp := strings.Split(pattern, "/")
	np := strings.Split(name, "/")

	return matchSegments(pp, np)
}

func matchSegments(pp, np []string) bool {
	for len(pp) > 0 && len(np) > 0 {
		p := pp[0]
		if p == "**" {
			// ** matches zero or more path segments.
			if len(pp) == 1 {
				return true // ** at end matches everything remaining
			}
			// Try matching the rest of the pattern against every suffix of np.
			for i := 0; i <= len(np); i++ {
				if matchSegments(pp[1:], np[i:]) {
					return true
				}
			}
			return false
		}
		if !segmentMatch(p, np[0]) {
			return false
		}
		pp = pp[1:]
		np = np[1:]
	}
	// Consume trailing ** in pattern.
	for len(pp) > 0 && pp[0] == "**" {
		pp = pp[1:]
	}
	return len(pp) == 0 && len(np) == 0
}

// segmentMatch matches a single path segment against a glob pattern (no /).
func segmentMatch(pattern, segment string) bool {
	// filepath.Match handles * and ? within a single segment.
	matched, err := filepath.Match(pattern, segment)
	if err != nil {
		return false
	}
	return matched
}
