package policy

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestLoadConfigWithValidation(t *testing.T) {
	tests := []struct {
		name         string
		data         string
		wantWarnings int
		wantErr      bool
	}{
		{
			name: "valid config",
			data: `version: 1
ownership:
  max_author_count_90d: 6
coverage:
  min_package_coverage: 60
boundaries:
  - name: handlers
    from: "*/internal/handlers/*"
    deny:
      - "*/internal/storage/*"
suppressions:
  - id: FL-BND-001
    package: "*/internal/handlers/*"
    reason: "temporary"
    owner: "@team"
    expires: "2099-01-01"
`,
		},
		{
			name: "unknown top-level key warns",
			data: `version: 1
mystery: true
`,
			wantWarnings: 1,
		},
		{
			name: "unknown nested ownership key warns",
			data: `version: 1
ownership:
  require_codeowners: true
  unknown_owner_key: true
`,
			wantWarnings: 1,
		},
		{
			name: "unknown nested coverage key warns",
			data: `version: 1
coverage:
  min_package_coverage: 60
  unknown_coverage_key: true
`,
			wantWarnings: 1,
		},
		{
			name: "unknown nested scoring key warns",
			data: `version: 1
scoring:
  churn_max_lines_30d: 1000
  unknown_scoring_key: true
`,
			wantWarnings: 1,
		},
		{
			name: "unknown owners key warns",
			data: `version: 1
owners:
  modules:
    example.com/app:
      owner: "@app"
      extra: true
`,
			wantWarnings: 1,
		},
		{
			name: "valid owners config",
			data: `version: 1
owners:
  aliases:
    "@platform":
      - "alice@example.com"
  modules:
    example.com/app:
      owner: "@app"
`,
		},
		{
			name: "unknown boundary key warns",
			data: `version: 1
boundaries:
  - name: handlers
    from: "*"
    deny: ["*"]
    unknown_boundary_key: true
`,
			wantWarnings: 1,
		},
		{
			name: "unknown suppression key warns",
			data: `version: 1
suppressions:
  - id: FL-OWN-001
    package: "*"
    reason: "temporary"
    owner: "@team"
    expires: "2099-01-01"
    unknown_suppression_key: true
`,
			wantWarnings: 1,
		},
		{
			name: "invalid version errors",
			data: `version: 99
`,
			wantErr: true,
		},
		{
			name: "malformed yaml errors",
			data: `version: [
`,
			wantErr: true,
		},
		{
			name: "bad thresholds warn",
			data: `version: 1
ownership:
  max_author_count_90d: -1
coverage:
  min_package_coverage: 101
scoring:
  complexity_max_loc: 0
`,
			wantWarnings: 3,
		},
		{
			name: "invalid suppression expiry warns",
			data: `version: 1
suppressions:
  - id: FL-OWN-001
    package: "*"
    reason: "temporary"
    owner: "@team"
    expires: "tomorrow"
`,
			wantWarnings: 1,
		},
		{
			name: "missing boundary fields warn",
			data: `version: 1
boundaries:
  - name: ""
`,
			wantWarnings: 3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "faultline.yaml")
			if err := os.WriteFile(path, []byte(tt.data), 0600); err != nil {
				t.Fatal(err)
			}
			_, validation, err := LoadConfigWithValidation(path)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if validation.WarningCount != tt.wantWarnings {
				t.Fatalf("warnings = %d, want %d: %+v", validation.WarningCount, tt.wantWarnings, validation.Issues)
			}
		})
	}
}

func TestValidationWarningOrderingDeterministic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "faultline.yaml")
	data := `version: 1
suppressions:
  - id: FL-OWN-001
    package: "*"
    reason: "temporary"
    owner: "@team"
    expires: "bad"
    zzz: true
ownership:
  aaa: true
coverage:
  zzz: true
`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	_, first, err := LoadConfigWithValidation(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, second, err := LoadConfigWithValidation(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(first.Issues) != len(second.Issues) {
		t.Fatalf("issue count changed: %d vs %d", len(first.Issues), len(second.Issues))
	}
	for i := range first.Issues {
		if first.Issues[i] != second.Issues[i] {
			t.Fatalf("issue %d differs: %+v vs %+v", i, first.Issues[i], second.Issues[i])
		}
		if i > 0 && first.Issues[i-1].Path > first.Issues[i].Path {
			t.Fatalf("issues not sorted by path: %+v", first.Issues)
		}
	}
}

func TestConfigHashDeterministic(t *testing.T) {
	cfg := DefaultConfig()
	first := ConfigHash(cfg)
	second := ConfigHash(cfg)
	if first == "" || first != second {
		t.Fatalf("config hash not deterministic: %q %q", first, second)
	}
}

func TestRulePackResolution(t *testing.T) {
	repo := t.TempDir()
	mustWrite(t, filepath.Join(repo, ".faultline", "rules", "platform.yaml"), `ownership:
  require_codeowners: true
  max_author_count_90d: 8
coverage:
  min_package_coverage: 70
scoring:
  churn_max_lines_30d: 2000
  complexity_max_loc: 2000
boundaries:
  - name: shared
    from: "*/internal/handlers/*"
    deny: ["*/internal/storage/*"]
`)
	mustWrite(t, filepath.Join(repo, "faultline.yaml"), `version: 1
rule_packs:
  - path: .faultline/rules/platform.yaml
coverage:
  min_package_coverage: 85
scoring:
  complexity_max_loc: 1500
boundaries:
  - name: repo
    from: "*/internal/api/*"
    deny: ["*/internal/db/*"]
suppressions:
  - id: FL-OWN-001
    package: "*"
    reason: "repo local"
    owner: "@team"
    expires: "2099-01-01"
`)
	cfg, validation, err := ResolveConfigWithValidation(filepath.Join(repo, "faultline.yaml"), ResolveOptions{RepoRoot: repo})
	if err != nil {
		t.Fatalf("resolve config: %v", err)
	}
	if !cfg.Ownership.RequireCodeowners || cfg.Ownership.MaxAuthorCount90d != 8 {
		t.Fatalf("ownership not imported: %+v", cfg.Ownership)
	}
	if cfg.Coverage.MinPackageCoverage != 85 {
		t.Fatalf("base coverage should override pack, got %.2f", cfg.Coverage.MinPackageCoverage)
	}
	if cfg.Scoring.ChurnMaxLines30d != 2000 || cfg.Scoring.ComplexityMaxLOC != 1500 {
		t.Fatalf("scoring merge precedence incorrect: %+v", cfg.Scoring)
	}
	if len(cfg.Boundaries) != 2 {
		t.Fatalf("boundaries = %+v", cfg.Boundaries)
	}
	if len(cfg.Suppressions) != 1 {
		t.Fatalf("repo-local suppressions not preserved: %+v", cfg.Suppressions)
	}
	if len(validation.RulePacks) != 1 || !validation.RulePacks[0].Imported || validation.RulePacks[0].ContentHash == "" {
		t.Fatalf("missing rule pack audit: %+v", validation.RulePacks)
	}
}

func TestMultipleRulePackPrecedenceAndDuplicateBoundaries(t *testing.T) {
	repo := t.TempDir()
	mustWrite(t, filepath.Join(repo, "first.yaml"), `ownership:
  max_author_count_90d: 4
boundaries:
  - name: duplicate
    from: "*/a/*"
    deny: ["*/b/*"]
`)
	mustWrite(t, filepath.Join(repo, "second.yaml"), `ownership:
  max_author_count_90d: 9
boundaries:
  - name: duplicate
    from: "*/a/*"
    deny: ["*/c/*"]
`)
	mustWrite(t, filepath.Join(repo, "faultline.yaml"), `version: 1
rule_packs:
  - path: first.yaml
  - path: second.yaml
`)
	cfg, validation, err := ResolveConfigWithValidation(filepath.Join(repo, "faultline.yaml"), ResolveOptions{RepoRoot: repo})
	if err != nil {
		t.Fatalf("resolve config: %v", err)
	}
	if cfg.Ownership.MaxAuthorCount90d != 9 {
		t.Fatalf("later pack scalar should win, got %d", cfg.Ownership.MaxAuthorCount90d)
	}
	if len(cfg.Boundaries) != 1 || cfg.Boundaries[0].Deny[0] != "*/c/*" {
		t.Fatalf("duplicate boundary not overridden: %+v", cfg.Boundaries)
	}
	if !hasValidationMessage(validation.Issues, "duplicate boundary name") {
		t.Fatalf("expected duplicate boundary warning: %+v", validation.Issues)
	}
}

func TestMissingRulePackWarns(t *testing.T) {
	repo := t.TempDir()
	mustWrite(t, filepath.Join(repo, "faultline.yaml"), `version: 1
rule_packs:
  - path: missing.yaml
`)
	_, validation, err := ResolveConfigWithValidation(filepath.Join(repo, "faultline.yaml"), ResolveOptions{RepoRoot: repo})
	if err != nil {
		t.Fatalf("missing rule pack should warn, not error: %v", err)
	}
	if !hasValidationMessage(validation.Issues, "does not exist") {
		t.Fatalf("expected missing pack warning: %+v", validation.Issues)
	}
}

func TestRulePackPathTraversalRejected(t *testing.T) {
	repo := t.TempDir()
	outside := t.TempDir()
	mustWrite(t, filepath.Join(outside, "pack.yaml"), `coverage:
  min_package_coverage: 90
`)
	mustWrite(t, filepath.Join(repo, "faultline.yaml"), `version: 1
rule_packs:
  - path: ../`+filepath.Base(outside)+`/pack.yaml
`)
	_, validation, err := ResolveConfigWithValidation(filepath.Join(repo, "faultline.yaml"), ResolveOptions{RepoRoot: repo})
	if err == nil {
		t.Fatal("expected path traversal error")
	}
	if validation.ErrorCount == 0 {
		t.Fatalf("expected validation error: %+v", validation.Issues)
	}
}

func TestRulePackSymlinkEscapeRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink privileges vary on Windows")
	}
	repo := t.TempDir()
	outside := filepath.Join(t.TempDir(), "pack.yaml")
	mustWrite(t, outside, `coverage:
  min_package_coverage: 90
`)
	if err := os.Symlink(outside, filepath.Join(repo, "pack-link.yaml")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	mustWrite(t, filepath.Join(repo, "faultline.yaml"), `version: 1
rule_packs:
  - path: pack-link.yaml
`)
	_, validation, err := ResolveConfigWithValidation(filepath.Join(repo, "faultline.yaml"), ResolveOptions{RepoRoot: repo})
	if err == nil {
		t.Fatal("expected symlink escape error")
	}
	if validation.ErrorCount == 0 {
		t.Fatalf("expected validation error: %+v", validation.Issues)
	}
}

func TestRulePackSuppressionsWarnAndIgnored(t *testing.T) {
	repo := t.TempDir()
	mustWrite(t, filepath.Join(repo, "pack.yaml"), `suppressions:
  - id: FL-OWN-001
    package: "*"
    reason: "not allowed"
    owner: "@team"
    expires: "2099-01-01"
`)
	mustWrite(t, filepath.Join(repo, "faultline.yaml"), `version: 1
rule_packs:
  - path: pack.yaml
`)
	cfg, validation, err := ResolveConfigWithValidation(filepath.Join(repo, "faultline.yaml"), ResolveOptions{RepoRoot: repo})
	if err != nil {
		t.Fatalf("resolve config: %v", err)
	}
	if len(cfg.Suppressions) != 0 {
		t.Fatalf("rule pack suppressions should be ignored: %+v", cfg.Suppressions)
	}
	if !hasValidationMessage(validation.Issues, "suppressions must stay repo-local") {
		t.Fatalf("expected rule pack suppression warning: %+v", validation.Issues)
	}
}

func TestResolvedConfigHashDeterministic(t *testing.T) {
	repo := t.TempDir()
	mustWrite(t, filepath.Join(repo, "pack.yaml"), `coverage:
  min_package_coverage: 80
`)
	mustWrite(t, filepath.Join(repo, "faultline.yaml"), `version: 1
rule_packs:
  - path: pack.yaml
`)
	_, first, err := ResolveConfigWithValidation(filepath.Join(repo, "faultline.yaml"), ResolveOptions{RepoRoot: repo})
	if err != nil {
		t.Fatal(err)
	}
	_, second, err := ResolveConfigWithValidation(filepath.Join(repo, "faultline.yaml"), ResolveOptions{RepoRoot: repo})
	if err != nil {
		t.Fatal(err)
	}
	if first.ConfigHash == "" || first.ConfigHash != second.ConfigHash {
		t.Fatalf("resolved hash not deterministic: %q %q", first.ConfigHash, second.ConfigHash)
	}
}

func TestSuppressionPolicyValidation(t *testing.T) {
	now := time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name          string
		policy        string
		suppression   string
		wantWarnings  int
		wantSubstring string
	}{
		{
			name: "valid suppression under max days",
			policy: `suppression_policy:
  require_owner: true
  require_reason: true
  require_expiry: true
  max_days: 90
`,
			suppression: `  - id: FL-BND-001
    package: "*"
    reason: "migration"
    owner: "@team"
    created: "2026-04-01"
    expires: "2026-06-30"
`,
		},
		{
			name: "suppression exceeds max days",
			policy: `suppression_policy:
  max_days: 30
`,
			suppression: `  - id: FL-BND-001
    package: "*"
    reason: "migration"
    owner: "@team"
    created: "2026-04-01"
    expires: "2026-06-01"
`,
			wantWarnings:  1,
			wantSubstring: "exceeds suppression_policy.max_days",
		},
		{
			name: "missing owner reason and expiry under policy",
			policy: `suppression_policy:
  require_owner: true
  require_reason: true
  require_expiry: true
`,
			suppression: `  - id: FL-BND-001
    package: "*"
`,
			wantWarnings:  3,
			wantSubstring: "suppression_policy.require_owner",
		},
		{
			name: "invalid created date",
			policy: `suppression_policy:
  max_days: 30
`,
			suppression: `  - id: FL-BND-001
    package: "*"
    reason: "migration"
    owner: "@team"
    created: "next week"
    expires: "2026-05-20"
`,
			wantWarnings:  1,
			wantSubstring: "invalid created date",
		},
		{
			name: "scan date fallback max days",
			policy: `suppression_policy:
  max_days: 10
`,
			suppression: `  - id: FL-BND-001
    package: "*"
    reason: "migration"
    owner: "@team"
    expires: "2026-05-20"
`,
			wantWarnings:  1,
			wantSubstring: "from 2026-04-30",
		},
		{
			name: "partial suppression policy keeps default required metadata",
			policy: `suppression_policy:
  max_days: 90
`,
			suppression: `  - id: FL-BND-001
    package: "*"
`,
			wantWarnings:  3,
			wantSubstring: "suppression_policy.require_owner",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := t.TempDir()
			mustWrite(t, filepath.Join(repo, "faultline.yaml"), "version: 1\n"+tt.policy+"suppressions:\n"+tt.suppression)
			_, validation, err := ResolveConfigWithValidation(filepath.Join(repo, "faultline.yaml"), ResolveOptions{RepoRoot: repo, Now: now})
			if err != nil {
				t.Fatalf("resolve config: %v", err)
			}
			if validation.WarningCount != tt.wantWarnings {
				t.Fatalf("warnings = %d, want %d: %+v", validation.WarningCount, tt.wantWarnings, validation.Issues)
			}
			if tt.wantSubstring != "" && !hasValidationMessage(validation.Issues, tt.wantSubstring) {
				t.Fatalf("missing warning %q: %+v", tt.wantSubstring, validation.Issues)
			}
		})
	}
}

func TestRulePackSuppressionPolicyAppliesToRepoSuppressions(t *testing.T) {
	repo := t.TempDir()
	mustWrite(t, filepath.Join(repo, "pack.yaml"), `suppression_policy:
  require_owner: true
  require_reason: true
  require_expiry: true
  max_days: 7
`)
	mustWrite(t, filepath.Join(repo, "faultline.yaml"), `version: 1
rule_packs:
  - path: pack.yaml
suppressions:
  - id: FL-BND-001
    package: "*"
    reason: "migration"
    owner: "@team"
    expires: "2026-05-20"
`)
	_, validation, err := ResolveConfigWithValidation(filepath.Join(repo, "faultline.yaml"), ResolveOptions{
		RepoRoot: repo,
		Now:      time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("resolve config: %v", err)
	}
	if !hasValidationMessage(validation.Issues, "exceeds suppression_policy.max_days") {
		t.Fatalf("expected rule-pack max_days warning: %+v", validation.Issues)
	}
}

func mustWrite(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}

func hasValidationMessage(issues []ValidationIssue, needle string) bool {
	for _, issue := range issues {
		if strings.Contains(issue.Message, needle) {
			return true
		}
	}
	return false
}
