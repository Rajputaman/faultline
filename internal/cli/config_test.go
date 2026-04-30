package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConfigValidateAndExplain(t *testing.T) {
	configPath := writeTempConfig(t, `version: 1
ownership:
  require_codeowners: true
  max_author_count_90d: 6
coverage:
  min_package_coverage: 60
`)

	var validateOut bytes.Buffer
	validate := NewRootCommand()
	validate.SetOut(&validateOut)
	validate.SetErr(new(bytes.Buffer))
	validate.SetArgs([]string{"config", "validate", "--config", configPath})
	if err := validate.Execute(); err != nil {
		t.Fatalf("config validate: %v", err)
	}
	if !strings.Contains(validateOut.String(), "valid:") || !strings.Contains(validateOut.String(), "config_hash:") {
		t.Fatalf("unexpected validate output:\n%s", validateOut.String())
	}

	var explainOut bytes.Buffer
	explain := NewRootCommand()
	explain.SetOut(&explainOut)
	explain.SetErr(new(bytes.Buffer))
	explain.SetArgs([]string{"config", "explain", "--config", configPath, "--format", "markdown"})
	if err := explain.Execute(); err != nil {
		t.Fatalf("config explain: %v", err)
	}
	if !strings.Contains(explainOut.String(), "# Faultline Config Explanation") || !strings.Contains(explainOut.String(), "Config hash") {
		t.Fatalf("unexpected explain output:\n%s", explainOut.String())
	}
}

func TestConfigValidateStrictWarningsExitOne(t *testing.T) {
	configPath := writeTempConfig(t, `version: 1
unknown_top: true
`)
	cmd := NewRootCommand()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"config", "validate", "--config", configPath, "--strict"})
	err := cmd.Execute()
	var exitErr ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != 1 {
		t.Fatalf("expected strict warning exit 1, got %v", err)
	}
}

func TestConfigValidateStrictNestedUnknownKeyExitTwo(t *testing.T) {
	configPath := writeTempConfig(t, `version: 1
ownership:
  typo: true
`)
	cmd := NewRootCommand()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"config", "validate", "--config", configPath, "--strict"})
	err := cmd.Execute()
	var exitErr ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != 2 {
		t.Fatalf("expected nested strict warning exit 2, got %v", err)
	}
}

func TestConfigValidateStrictSuppressionPolicyExitTwo(t *testing.T) {
	configPath := writeTempConfig(t, `version: 1
suppression_policy:
  max_days: 7
suppressions:
  - id: FL-BND-001
    package: "*"
    reason: "too long"
    owner: "@team"
    created: "2026-04-01"
    expires: "2026-06-01"
`)
	cmd := NewRootCommand()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"config", "validate", "--config", configPath, "--strict"})
	err := cmd.Execute()
	var exitErr ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != 2 {
		t.Fatalf("expected suppression policy strict warning exit 2, got %v", err)
	}
}

func TestScanStrictConfigFailure(t *testing.T) {
	testRepo := testdataRepo(t)
	restore := chdir(t, testRepo)
	defer restore()

	configPath := writeTempConfig(t, `version: 1
unknown_top: true
`)
	cmd := NewRootCommand()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"scan", "./...", "--config", configPath, "--strict-config", "--format", "json", "--out", filepath.Join(t.TempDir(), "report.json"), "--no-history"})
	err := cmd.Execute()
	var exitErr ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != 2 {
		t.Fatalf("expected strict config scan exit 2, got %v", err)
	}
}

func TestScanStrictConfigFailsOnNestedUnknownKey(t *testing.T) {
	testRepo := testdataRepo(t)
	restore := chdir(t, testRepo)
	defer restore()

	configPath := writeTempConfig(t, `version: 1
ownership:
  require_codeowners: true
  typo: true
`)
	cmd := NewRootCommand()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"scan", "./...", "--config", configPath, "--strict-config", "--format", "json", "--out", filepath.Join(t.TempDir(), "report.json"), "--no-history"})
	err := cmd.Execute()
	var exitErr ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != 2 {
		t.Fatalf("expected nested strict config scan exit 2, got %v", err)
	}
}

func TestScanStrictConfigFailsOnSuppressionPolicyViolation(t *testing.T) {
	testRepo := testdataRepo(t)
	restore := chdir(t, testRepo)
	defer restore()

	configPath := writeTempConfig(t, `version: 1
suppression_policy:
  max_days: 7
suppressions:
  - id: FL-BND-001
    package: "*"
    reason: "too long"
    owner: "@team"
    created: "2026-04-01"
    expires: "2026-06-01"
`)
	cmd := NewRootCommand()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"scan", "./...", "--config", configPath, "--strict-config", "--format", "json", "--out", filepath.Join(t.TempDir(), "report.json"), "--no-history"})
	err := cmd.Execute()
	var exitErr ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != 2 {
		t.Fatalf("expected strict config scan exit 2, got %v", err)
	}
}

func TestConfigSchemaMarkdownAndJSON(t *testing.T) {
	var md bytes.Buffer
	markdownCmd := NewRootCommand()
	markdownCmd.SetOut(&md)
	markdownCmd.SetErr(new(bytes.Buffer))
	markdownCmd.SetArgs([]string{"config", "schema", "--format", "markdown"})
	if err := markdownCmd.Execute(); err != nil {
		t.Fatalf("config schema markdown: %v", err)
	}
	if !strings.Contains(md.String(), "# Faultline Config Schema") || !strings.Contains(md.String(), "suppressions[].expires") {
		t.Fatalf("unexpected markdown schema:\n%s", md.String())
	}

	var js bytes.Buffer
	jsonCmd := NewRootCommand()
	jsonCmd.SetOut(&js)
	jsonCmd.SetErr(new(bytes.Buffer))
	jsonCmd.SetArgs([]string{"config", "schema", "--format", "json"})
	if err := jsonCmd.Execute(); err != nil {
		t.Fatalf("config schema json: %v", err)
	}
	var schema struct {
		SupportedVersion int `json:"supported_version"`
		Sections         []struct {
			Name string `json:"name"`
		} `json:"sections"`
	}
	if err := json.Unmarshal(js.Bytes(), &schema); err != nil {
		t.Fatalf("unmarshal schema: %v", err)
	}
	if schema.SupportedVersion != 1 || len(schema.Sections) == 0 {
		t.Fatalf("unexpected schema: %+v", schema)
	}
}

func TestConfigResolvedOutput(t *testing.T) {
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, ".faultline", "rules"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".faultline", "rules", "platform.yaml"), []byte(`coverage:
  min_package_coverage: 75
`), 0600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(repo, "faultline.yaml")
	if err := os.WriteFile(configPath, []byte(`version: 1
rule_packs:
  - path: .faultline/rules/platform.yaml
`), 0600); err != nil {
		t.Fatal(err)
	}
	restore := chdir(t, repo)
	defer restore()

	out := filepath.Join(t.TempDir(), "resolved.json")
	cmd := NewRootCommand()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"config", "resolved", "--config", configPath, "--format", "json", "--out", out})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("config resolved: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var resolved struct {
		Config struct {
			Coverage struct {
				MinPackageCoverage float64 `json:"min_package_coverage"`
			} `json:"coverage"`
		} `json:"config"`
		RulePacks []struct {
			Path     string `json:"path"`
			Imported bool   `json:"imported"`
		} `json:"rule_packs"`
		ResolvedConfigHash string `json:"resolved_config_hash"`
	}
	if err := json.Unmarshal(data, &resolved); err != nil {
		t.Fatalf("unmarshal resolved config: %v", err)
	}
	if resolved.Config.Coverage.MinPackageCoverage != 75 || len(resolved.RulePacks) != 1 || !resolved.RulePacks[0].Imported || resolved.ResolvedConfigHash == "" {
		t.Fatalf("unexpected resolved output: %s", string(data))
	}
}

func TestConfigDocsGroupsSuppressions(t *testing.T) {
	expired := time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02")
	soon := time.Now().UTC().AddDate(0, 0, 7).Format("2006-01-02")
	configPath := writeTempConfig(t, `version: 1
suppressions:
  - id: FL-OWN-001
    package: "*"
    reason: "active"
    owner: "@team"
    expires: "2099-01-01"
  - id: FL-COV-001
    package: "*"
    reason: "expired"
    owner: "@team"
    expires: "`+expired+`"
  - id: FL-COV-002
    package: "*"
    reason: "soon"
    owner: "@team"
    expires: "`+soon+`"
`)
	var out bytes.Buffer
	cmd := NewRootCommand()
	cmd.SetOut(&out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"config", "docs", "--config", configPath, "--format", "markdown"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("config docs: %v", err)
	}
	got := out.String()
	for _, want := range []string{"# Faultline Policy Documentation", "Active Suppressions", "Expired Suppressions", "Expiring Soon Suppressions", "Strict-mode suitability"} {
		if !strings.Contains(got, want) {
			t.Fatalf("docs missing %q:\n%s", want, got)
		}
	}
}

func TestSuppressionsAuditClassifiesSuppressions(t *testing.T) {
	testRepo := testdataRepo(t)
	restore := chdir(t, testRepo)
	defer restore()

	expired := time.Now().UTC().AddDate(0, 0, -30).Format("2006-01-02")
	soon := time.Now().UTC().AddDate(0, 0, 15).Format("2006-01-02")
	configPath := writeTempConfig(t, `version: 1
boundaries:
  - name: main-must-not-import-store
    from: "github.com/faultline-go/faultline/testdata/simple-go-module"
    deny:
      - "*/internal/store"
suppressions:
  - id: FL-BND-001
    category: BOUNDARY
    package: "github.com/faultline-go/faultline/testdata/simple-go-module"
    reason: "active match"
    owner: "@test"
    expires: "2099-01-01"
  - id: FL-OWN-001
    package: "*/does/not/match"
    reason: "unmatched"
    owner: "@test"
    expires: "2099-01-01"
  - id: FL-COV-001
    package: "*"
    reason: "expired"
    owner: "@test"
    expires: "`+expired+`"
  - id: FL-COV-002
    package: "*"
    reason: "soon"
    owner: "@test"
    expires: "`+soon+`"
  - id: FL-DEP-001
    package: "*"
    reason: "missing owner"
    expires: "2099-01-01"
`)
	out := filepath.Join(t.TempDir(), "audit.json")
	cmd := NewRootCommand()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"suppressions", "audit", "--config", configPath, "--format", "json", "--out", out})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("suppressions audit: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var audit struct {
		Active           []any `json:"active"`
		Expired          []any `json:"expired"`
		ExpiringSoon     []any `json:"expiring_soon"`
		Invalid          []any `json:"invalid"`
		PolicyViolations []any `json:"policy_violations"`
		Unmatched        []any `json:"unmatched"`
	}
	if err := json.Unmarshal(data, &audit); err != nil {
		t.Fatalf("unmarshal audit: %v", err)
	}
	if len(audit.Active) != 3 || len(audit.Expired) != 1 || len(audit.ExpiringSoon) != 1 || len(audit.Invalid) != 1 || len(audit.PolicyViolations) != 2 || len(audit.Unmatched) != 1 {
		t.Fatalf("unexpected audit counts: active=%d expired=%d soon=%d invalid=%d policy=%d unmatched=%d\n%s",
			len(audit.Active), len(audit.Expired), len(audit.ExpiringSoon), len(audit.Invalid), len(audit.PolicyViolations), len(audit.Unmatched), string(data))
	}
}

func writeTempConfig(t *testing.T, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "faultline.yaml")
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
