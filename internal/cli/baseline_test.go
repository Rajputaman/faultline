package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestBaselineCreateAndCheckAgainstTestdata(t *testing.T) {
	testRepo := testdataRepo(t)
	restore := chdir(t, testRepo)
	defer restore()

	tmp := t.TempDir()
	baselinePath := filepath.Join(tmp, "faultline-baseline.json")
	create := NewRootCommand()
	create.SetOut(new(bytes.Buffer))
	create.SetErr(new(bytes.Buffer))
	create.SetArgs([]string{"baseline", "create", "--out", baselinePath})
	if err := create.Execute(); err != nil {
		t.Fatalf("baseline create: %v", err)
	}

	data, err := os.ReadFile(baselinePath)
	if err != nil {
		t.Fatal(err)
	}
	var baseline struct {
		SchemaVersion int `json:"schema_version"`
		PackageRisks  []struct {
			ImportPath string  `json:"import_path"`
			RiskScore  float64 `json:"risk_score"`
		} `json:"package_risks"`
		FindingIdentities []struct {
			Key string `json:"key"`
		} `json:"finding_identities"`
	}
	if err := json.Unmarshal(data, &baseline); err != nil {
		t.Fatalf("unmarshal baseline: %v", err)
	}
	if baseline.SchemaVersion != 1 || len(baseline.PackageRisks) == 0 {
		t.Fatalf("unexpected baseline: %+v", baseline)
	}

	out := filepath.Join(tmp, "baseline-check.json")
	check := NewRootCommand()
	check.SetOut(new(bytes.Buffer))
	check.SetErr(new(bytes.Buffer))
	check.SetArgs([]string{"baseline", "check", "--baseline", baselinePath, "--format", "json", "--out", out, "--fail-on-new", "high"})
	if err := check.Execute(); err != nil {
		t.Fatalf("baseline check: %v", err)
	}
	checkData, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Summary struct {
			Failed bool `json:"failed"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(checkData, &result); err != nil {
		t.Fatalf("unmarshal check result: %v", err)
	}
	if result.Summary.Failed {
		t.Fatal("same scan should not fail baseline check")
	}
}

func TestBaselineCheckNewHighFindingFails(t *testing.T) {
	testRepo := testdataRepo(t)
	restore := chdir(t, testRepo)
	defer restore()

	tmp := t.TempDir()
	baselinePath := filepath.Join(tmp, "faultline-baseline.json")
	create := NewRootCommand()
	create.SetOut(new(bytes.Buffer))
	create.SetErr(new(bytes.Buffer))
	create.SetArgs([]string{"baseline", "create", "--out", baselinePath})
	if err := create.Execute(); err != nil {
		t.Fatalf("baseline create: %v", err)
	}

	configPath := filepath.Join(tmp, "faultline.yaml")
	if err := os.WriteFile(configPath, []byte(boundaryConfig("")), 0600); err != nil {
		t.Fatal(err)
	}
	check := NewRootCommand()
	check.SetOut(new(bytes.Buffer))
	check.SetErr(new(bytes.Buffer))
	check.SetArgs([]string{"baseline", "check", "--baseline", baselinePath, "--config", configPath, "--fail-on-new", "high"})
	err := check.Execute()
	var exitErr ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != 1 {
		t.Fatalf("expected exit 1, got err=%v", err)
	}
}

func TestBaselineCheckSuppressedHighDoesNotFail(t *testing.T) {
	testRepo := testdataRepo(t)
	restore := chdir(t, testRepo)
	defer restore()

	tmp := t.TempDir()
	baselinePath := filepath.Join(tmp, "faultline-baseline.json")
	create := NewRootCommand()
	create.SetOut(new(bytes.Buffer))
	create.SetErr(new(bytes.Buffer))
	create.SetArgs([]string{"baseline", "create", "--out", baselinePath})
	if err := create.Execute(); err != nil {
		t.Fatalf("baseline create: %v", err)
	}

	configPath := filepath.Join(tmp, "faultline.yaml")
	if err := os.WriteFile(configPath, []byte(boundaryConfig(`suppressions:
  - id: FL-BND-001
    category: BOUNDARY
    package: "github.com/faultline-go/faultline/testdata/simple-go-module"
    reason: "baseline fixture waiver"
    owner: "@test"
    expires: "2099-01-01"
`)), 0600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(tmp, "check.json")
	check := NewRootCommand()
	check.SetOut(new(bytes.Buffer))
	check.SetErr(new(bytes.Buffer))
	check.SetArgs([]string{"baseline", "check", "--baseline", baselinePath, "--config", configPath, "--format", "json", "--out", out, "--fail-on-new", "high"})
	if err := check.Execute(); err != nil {
		t.Fatalf("suppressed baseline check should pass: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		SuppressedFindings []struct {
			ID         string `json:"id"`
			Suppressed bool   `json:"suppressed"`
		} `json:"suppressed_findings"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if len(result.SuppressedFindings) == 0 || result.SuppressedFindings[0].ID != "FL-BND-001" {
		t.Fatalf("expected suppressed boundary in metadata: %+v", result.SuppressedFindings)
	}
}

func boundaryConfig(extra string) string {
	return `version: 1
boundaries:
  - name: main-must-not-import-store
    from: "github.com/faultline-go/faultline/testdata/simple-go-module"
    deny:
      - "*/internal/store"
` + extra
}
