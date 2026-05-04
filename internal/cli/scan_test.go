package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestScanCommandAgainstTestdata(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	testRepo := filepath.Join(repoRoot, "testdata", "simple-go-module")
	out := filepath.Join(t.TempDir(), "report.json")

	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(testRepo); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldwd); err != nil {
			t.Fatalf("restore wd: %v", err)
		}
	})

	cmd := NewRootCommand()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"scan", "./...", "--format", "json", "--out", out, "--no-history"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Warnings []struct {
			Message string `json:"message"`
			Source  string `json:"source"`
		} `json:"warnings"`
		Packages []struct {
			ImportPath            string   `json:"import_path"`
			DirectInternalImports []string `json:"direct_internal_imports"`
		} `json:"packages"`
		ScoringVersion string `json:"scoring_version"`
	}
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if len(rep.Packages) == 0 {
		t.Fatal("expected packages in report")
	}
	if rep.ScoringVersion == "" {
		t.Fatal("expected scoring version")
	}
	if len(rep.Warnings) == 0 {
		t.Fatal("expected missing coverage warning")
	}
}

func TestScanCommandWritesSnapshot(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	testRepo := filepath.Join(repoRoot, "testdata", "simple-go-module")
	out := filepath.Join(t.TempDir(), "snapshot.json")

	restore := chdir(t, testRepo)
	defer restore()

	cmd := NewRootCommand()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"scan", "./...", "--format", "snapshot", "--out", out, "--no-history"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot struct {
		SchemaVersion string `json:"schema_version"`
		Source        struct {
			RepoFingerprint string `json:"repo_fingerprint"`
		} `json:"source"`
		Packages []struct {
			ImportPath string `json:"import_path"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}
	if snapshot.SchemaVersion != "faultline.snapshot.v1" {
		t.Fatalf("schema version = %q", snapshot.SchemaVersion)
	}
	if snapshot.Source.RepoFingerprint == "" {
		t.Fatal("expected repo fingerprint")
	}
	if len(snapshot.Packages) == 0 {
		t.Fatal("expected packages in snapshot")
	}
}

func TestScanCommandWarnsWhenNoGoPackagesMatch(t *testing.T) {
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "package.json"), []byte(`{"name":"web"}`), 0600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "report.json")
	restore := chdir(t, repo)
	defer restore()

	cmd := NewRootCommand()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"scan", "./...", "--format", "json", "--out", out, "--no-history"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "no Go packages matched") {
		t.Fatalf("expected no Go packages warning in report: %s", string(data))
	}
}

func TestScanCommandWritesSARIF(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	testRepo := filepath.Join(repoRoot, "testdata", "simple-go-module")
	out := filepath.Join(t.TempDir(), "report.sarif")

	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(testRepo); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldwd); err != nil {
			t.Fatalf("restore wd: %v", err)
		}
	})

	cmd := NewRootCommand()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"scan", "./...", "--format", "sarif", "--out", out, "--no-history"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name string `json:"name"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal SARIF: %v", err)
	}
	if doc.Version != "2.1.0" || len(doc.Runs) != 1 || doc.Runs[0].Tool.Driver.Name != "Faultline" {
		t.Fatalf("unexpected SARIF shape: %+v", doc)
	}
}

func TestScanReportIncludesDependencyInventory(t *testing.T) {
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "go.mod"), []byte(`module example.com/app

go 1.26

require example.com/unused v1.0.0
`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "main.go"), []byte(`package app

func Hello() string { return "hello" }
`), 0600); err != nil {
		t.Fatal(err)
	}
	restore := chdir(t, repo)
	defer restore()
	out := filepath.Join(t.TempDir(), "report.json")
	cmd := NewRootCommand()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"scan", "./...", "--format", "json", "--out", out, "--no-history"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Dependencies []struct {
			ModulePath string `json:"module_path"`
		} `json:"dependencies"`
		DependencyFindings []struct {
			ID string `json:"id"`
		} `json:"dependency_findings"`
	}
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Dependencies) != 1 || rep.Dependencies[0].ModulePath != "example.com/unused" {
		t.Fatalf("dependency inventory missing: %s", string(data))
	}
	if len(rep.DependencyFindings) != 1 || rep.DependencyFindings[0].ID != "FL-DEP-004" {
		t.Fatalf("dependency finding missing: %+v\n%s", rep.DependencyFindings, string(data))
	}
}

func TestScanIncludesCodeownersMatchEvidence(t *testing.T) {
	repo := t.TempDir()
	mustWriteFile(t, filepath.Join(repo, "go.mod"), `module example.com/app

go 1.26
`)
	mustWriteFile(t, filepath.Join(repo, "CODEOWNERS"), `/pkg/ @pkg-team @security
`)
	if err := os.MkdirAll(filepath.Join(repo, "pkg"), 0755); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, filepath.Join(repo, "pkg", "pkg.go"), `package pkg

func Name() string { return "pkg" }
`)
	restore := chdir(t, repo)
	defer restore()
	out := filepath.Join(t.TempDir(), "report.json")
	cmd := NewRootCommand()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"scan", "./...", "--format", "json", "--out", out, "--no-history"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Packages []struct {
			ImportPath    string  `json:"import_path"`
			DominantOwner *string `json:"dominant_owner"`
			Evidence      []struct {
				Key   string `json:"key"`
				Value string `json:"value"`
			} `json:"evidence"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, pkg := range rep.Packages {
		if pkg.ImportPath != "example.com/app/pkg" {
			continue
		}
		found = true
		if pkg.DominantOwner == nil || *pkg.DominantOwner != "@pkg-team" {
			t.Fatalf("dominant owner = %v, want @pkg-team", pkg.DominantOwner)
		}
		if !hasEvidence(pkg.Evidence, "codeowners_matched_file", "CODEOWNERS") ||
			!hasEvidence(pkg.Evidence, "codeowners_matched_line", "1") ||
			!hasEvidence(pkg.Evidence, "codeowners_matched_pattern", "/pkg/") ||
			!hasEvidence(pkg.Evidence, "codeowners_matched_owners", "@pkg-team,@security") {
			t.Fatalf("missing CODEOWNERS match evidence: %+v", pkg.Evidence)
		}
	}
	if !found {
		t.Fatalf("package example.com/app/pkg not found: %+v", rep.Packages)
	}
}

func TestScanStrictConfigFailsOnCodeownersDiagnostics(t *testing.T) {
	repo := t.TempDir()
	mustWriteFile(t, filepath.Join(repo, "go.mod"), `module example.com/app

go 1.26
`)
	mustWriteFile(t, filepath.Join(repo, "CODEOWNERS"), `/pkg/ team
`)
	if err := os.MkdirAll(filepath.Join(repo, "pkg"), 0755); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, filepath.Join(repo, "pkg", "pkg.go"), `package pkg

func Name() string { return "pkg" }
`)
	restore := chdir(t, repo)
	defer restore()
	cmd := NewRootCommand()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"scan", "./...", "--strict-config", "--format", "json", "--out", filepath.Join(t.TempDir(), "report.json"), "--no-history"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected strict config failure")
	}
	var exitErr ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != 2 {
		t.Fatalf("error = %v, want exit code 2", err)
	}
}

func TestBoundaryFindingIncludesFileOwnerEvidence(t *testing.T) {
	repo := t.TempDir()
	mustWriteFile(t, filepath.Join(repo, "go.mod"), `module example.com/app

go 1.26
`)
	mustWriteFile(t, filepath.Join(repo, "CODEOWNERS"), `/internal/handlers/ @handlers-team
`)
	mustWriteFile(t, filepath.Join(repo, "internal", "storage", "storage.go"), `package storage

func Save() {}
`)
	mustWriteFile(t, filepath.Join(repo, "internal", "handlers", "handler.go"), `package handlers

import "example.com/app/internal/storage"

func Handle() { storage.Save() }
`)
	configPath := filepath.Join(t.TempDir(), "faultline.yaml")
	mustWriteFile(t, configPath, `version: 1
boundaries:
  - name: handlers-must-not-import-storage
    from: "*/internal/handlers"
    deny:
      - "*/internal/storage"
`)
	restore := chdir(t, repo)
	defer restore()
	out := filepath.Join(t.TempDir(), "report.json")
	cmd := NewRootCommand()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"scan", "./...", "--config", configPath, "--format", "json", "--out", out, "--no-history"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Packages []struct {
			ImportPath string `json:"import_path"`
			Findings   []struct {
				ID       string `json:"id"`
				Evidence []struct {
					Key   string `json:"key"`
					Value string `json:"value"`
				} `json:"evidence"`
			} `json:"findings"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatal(err)
	}
	for _, pkg := range rep.Packages {
		for _, finding := range pkg.Findings {
			if finding.ID != "FL-BND-001" {
				continue
			}
			if !hasEvidence(finding.Evidence, "importing_file", "internal/handlers/handler.go") ||
				!hasEvidence(finding.Evidence, "file_owner", "@handlers-team") ||
				!hasEvidence(finding.Evidence, "file_codeowners_line", "1") ||
				!hasEvidence(finding.Evidence, "file_codeowners_pattern", "/internal/handlers/") {
				t.Fatalf("missing boundary file owner evidence: %+v", finding.Evidence)
			}
			return
		}
	}
	t.Fatalf("missing boundary finding: %+v", rep.Packages)
}

func TestScanMultiModuleRepoReportsModulesAndDependencies(t *testing.T) {
	repo := multiModuleRepo(t)
	restore := chdir(t, repo)
	defer restore()
	out := filepath.Join(t.TempDir(), "report.json")
	configPath := filepath.Join(t.TempDir(), "faultline.yaml")
	if err := os.WriteFile(configPath, []byte(`version: 1
owners:
  modules:
    "example.com/monorepo/service-a":
      owner: "@service-a-team"
    "example.com/monorepo/service-b":
      owner: "@service-b-team"
    "example.com/monorepo/shared":
      owner: "@platform-team"
boundaries:
  - name: handlers-must-not-import-storage
    from: "*/service-a/internal/handlers"
    deny:
      - "*/service-a/internal/storage"
`), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := NewRootCommand()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"scan", "./...", "--config", configPath, "--format", "json", "--out", out, "--no-history"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("scan multi-module: %v", err)
	}
	rep := readScanJSON(t, out)
	if len(rep.Modules) != 3 {
		t.Fatalf("modules = %d, want 3: %+v", len(rep.Modules), rep.Modules)
	}
	if !hasDependencyFinding(rep.DependencyFindings, "FL-DEP-007") {
		t.Fatalf("missing cross-module dependency finding: %+v", rep.DependencyFindings)
	}
	if !hasPackageFinding(rep.Packages, "FL-BND-001") {
		t.Fatalf("missing boundary finding in multi-module report: %+v", rep.Packages)
	}
	for _, pkg := range rep.Packages {
		if pkg.ModulePath == "" || pkg.ModuleRoot == "" {
			t.Fatalf("package missing module metadata: %+v", pkg)
		}
	}
	for _, pkg := range rep.Packages {
		if pkg.ModulePath == "example.com/monorepo/service-a" {
			if pkg.DominantOwner == nil || *pkg.DominantOwner != "@service-a-team" || pkg.OwnerSource != "module" {
				t.Fatalf("module owner not resolved for service-a package: %+v", pkg)
			}
			if len(pkg.CandidateOwners) == 0 {
				t.Fatalf("expected owner candidates for service-a package: %+v", pkg)
			}
		}
	}
}

func TestScanMultiModuleSelectionAndIgnore(t *testing.T) {
	repo := multiModuleRepo(t)
	restore := chdir(t, repo)
	defer restore()

	outOne := filepath.Join(t.TempDir(), "one.json")
	cmdOne := NewRootCommand()
	cmdOne.SetOut(new(bytes.Buffer))
	cmdOne.SetErr(new(bytes.Buffer))
	cmdOne.SetArgs([]string{"scan", "./...", "--module", "service-a", "--format", "json", "--out", outOne, "--no-history"})
	if err := cmdOne.Execute(); err != nil {
		t.Fatalf("scan selected module: %v", err)
	}
	one := readScanJSON(t, outOne)
	if selectedCount(one.Modules) != 1 || !allPackagesInModule(one.Packages, "example.com/monorepo/service-a") {
		t.Fatalf("expected only service-a selected/scanned: modules=%+v packages=%+v", one.Modules, one.Packages)
	}

	outIgnore := filepath.Join(t.TempDir(), "ignore.json")
	cmdIgnore := NewRootCommand()
	cmdIgnore.SetOut(new(bytes.Buffer))
	cmdIgnore.SetErr(new(bytes.Buffer))
	cmdIgnore.SetArgs([]string{"scan", "./...", "--ignore-module", "service-b", "--format", "json", "--out", outIgnore, "--no-history"})
	if err := cmdIgnore.Execute(); err != nil {
		t.Fatalf("scan ignored module: %v", err)
	}
	ignored := readScanJSON(t, outIgnore)
	for _, pkg := range ignored.Packages {
		if pkg.ModulePath == "example.com/monorepo/service-b" {
			t.Fatalf("service-b package should be ignored: %+v", ignored.Packages)
		}
	}
}

func TestSuppressedHighFindingDoesNotFailOnHigh(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	testRepo := filepath.Join(repoRoot, "testdata", "simple-go-module")
	tmp := t.TempDir()
	out := filepath.Join(tmp, "report.json")
	configPath := filepath.Join(tmp, "faultline.yaml")
	config := `version: 1
boundaries:
  - name: main-must-not-import-store
    from: "github.com/faultline-go/faultline/testdata/simple-go-module"
    deny:
      - "*/internal/store"
suppressions:
  - id: FL-BND-001
    category: BOUNDARY
    package: "github.com/faultline-go/faultline/testdata/simple-go-module"
    reason: "temporary fixture waiver"
    owner: "@test"
    expires: "2099-09-30"
`
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}

	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(testRepo); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldwd); err != nil {
			t.Fatalf("restore wd: %v", err)
		}
	})

	cmd := NewRootCommand()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"scan", "./...", "--format", "json", "--out", out, "--config", configPath, "--fail-on", "high", "--no-history"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error for suppressed high finding: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Summary struct {
			SuppressedCount int `json:"suppressed_count"`
			HighCount       int `json:"high_count"`
		} `json:"summary"`
		SuppressedFindings []struct {
			FindingID string `json:"finding_id"`
		} `json:"suppressed_findings"`
		Packages []struct {
			Findings []struct {
				ID         string `json:"id"`
				Suppressed bool   `json:"suppressed"`
			} `json:"findings"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if rep.Summary.SuppressedCount != 1 {
		t.Fatalf("SuppressedCount = %d, want 1", rep.Summary.SuppressedCount)
	}
	if len(rep.SuppressedFindings) != 1 || rep.SuppressedFindings[0].FindingID != "FL-BND-001" {
		t.Fatalf("unexpected suppression audit: %+v", rep.SuppressedFindings)
	}
	if !containsSuppressedBoundary(rep.Packages) {
		t.Fatalf("suppressed boundary finding not preserved in package findings: %+v", rep.Packages)
	}
}

func TestScanHistoryPersistsAndLists(t *testing.T) {
	testRepo := testdataRepo(t)
	historyDir := filepath.Join(testRepo, ".faultline")
	if err := os.RemoveAll(historyDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(historyDir)
	})
	restore := chdir(t, testRepo)
	defer restore()

	out1 := filepath.Join(t.TempDir(), "first.json")
	cmd1 := NewRootCommand()
	cmd1.SetOut(new(bytes.Buffer))
	cmd1.SetErr(new(bytes.Buffer))
	cmd1.SetArgs([]string{"scan", "./...", "--format", "json", "--out", out1})
	if err := cmd1.Execute(); err != nil {
		t.Fatalf("first scan: %v", err)
	}
	if _, err := os.Stat(filepath.Join(historyDir, "faultline.db")); err != nil {
		t.Fatalf("expected history db: %v", err)
	}

	out2 := filepath.Join(t.TempDir(), "second.json")
	cmd2 := NewRootCommand()
	cmd2.SetOut(new(bytes.Buffer))
	cmd2.SetErr(new(bytes.Buffer))
	cmd2.SetArgs([]string{"scan", "./...", "--format", "json", "--out", out2})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("second scan: %v", err)
	}
	data, err := os.ReadFile(out2)
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Meta struct {
			ScanID int64 `json:"scan_id"`
		} `json:"meta"`
		Packages []struct {
			PreviousRiskScore *float64 `json:"previous_risk_score"`
			RiskDelta         *float64 `json:"risk_delta"`
			Trend             string   `json:"trend"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Meta.ScanID == 0 {
		t.Fatal("expected scan id in second report")
	}
	if !hasPreviousTrend(rep.Packages) {
		t.Fatalf("expected at least one package with previous trend data: %+v", rep.Packages)
	}

	var listOut bytes.Buffer
	list := NewRootCommand()
	list.SetOut(&listOut)
	list.SetErr(new(bytes.Buffer))
	list.SetArgs([]string{"history", "list"})
	if err := list.Execute(); err != nil {
		t.Fatalf("history list: %v", err)
	}
	if !bytes.Contains(listOut.Bytes(), []byte("SCAN ID")) || !bytes.Contains(listOut.Bytes(), []byte(testRepo)) {
		t.Fatalf("unexpected history list output:\n%s", listOut.String())
	}

	var doctorOut bytes.Buffer
	doctor := NewRootCommand()
	doctor.SetOut(&doctorOut)
	doctor.SetErr(new(bytes.Buffer))
	doctor.SetArgs([]string{"history", "doctor"})
	if err := doctor.Execute(); err != nil {
		t.Fatalf("history doctor: %v", err)
	}
	if !bytes.Contains(doctorOut.Bytes(), []byte("Driver:")) || !bytes.Contains(doctorOut.Bytes(), []byte("Schema Version:")) {
		t.Fatalf("unexpected history doctor output:\n%s", doctorOut.String())
	}
}

func TestNoHistoryDisablesPersistence(t *testing.T) {
	testRepo := testdataRepo(t)
	historyDir := filepath.Join(testRepo, ".faultline")
	if err := os.RemoveAll(historyDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(historyDir)
	})
	restore := chdir(t, testRepo)
	defer restore()

	cmd := NewRootCommand()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"scan", "./...", "--format", "json", "--out", filepath.Join(t.TempDir(), "report.json"), "--no-history"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if _, err := os.Stat(filepath.Join(historyDir, "faultline.db")); !os.IsNotExist(err) {
		t.Fatalf("expected no history db, stat err=%v", err)
	}
}

func TestCorruptHistoryDBDegradesGracefully(t *testing.T) {
	testRepo := testdataRepo(t)
	historyDir := filepath.Join(testRepo, ".faultline")
	if err := os.RemoveAll(historyDir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(historyDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(historyDir, "faultline.db"), []byte("not sqlite"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(historyDir)
	})
	restore := chdir(t, testRepo)
	defer restore()

	out := filepath.Join(t.TempDir(), "report.json")
	cmd := NewRootCommand()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"scan", "./...", "--format", "json", "--out", out})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("scan should degrade on corrupt history db: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Warnings []struct {
			Source string `json:"source"`
		} `json:"warnings"`
	}
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatal(err)
	}
	if !hasHistoryWarningSource(rep.Warnings) {
		t.Fatalf("expected history warning: %+v", rep.Warnings)
	}
}

func TestParseFailOn(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"default", "", "", false},
		{"none", "none", "", false},
		{"high", "high", "HIGH", false},
		{"critical", "critical", "CRITICAL", false},
		{"bad", "medium", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseFailOn(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				var exitErr ExitError
				if errors.As(err, &exitErr) {
					t.Fatal("parseFailOn should not wrap ExitError")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func containsSuppressedBoundary(pkgs []struct {
	Findings []struct {
		ID         string `json:"id"`
		Suppressed bool   `json:"suppressed"`
	} `json:"findings"`
}) bool {
	for _, pkg := range pkgs {
		for _, finding := range pkg.Findings {
			if finding.ID == "FL-BND-001" && finding.Suppressed {
				return true
			}
		}
	}
	return false
}

func testdataRepo(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	return filepath.Join(repoRoot, "testdata", "simple-go-module")
}

func multiModuleRepo(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	return filepath.Join(repoRoot, "testdata", "multi-module-repo")
}

type scanJSON struct {
	Modules []struct {
		ModulePath       string `json:"module_path"`
		ModuleRoot       string `json:"module_root"`
		IncludedByGoWork bool   `json:"included_by_go_work"`
		Selected         bool   `json:"selected"`
	} `json:"modules"`
	DependencyFindings []struct {
		ID string `json:"id"`
	} `json:"dependency_findings"`
	Packages []struct {
		ImportPath      string  `json:"import_path"`
		ModulePath      string  `json:"module_path"`
		ModuleRoot      string  `json:"module_root"`
		DominantOwner   *string `json:"dominant_owner"`
		OwnerSource     string  `json:"owner_source"`
		CandidateOwners []struct {
			Owner  string `json:"owner"`
			Source string `json:"source"`
		} `json:"candidate_owners"`
		Findings []struct {
			ID string `json:"id"`
		} `json:"findings"`
	} `json:"packages"`
}

func readScanJSON(t *testing.T, path string) scanJSON {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rep scanJSON
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatal(err)
	}
	return rep
}

func hasDependencyFinding(findings []struct {
	ID string `json:"id"`
}, id string) bool {
	for _, finding := range findings {
		if finding.ID == id {
			return true
		}
	}
	return false
}

func hasPackageFinding(pkgs []struct {
	ImportPath      string  `json:"import_path"`
	ModulePath      string  `json:"module_path"`
	ModuleRoot      string  `json:"module_root"`
	DominantOwner   *string `json:"dominant_owner"`
	OwnerSource     string  `json:"owner_source"`
	CandidateOwners []struct {
		Owner  string `json:"owner"`
		Source string `json:"source"`
	} `json:"candidate_owners"`
	Findings []struct {
		ID string `json:"id"`
	} `json:"findings"`
}, id string) bool {
	for _, pkg := range pkgs {
		for _, finding := range pkg.Findings {
			if finding.ID == id {
				return true
			}
		}
	}
	return false
}

func selectedCount(modules []struct {
	ModulePath       string `json:"module_path"`
	ModuleRoot       string `json:"module_root"`
	IncludedByGoWork bool   `json:"included_by_go_work"`
	Selected         bool   `json:"selected"`
}) int {
	count := 0
	for _, module := range modules {
		if module.Selected {
			count++
		}
	}
	return count
}

func allPackagesInModule(pkgs []struct {
	ImportPath      string  `json:"import_path"`
	ModulePath      string  `json:"module_path"`
	ModuleRoot      string  `json:"module_root"`
	DominantOwner   *string `json:"dominant_owner"`
	OwnerSource     string  `json:"owner_source"`
	CandidateOwners []struct {
		Owner  string `json:"owner"`
		Source string `json:"source"`
	} `json:"candidate_owners"`
	Findings []struct {
		ID string `json:"id"`
	} `json:"findings"`
}, modulePath string) bool {
	if len(pkgs) == 0 {
		return false
	}
	for _, pkg := range pkgs {
		if pkg.ModulePath != modulePath {
			return false
		}
	}
	return true
}

func chdir(t *testing.T, dir string) func() {
	t.Helper()
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	return func() {
		if err := os.Chdir(oldwd); err != nil {
			t.Fatalf("restore wd: %v", err)
		}
	}
}

func hasPreviousTrend(pkgs []struct {
	PreviousRiskScore *float64 `json:"previous_risk_score"`
	RiskDelta         *float64 `json:"risk_delta"`
	Trend             string   `json:"trend"`
}) bool {
	for _, pkg := range pkgs {
		if pkg.PreviousRiskScore != nil && pkg.RiskDelta != nil && pkg.Trend != "" && pkg.Trend != "NEW" {
			return true
		}
	}
	return false
}

func hasHistoryWarningSource(warnings []struct {
	Source string `json:"source"`
}) bool {
	for _, warning := range warnings {
		if warning.Source == "history" {
			return true
		}
	}
	return false
}

func hasEvidence(evidence []struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}, key, value string) bool {
	for _, item := range evidence {
		if item.Key == key && item.Value == value {
			return true
		}
	}
	return false
}

func mustWriteFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}
