package sarif

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/faultline-go/faultline/internal/report"
)

func TestBuildBasicDocumentAndRules(t *testing.T) {
	rep := testReport(t)
	doc := Build(rep)

	if doc.Version != "2.1.0" {
		t.Fatalf("Version = %q, want 2.1.0", doc.Version)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(doc.Runs))
	}
	driver := doc.Runs[0].Tool.Driver
	if driver.Name != "Faultline" {
		t.Fatalf("tool name = %q, want Faultline", driver.Name)
	}
	if driver.Version != "1.2.3" {
		t.Fatalf("tool version = %q, want 1.2.3", driver.Version)
	}

	wantIDs := []string{
		"FL-BND-001",
		"FL-CHURN-001",
		"FL-COV-001",
		"FL-COV-002",
		"FL-DEP-001",
		"FL-DEP-002",
		"FL-DEP-003",
		"FL-DEP-004",
		"FL-DEP-005",
		"FL-DEP-006",
		"FL-DEP-007",
		"FL-GEN-001",
		"FL-OWN-001",
		"FL-OWN-002",
		"FL-OWN-003",
		"FL-OWN-004",
	}
	if len(driver.Rules) != len(wantIDs) {
		t.Fatalf("rules = %d, want %d", len(driver.Rules), len(wantIDs))
	}
	for i, want := range wantIDs {
		if driver.Rules[i].ID != want {
			t.Fatalf("rule[%d] = %q, want %q", i, driver.Rules[i].ID, want)
		}
		if driver.Rules[i].ShortDescription.Text == "" || driver.Rules[i].FullDescription.Text == "" || driver.Rules[i].Help.Text == "" {
			t.Fatalf("rule %s missing descriptions/help: %+v", want, driver.Rules[i])
		}
	}
}

func TestSuppressedFindingsAreOmitted(t *testing.T) {
	rep := testReport(t)
	doc := Build(rep)

	for _, result := range doc.Runs[0].Results {
		if result.RuleID == "FL-OWN-001" {
			t.Fatalf("suppressed finding appeared in SARIF results: %+v", result)
		}
	}
}

func TestLevel(t *testing.T) {
	tests := []struct {
		severity report.Severity
		want     string
	}{
		{report.SeverityCritical, "error"},
		{report.SeverityHigh, "error"},
		{report.SeverityMedium, "warning"},
		{report.SeverityLow, "note"},
		{report.SeverityInfo, "note"},
		{report.Severity("UNKNOWN"), "note"},
	}
	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			if got := Level(tt.severity); got != tt.want {
				t.Fatalf("Level(%q) = %q, want %q", tt.severity, got, tt.want)
			}
		})
	}
}

func TestBoundaryFindingIncludesImportLocation(t *testing.T) {
	rep := testReport(t)
	doc := Build(rep)

	var boundary *Result
	for i := range doc.Runs[0].Results {
		if doc.Runs[0].Results[i].RuleID == "FL-BND-001" {
			boundary = &doc.Runs[0].Results[i]
			break
		}
	}
	if boundary == nil {
		t.Fatal("missing boundary result")
	}
	if len(boundary.Locations) != 1 {
		t.Fatalf("locations = %d, want 1", len(boundary.Locations))
	}
	got := boundary.Locations[0].PhysicalLocation.ArtifactLocation.URI
	if got != "internal/handlers/handler.go" {
		t.Fatalf("location URI = %q, want internal/handlers/handler.go", got)
	}
	region := boundary.Locations[0].PhysicalLocation.Region
	if region == nil || region.StartLine != 3 {
		t.Fatalf("region = %+v, want startLine 3", region)
	}
}

func TestDependencyFindingIncludesGoModLocation(t *testing.T) {
	rep := testReport(t)
	doc := Build(rep)
	var dep *Result
	for i := range doc.Runs[0].Results {
		if doc.Runs[0].Results[i].RuleID == "FL-DEP-002" {
			dep = &doc.Runs[0].Results[i]
			break
		}
	}
	if dep == nil {
		t.Fatal("missing dependency result")
	}
	if dep.Properties.ModulePath != "github.com/example/local" {
		t.Fatalf("module path property = %q", dep.Properties.ModulePath)
	}
	if len(dep.Locations) != 1 {
		t.Fatalf("locations = %d, want 1", len(dep.Locations))
	}
	if got := dep.Locations[0].PhysicalLocation.ArtifactLocation.URI; got != "go.mod" {
		t.Fatalf("location URI = %q, want go.mod", got)
	}
	if dep.Locations[0].PhysicalLocation.Region == nil || dep.Locations[0].PhysicalLocation.Region.StartLine != 7 {
		t.Fatalf("unexpected region: %+v", dep.Locations[0].PhysicalLocation.Region)
	}
}

func TestConvertDeterministic(t *testing.T) {
	rep := testReport(t)
	first, err := Convert(rep)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Convert(rep)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("SARIF output changed across repeated conversions")
	}
	var doc Document
	if err := json.Unmarshal(first, &doc); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
}

func TestBuildWithOptionsIncludesRunProperties(t *testing.T) {
	rep := testReport(t)
	doc := BuildWithOptions(rep, Options{Properties: map[string]string{
		"faultline.pr.base_ref":              "main",
		"faultline.pr.head_ref":              "feature/foo",
		"faultline.pr.changed_package_count": "1",
	}})
	props := doc.Runs[0].Properties
	if props["faultline.pr.base_ref"] != "main" ||
		props["faultline.pr.head_ref"] != "feature/foo" ||
		props["faultline.pr.changed_package_count"] != "1" {
		t.Fatalf("unexpected run properties: %+v", props)
	}
}

func testReport(t *testing.T) *report.Report {
	t.Helper()
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "internal", "handlers", "handler.go"), `package handlers

import "github.com/example/project/internal/storage"

func Handle() {}
`)
	mustWrite(t, filepath.Join(root, "internal", "storage", "store.go"), `package storage

func Store() {}
`)

	return &report.Report{
		Meta: report.ScanMeta{
			Version:  "1.2.3",
			ScanTime: time.Date(2026, 4, 30, 0, 0, 0, 0, time.UTC),
			RepoPath: root,
		},
		Packages: []report.PackageRisk{
			{
				ImportPath: "github.com/example/project/internal/handlers",
				Dir:        "internal/handlers",
				Findings: []report.Finding{
					{
						ID:          "FL-BND-001",
						Category:    report.CategoryBoundary,
						Severity:    report.SeverityHigh,
						Title:       "Architecture boundary violation",
						Description: "Package imports a denied dependency.",
						Evidence: []report.Evidence{
							{Key: "matched_import", Value: "github.com/example/project/internal/storage", Source: "import_graph"},
							{Key: "boundary_rule", Value: "handlers-must-not-import-storage", Source: "policy"},
						},
					},
					{
						ID:          "FL-OWN-001",
						Category:    report.CategoryOwnership,
						Severity:    report.SeverityLow,
						Title:       "No owner found",
						Description: "No CODEOWNERS rule resolved an owner.",
						Suppressed:  true,
					},
				},
			},
			{
				ImportPath: "github.com/example/project/internal/storage",
				Dir:        "internal/storage",
				Findings: []report.Finding{
					{
						ID:          "FL-COV-002",
						Category:    report.CategoryCoverage,
						Severity:    report.SeverityLow,
						Title:       "Coverage data is missing",
						Description: "Coverage was not supplied.",
						Evidence:    []report.Evidence{{Key: "coverage", Value: "unknown", Source: "cli"}},
					},
				},
			},
		},
		Dependencies: []report.DependencyRisk{
			{ModulePath: "github.com/example/local", Version: "v1.0.0", LocalReplace: true},
		},
		DependencyFindings: []report.Finding{
			{
				ID:          "FL-DEP-002",
				Category:    report.CategoryDependency,
				Severity:    report.SeverityHigh,
				Title:       "Local replace directive present",
				Description: "Module github.com/example/local is replaced with local path ./local.",
				Evidence: []report.Evidence{
					{Key: "module_path", Value: "github.com/example/local", Source: "go.mod"},
					{Key: "go_mod_line", Value: "7", Source: "go.mod"},
				},
			},
		},
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}
