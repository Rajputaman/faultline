package report

import (
	"encoding/json"
	"testing"
)

func TestComputeSummary(t *testing.T) {
	pkgs := []PackageRisk{
		{
			RiskScore:          80,
			FileCount:          4,
			GeneratedFileCount: 1,
			Findings: []Finding{
				{Severity: SeverityHigh},
				{Severity: SeverityLow},
				{Severity: SeverityHigh, Suppressed: true},
			},
		},
		{
			RiskScore:          20,
			FileCount:          6,
			GeneratedFileCount: 2,
			Findings: []Finding{
				{Severity: SeverityCritical},
			},
		},
	}
	warnings := []Warning{{Message: "missing coverage", Source: "coverage"}}

	got := ComputeSummaryWithDependencies(pkgs, warnings, []Finding{{Severity: SeverityMedium}})
	if got.TotalPackages != 2 {
		t.Fatalf("TotalPackages = %d, want 2", got.TotalPackages)
	}
	if got.HighRiskCount != 1 {
		t.Fatalf("HighRiskCount = %d, want 1", got.HighRiskCount)
	}
	if got.WarningCount != 1 {
		t.Fatalf("WarningCount = %d, want 1", got.WarningCount)
	}
	if got.TotalFindings != 5 || got.HighCount != 1 || got.CriticalCount != 1 || got.MediumCount != 1 || got.LowCount != 1 || got.SuppressedCount != 1 || got.DependencyFindingCount != 1 {
		t.Fatalf("unexpected finding counts: %+v", got)
	}
	if got.GeneratedFilePct != 30 {
		t.Fatalf("GeneratedFilePct = %.1f, want 30.0", got.GeneratedFilePct)
	}
}

func TestHasFindingAtOrAbove(t *testing.T) {
	pkgs := []PackageRisk{{Findings: []Finding{{Severity: SeverityHigh}}}}
	if !HasFindingAtOrAbove(pkgs, SeverityHigh) {
		t.Fatal("expected high threshold to match")
	}
	if HasFindingAtOrAbove(pkgs, SeverityCritical) {
		t.Fatal("did not expect critical threshold to match")
	}
	if !HasFindingAtOrAbove(nil, SeverityMedium, []Finding{{Severity: SeverityMedium}}) {
		t.Fatal("expected dependency finding threshold to match")
	}
}

func TestMarshalJSONIncludesDependencyInventory(t *testing.T) {
	rep := &Report{
		Dependencies: []DependencyRisk{{
			ModulePath: "github.com/example/lib",
			Version:    "v1.2.3",
			Used:       true,
		}},
		DependencyFindings: []Finding{{
			ID:       "FL-DEP-006",
			Category: CategoryDependency,
			Severity: SeverityLow,
			Title:    "Dependency uses pseudo-version",
		}},
	}
	data, err := MarshalJSON(rep)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Dependencies []DependencyRisk `json:"dependencies"`
		Findings     []Finding        `json:"dependency_findings"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Dependencies) != 1 || decoded.Dependencies[0].ModulePath != "github.com/example/lib" || len(decoded.Findings) != 1 {
		t.Fatalf("dependency inventory missing from JSON: %s", string(data))
	}
}
