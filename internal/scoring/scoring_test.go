package scoring

import (
	"testing"

	"github.com/faultline-go/faultline/internal/policy"
	"github.com/faultline-go/faultline/internal/report"
)

func TestScorePackage(t *testing.T) {
	lowCoverage := 20.0
	tests := []struct {
		name        string
		pkg         report.PackageRisk
		opts        Options
		wantFinding []string
	}{
		{
			name: "high churn low coverage",
			pkg: report.PackageRisk{
				Churn30d:       800,
				CoveragePct:    &lowCoverage,
				LOC:            500,
				ImportCount:    10,
				AuthorCount90d: 2,
			},
			opts:        Options{CoverageSupplied: true, CoverageUsable: true, GitAvailable: true},
			wantFinding: []string{"FL-CHURN-001", "FL-COV-001"},
		},
		{
			name:        "no coverage",
			pkg:         report.PackageRisk{LOC: 10},
			opts:        Options{GitAvailable: true},
			wantFinding: []string{"FL-COV-002"},
		},
		{
			name:        "no git still scores",
			pkg:         report.PackageRisk{LOC: 10},
			opts:        Options{CoverageSupplied: true, CoverageUsable: true},
			wantFinding: []string{"FL-COV-002"},
		},
		{
			name: "high centrality",
			pkg: report.PackageRisk{
				ReverseImportCount: 8,
			},
			opts:        Options{CoverageSupplied: true, CoverageUsable: true},
			wantFinding: []string{"FL-DEP-001", "FL-COV-002"},
		},
		{
			name: "generated heavy",
			pkg: report.PackageRisk{
				FileCount:          4,
				GeneratedFileCount: 2,
			},
			opts:        Options{CoverageSupplied: true, CoverageUsable: true},
			wantFinding: []string{"FL-GEN-001", "FL-COV-002"},
		},
		{
			name: "ownerless high churn package",
			pkg: report.PackageRisk{
				Churn30d:       900,
				AuthorCount90d: 9,
			},
			opts:        Options{CoverageSupplied: true, CoverageUsable: true},
			wantFinding: []string{"FL-CHURN-001", "FL-OWN-001", "FL-OWN-002", "FL-COV-002"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := policy.DefaultConfig()
			cfg.Ownership.RequireCodeowners = true
			tt.opts.Config = cfg
			got := ScorePackage(tt.pkg, tt.opts)
			if got.RiskScore < 0 || got.RiskScore > 100 {
				t.Fatalf("RiskScore = %.2f, want [0,100]", got.RiskScore)
			}
			if got.Breakdown.ChurnScore < 0 || got.Breakdown.ChurnScore > 100 {
				t.Fatalf("ChurnScore = %.2f, want [0,100]", got.Breakdown.ChurnScore)
			}
			if len(got.Evidence) == 0 {
				t.Fatal("expected score evidence")
			}
			for _, id := range tt.wantFinding {
				if !hasFinding(got.Findings, id) {
					t.Fatalf("expected finding %s in %+v", id, got.Findings)
				}
			}
			if got.RiskScore >= 70 && len(got.Evidence) < 3 {
				t.Fatalf("high-risk package has %d evidence items, want at least 3", len(got.Evidence))
			}
		})
	}
}

func hasFinding(findings []report.Finding, id string) bool {
	for _, f := range findings {
		if f.ID == id {
			return true
		}
	}
	return false
}
