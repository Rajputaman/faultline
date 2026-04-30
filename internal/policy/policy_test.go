package policy

import (
	"testing"
	"time"

	"github.com/faultline-go/faultline/internal/report"
)

func TestEvaluateBoundaries(t *testing.T) {
	pkgs := []PackageFacts{
		{
			ImportPath:            "github.com/example/app/internal/handlers/http",
			Dir:                   "internal/handlers/http",
			DirectInternalImports: []string{"github.com/example/app/internal/storage/sql"},
		},
		{
			ImportPath: "github.com/example/app/internal/storage/sql",
			Dir:        "internal/storage/sql",
		},
	}

	tests := []struct {
		name         string
		rule         BoundaryRule
		wantFindings int
		wantWarnings int
	}{
		{
			name: "boundary violation emitted",
			rule: BoundaryRule{
				Name: "handlers-must-not-import-storage",
				From: "*/internal/handlers/*",
				Deny: []string{"*/internal/storage/*"},
			},
			wantFindings: 1,
		},
		{
			name: "exception prevents violation",
			rule: BoundaryRule{
				Name:   "handlers-must-not-import-storage",
				From:   "*/internal/handlers/*",
				Deny:   []string{"*/internal/storage/*"},
				Except: []string{"*/internal/storage/sql"},
			},
		},
		{
			name: "unrelated imports ignored",
			rule: BoundaryRule{
				Name: "handlers-must-not-import-cache",
				From: "*/internal/handlers/*",
				Deny: []string{"*/internal/cache/*"},
			},
		},
		{
			name: "malformed rule warning",
			rule: BoundaryRule{
				Name: "missing-deny",
				From: "*/internal/handlers/*",
			},
			wantWarnings: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, warnings := EvaluateBoundaries(Config{Boundaries: []BoundaryRule{tt.rule}}, pkgs)
			count := 0
			for _, pkgFindings := range findings {
				count += len(pkgFindings)
			}
			if count != tt.wantFindings {
				t.Fatalf("findings = %d, want %d: %+v", count, tt.wantFindings, findings)
			}
			if len(warnings) != tt.wantWarnings {
				t.Fatalf("warnings = %d, want %d: %+v", len(warnings), tt.wantWarnings, warnings)
			}
			if tt.wantFindings > 0 {
				got := findings["github.com/example/app/internal/handlers/http"][0]
				if got.ID != "FL-BND-001" || got.Category != report.CategoryBoundary || got.Severity != report.SeverityHigh {
					t.Fatalf("unexpected finding: %+v", got)
				}
				if !hasEvidence(got.Evidence, "matched_import", "github.com/example/app/internal/storage/sql") {
					t.Fatalf("missing matched_import evidence: %+v", got.Evidence)
				}
			}
		})
	}
}

func TestApplySuppressions(t *testing.T) {
	now := time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)
	pkgs := []report.PackageRisk{
		{
			ImportPath: "github.com/example/app/internal/handlers/http",
			Dir:        "internal/handlers/http",
			Findings: []report.Finding{
				{ID: "FL-BND-001", Category: report.CategoryBoundary, Severity: report.SeverityHigh},
			},
		},
	}

	tests := []struct {
		name           string
		suppression    Suppression
		maxDays        int
		wantSuppressed bool
		wantWarnings   int
	}{
		{
			name: "active suppression applied",
			suppression: Suppression{
				ID:       "FL-BND-001",
				Package:  "*/internal/handlers/*",
				Category: "BOUNDARY",
				Reason:   "temporary migration",
				Owner:    "@platform",
				Expires:  "2099-09-30",
			},
			wantSuppressed: true,
		},
		{
			name: "expired suppression ignored",
			suppression: Suppression{
				ID:      "FL-BND-001",
				Package: "*/internal/handlers/*",
				Reason:  "temporary migration",
				Owner:   "@platform",
				Expires: "2026-01-01",
			},
			wantWarnings: 1,
		},
		{
			name: "missing owner and expiry warns",
			suppression: Suppression{
				ID:      "FL-BND-001",
				Package: "*/internal/handlers/*",
				Reason:  "temporary migration",
			},
			wantWarnings: 2,
		},
		{
			name: "max duration violation still applies in non-strict policy",
			suppression: Suppression{
				ID:      "FL-BND-001",
				Package: "*/internal/handlers/*",
				Reason:  "temporary migration",
				Owner:   "@platform",
				Created: "2026-04-01",
				Expires: "2026-09-30",
			},
			wantSuppressed: true,
			maxDays:        90,
			wantWarnings:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.SuppressionPolicy.MaxDays = tt.maxDays
			cfg.Suppressions = []Suppression{tt.suppression}
			got, audit, warnings := ApplySuppressions(cfg, pkgs, now)
			if got[0].Findings[0].Suppressed != tt.wantSuppressed {
				t.Fatalf("Suppressed = %v, want %v", got[0].Findings[0].Suppressed, tt.wantSuppressed)
			}
			if tt.wantSuppressed {
				if got[0].Findings[0].Suppression == nil {
					t.Fatal("expected suppression metadata on finding")
				}
				if len(audit) != 1 {
					t.Fatalf("audit entries = %d, want 1", len(audit))
				}
			}
			if len(warnings) != tt.wantWarnings {
				t.Fatalf("warnings = %d, want %d: %+v", len(warnings), tt.wantWarnings, warnings)
			}
		})
	}
}

func hasEvidence(evidence []report.Evidence, key, value string) bool {
	for _, item := range evidence {
		if item.Key == key && item.Value == value {
			return true
		}
	}
	return false
}
