package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWriteHTMLFileSmokeAndEscaping(t *testing.T) {
	out := filepath.Join(t.TempDir(), "faultline-report.html")
	rep := &Report{
		Meta: ScanMeta{
			Version:  "test",
			ScanTime: time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC),
			RepoPath: "/repo",
		},
		ScoringVersion: "test-scoring",
		Packages: []PackageRisk{
			{
				ImportPath: "<example.com/acme/orders>",
				Dir:        "/repo/orders",
				RiskScore:  72.5,
				Findings: []Finding{
					{
						ID:             "FL-COV-001",
						Category:       CategoryCoverage,
						Severity:       SeverityHigh,
						Title:          "Low coverage <unsafe>",
						Description:    "Package coverage is below threshold.",
						Recommendation: "Add tests.",
						Evidence:       []Evidence{{Key: "coverage_pct", Value: "12.3", Source: "coverage"}},
						Confidence:     0.8,
					},
				},
				Evidence: []Evidence{{Key: "risk_score", Value: "72.50", Source: "scoring"}},
			},
		},
		Summary: Summary{TotalPackages: 1, HighRiskCount: 1},
	}

	if err := WriteHTMLFile(out, rep); err != nil {
		t.Fatalf("WriteHTMLFile: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read html: %v", err)
	}
	html := string(data)
	for _, want := range []string{
		"Faultline Report",
		"Top 10 Risky Packages",
		"Package Risk Table",
		"Findings By Severity And Category",
		"Evidence Appendix",
		"&lt;example.com/acme/orders&gt;",
		"Low coverage &lt;unsafe&gt;",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("HTML missing %q\n%s", want, html)
		}
	}
	if strings.Contains(html, "<example.com/acme/orders>") || strings.Contains(html, "Low coverage <unsafe>") {
		t.Fatalf("HTML contained unescaped package or finding text:\n%s", html)
	}
}
