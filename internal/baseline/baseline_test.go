package baseline

import (
	"bytes"
	"testing"
	"time"

	"github.com/faultline-go/faultline/internal/report"
)

func TestCreateBaselineFormatAndDeterminism(t *testing.T) {
	rep := sampleReport([]report.Finding{
		{ID: "FL-COV-001", Category: report.CategoryCoverage, Severity: report.SeverityMedium, Title: "Low coverage", Evidence: []report.Evidence{{Key: "coverage_pct", Value: "42.00", Source: "coverage"}}},
	})
	first := Create(rep)
	second := Create(rep)
	if first.SchemaVersion != SchemaVersion {
		t.Fatalf("schema version = %d, want %d", first.SchemaVersion, SchemaVersion)
	}
	if first.RepoFingerprint != "repo-abc" || first.ConfigHash != "cfg-123" {
		t.Fatalf("missing metadata: %+v", first)
	}
	if len(first.PackageRisks) != 1 || len(first.FindingIdentities) != 1 {
		t.Fatalf("unexpected baseline contents: %+v", first)
	}
	firstJSON, err := MarshalBaseline(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := MarshalBaseline(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatalf("baseline output is not deterministic\nfirst=%s\nsecond=%s", firstJSON, secondJSON)
	}
}

func TestCompareDetectsNewAndResolvedFindings(t *testing.T) {
	base := Create(sampleReport([]report.Finding{
		{ID: "FL-OWN-001", Category: report.CategoryOwnership, Severity: report.SeverityLow, Title: "No owner"},
	}))
	current := sampleReport([]report.Finding{
		{ID: "FL-BND-001", Category: report.CategoryBoundary, Severity: report.SeverityHigh, Title: "Boundary", Evidence: []report.Evidence{{Key: "matched_import", Value: "example.com/app/internal/store", Source: "import_graph"}}},
	})
	result := Compare(base, current, CheckOptions{FailOnNew: report.SeverityHigh, FailOnRiskDelta: -1})
	if len(result.NewFindings) != 1 || result.NewFindings[0].ID != "FL-BND-001" {
		t.Fatalf("new findings = %+v", result.NewFindings)
	}
	if len(result.ResolvedFindings) != 1 || result.ResolvedFindings[0].ID != "FL-OWN-001" {
		t.Fatalf("resolved findings = %+v", result.ResolvedFindings)
	}
	if !result.Summary.Failed {
		t.Fatal("expected high new finding to fail")
	}
}

func TestCompareListsSuppressedWithoutFailing(t *testing.T) {
	base := Create(sampleReport(nil))
	supp := report.SuppressionInfo{Reason: "waived", Owner: "@team", Expires: "2099-01-01", Package: "example.com/app"}
	current := sampleReport([]report.Finding{
		{ID: "FL-BND-001", Category: report.CategoryBoundary, Severity: report.SeverityHigh, Title: "Boundary", Suppressed: true, Suppression: &supp},
	})
	result := Compare(base, current, CheckOptions{FailOnNew: report.SeverityHigh, FailOnRiskDelta: -1})
	if len(result.SuppressedFindings) != 1 {
		t.Fatalf("suppressed findings = %+v", result.SuppressedFindings)
	}
	if len(result.NewFindings) != 0 {
		t.Fatalf("suppressed finding should not be new: %+v", result.NewFindings)
	}
	if result.Summary.Failed {
		t.Fatal("suppressed high finding should not fail baseline check")
	}
}

func TestCompareRiskDeltaThreshold(t *testing.T) {
	baseReport := sampleReport(nil)
	baseReport.Packages[0].RiskScore = 20
	current := sampleReport(nil)
	current.Packages[0].RiskScore = 28.5
	result := Compare(Create(baseReport), current, CheckOptions{FailOnRiskDelta: 5})
	if len(result.WorsenedPackages) != 1 {
		t.Fatalf("worsened packages = %+v", result.WorsenedPackages)
	}
	if !result.Summary.Failed {
		t.Fatal("expected risk delta over threshold to fail")
	}
}

func TestCompareRepoFingerprintMismatchWarning(t *testing.T) {
	base := Create(sampleReport(nil))
	current := sampleReport(nil)
	current.Meta.RepoFingerprint = "other"
	result := Compare(base, current, CheckOptions{FailOnRiskDelta: -1})
	if len(result.Warnings) == 0 {
		t.Fatal("expected fingerprint mismatch warning")
	}
}

func TestFindingIdentityUsesBoundaryImportEvidence(t *testing.T) {
	pkg := report.PackageRisk{ImportPath: "example.com/app/internal/handlers", Dir: "internal/handlers"}
	first := Identity(pkg, report.Finding{
		ID:       "FL-BND-001",
		Category: report.CategoryBoundary,
		Severity: report.SeverityHigh,
		Evidence: []report.Evidence{{Key: "matched_import", Value: "example.com/app/internal/store", Source: "import_graph"}},
	})
	second := Identity(pkg, report.Finding{
		ID:       "FL-BND-001",
		Category: report.CategoryBoundary,
		Severity: report.SeverityHigh,
		Evidence: []report.Evidence{{Key: "matched_import", Value: "example.com/app/internal/db", Source: "import_graph"}},
	})
	if first.Key == second.Key {
		t.Fatal("different denied imports should produce different identities")
	}
	if first.Location == "" {
		t.Fatal("expected location in identity")
	}
}

func sampleReport(findings []report.Finding) *report.Report {
	scanTime := time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)
	pkg := report.PackageRisk{
		ImportPath: "example.com/app/internal/foo",
		Dir:        "internal/foo",
		RiskScore:  50,
		Findings:   append([]report.Finding{}, findings...),
	}
	rep := &report.Report{
		Meta: report.ScanMeta{
			Version:         "dev",
			ScanTime:        scanTime,
			RepoFingerprint: "repo-abc",
			ConfigHash:      "cfg-123",
		},
		Packages: []report.PackageRisk{pkg},
	}
	rep.Summary = report.ComputeSummary(rep.Packages, nil)
	return rep
}
