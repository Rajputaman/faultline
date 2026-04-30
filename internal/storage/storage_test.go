package storage

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/faultline-go/faultline/internal/report"
)

func TestSaveReportAndTrendComparison(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "faultline.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	first := sampleReport("repo", 10)
	first.Meta.ConfigHash = "abc"
	ApplyTrends(first, map[string]float64{})
	scanID, err := store.SaveReport(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	if scanID == 0 {
		t.Fatal("expected scan id")
	}

	previous, method, err := store.PreviousPackageScores(ctx, RepoIdentity{RootPath: "repo"})
	if err != nil {
		t.Fatal(err)
	}
	if method != HistoryMatchPath {
		t.Fatalf("match method = %s, want PATH", method)
	}
	second := sampleReport("repo", 15)
	ApplyTrends(second, previous)
	if second.Packages[0].PreviousRiskScore == nil || *second.Packages[0].PreviousRiskScore != 10 {
		t.Fatalf("previous risk = %v, want 10", second.Packages[0].PreviousRiskScore)
	}
	if second.Packages[0].RiskDelta == nil || *second.Packages[0].RiskDelta != 5 {
		t.Fatalf("risk delta = %v, want 5", second.Packages[0].RiskDelta)
	}
	if second.Packages[0].Trend != "WORSENED" {
		t.Fatalf("trend = %q, want WORSENED", second.Packages[0].Trend)
	}
	if _, err := store.SaveReport(ctx, second); err != nil {
		t.Fatal(err)
	}

	scans, err := store.ListScans(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(scans) != 2 {
		t.Fatalf("scans = %d, want 2", len(scans))
	}
	detail, err := store.ShowScan(ctx, scans[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(detail.Packages) != 1 || detail.Packages[0].Trend != "WORSENED" {
		t.Fatalf("unexpected detail packages: %+v", detail.Packages)
	}
}

func TestApplyTrendsDeterministic(t *testing.T) {
	rep := &report.Report{
		Packages: []report.PackageRisk{
			{ImportPath: "b", RiskScore: 20},
			{ImportPath: "a", RiskScore: 9},
		},
	}
	ApplyTrends(rep, map[string]float64{"a": 10, "b": 20})
	if rep.Packages[0].ImportPath != "a" || rep.Packages[1].ImportPath != "b" {
		t.Fatalf("packages not sorted deterministically: %+v", rep.Packages)
	}
	if rep.Packages[0].Trend != "IMPROVED" || rep.Packages[1].Trend != "UNCHANGED" {
		t.Fatalf("unexpected trends: %+v", rep.Packages)
	}
}

func TestRepoFingerprintStableAcrossDifferentLocalPaths(t *testing.T) {
	parent := t.TempDir()
	first := filepath.Join(parent, "one", "repo")
	second := filepath.Join(parent, "two", "repo")
	writeGoMod(t, first, "github.com/example/project")
	writeGoMod(t, second, "github.com/example/project")

	a := ComputeRepoIdentity(context.Background(), first, nil)
	b := ComputeRepoIdentity(context.Background(), second, nil)
	if a.Fingerprint == "" {
		t.Fatal("expected fingerprint")
	}
	if a.Fingerprint != b.Fingerprint {
		t.Fatalf("fingerprints differ: %s != %s", a.Fingerprint, b.Fingerprint)
	}
	if a.DisplayName != "github.com/example/project" {
		t.Fatalf("display name = %q", a.DisplayName)
	}
}

func TestFingerprintHistoryMatchesMovedRepo(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "faultline.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	parent := t.TempDir()
	firstPath := filepath.Join(parent, "one", "repo")
	secondPath := filepath.Join(parent, "two", "repo")
	writeGoMod(t, firstPath, "github.com/example/project")
	writeGoMod(t, secondPath, "github.com/example/project")
	firstIdentity := ComputeRepoIdentity(ctx, firstPath, nil)
	secondIdentity := ComputeRepoIdentity(ctx, secondPath, nil)

	first := sampleReport(firstPath, 33)
	first.Meta.RepoFingerprint = firstIdentity.Fingerprint
	first.Meta.RepoDisplayName = firstIdentity.DisplayName
	if _, err := store.SaveReport(ctx, first); err != nil {
		t.Fatal(err)
	}
	previous, method, err := store.PreviousPackageScores(ctx, secondIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if method != HistoryMatchFingerprint {
		t.Fatalf("method = %s, want FINGERPRINT", method)
	}
	if previous["github.com/example/project/pkg"] != 33 {
		t.Fatalf("previous score = %+v, want 33", previous)
	}
}

func TestLegacyPathOnlyRowsStillMatchAndMigrate(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "faultline.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE scans (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp TEXT NOT NULL,
		repo_root TEXT NOT NULL,
		faultline_version TEXT NOT NULL,
		config_hash TEXT NOT NULL
	);
	CREATE TABLE package_metrics (
		scan_id INTEGER NOT NULL,
		import_path TEXT NOT NULL,
		dir TEXT NOT NULL,
		risk_score REAL NOT NULL,
		previous_risk_score REAL,
		risk_delta REAL,
		trend TEXT,
		churn_score REAL NOT NULL,
		coverage_gap_score REAL NOT NULL,
		complexity_score REAL NOT NULL,
		ownership_entropy_score REAL NOT NULL,
		dependency_centrality_score REAL NOT NULL,
		coverage_pct REAL,
		churn_30d INTEGER NOT NULL,
		churn_90d INTEGER NOT NULL,
		author_count_90d INTEGER NOT NULL,
		owner TEXT,
		reverse_import_count INTEGER NOT NULL
	);
	INSERT INTO scans(timestamp, repo_root, faultline_version, config_hash) VALUES('2026-04-30T00:00:00Z', '/legacy/repo', 'old', 'old');
	INSERT INTO package_metrics(scan_id, import_path, dir, risk_score, churn_score, coverage_gap_score, complexity_score, ownership_entropy_score, dependency_centrality_score, churn_30d, churn_90d, author_count_90d, reverse_import_count)
	VALUES(1, 'github.com/example/project/pkg', 'pkg', 42, 0, 0, 0, 0, 0, 0, 0, 0, 0);`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	previous, method, err := store.PreviousPackageScores(ctx, RepoIdentity{Fingerprint: "new", RootPath: "/legacy/repo"})
	if err != nil {
		t.Fatal(err)
	}
	if method != HistoryMatchPath {
		t.Fatalf("method = %s, want PATH", method)
	}
	if previous["github.com/example/project/pkg"] != 42 {
		t.Fatalf("previous = %+v, want 42", previous)
	}
	columns, err := store.tableColumns(ctx, "scans")
	if err != nil {
		t.Fatal(err)
	}
	for _, col := range []string{"repo_root_path", "repo_fingerprint", "repo_display_name"} {
		if !columns[col] {
			t.Fatalf("expected migrated column %s", col)
		}
	}
}

func TestDoctor(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "faultline.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	rep := sampleReport("repo", 10)
	rep.Meta.RepoFingerprint = "abc"
	rep.Meta.RepoDisplayName = "repo"
	if _, err := store.SaveReport(ctx, rep); err != nil {
		t.Fatal(err)
	}
	doctor, err := store.Doctor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if doctor.DriverName != DriverName || doctor.SchemaVersion != schemaVersion || doctor.ScanCount != 1 || doctor.FingerprintCount != 1 {
		t.Fatalf("unexpected doctor report: %+v", doctor)
	}
}

func sampleReport(repoRoot string, risk float64) *report.Report {
	return &report.Report{
		Meta: report.ScanMeta{
			RepoPath: repoRoot,
			Version:  "test",
			ScanTime: time.Now().UTC(),
		},
		Packages: []report.PackageRisk{
			{
				ImportPath: "github.com/example/project/pkg",
				Dir:        "pkg",
				RiskScore:  risk,
				ScoreBreakdown: report.ScoreBreakdown{
					ChurnScore:                risk,
					CoverageGapScore:          risk,
					ComplexityScore:           risk,
					OwnershipEntropyScore:     risk,
					DependencyCentralityScore: risk,
				},
				Findings: []report.Finding{
					{ID: "FL-COV-002", Category: report.CategoryCoverage, Severity: report.SeverityLow, Title: "missing coverage"},
				},
			},
		},
	}
}

func writeGoMod(t *testing.T, dir, modulePath string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module "+modulePath+"\n\ngo 1.26\n"), 0600); err != nil {
		t.Fatal(err)
	}
}
