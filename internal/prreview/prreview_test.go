package prreview

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/faultline-go/faultline/internal/analyzer"
	"github.com/faultline-go/faultline/internal/policy"
	"github.com/faultline-go/faultline/internal/report"
)

func TestChangedFiles(t *testing.T) {
	dir := t.TempDir()
	runGit(t, dir, "init")
	runGit(t, dir, "config", "user.email", "test@example.com")
	runGit(t, dir, "config", "user.name", "Test")
	writeFile(t, filepath.Join(dir, "pkg", "a", "a.go"), "package a\n")
	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "-m", "initial")
	writeFile(t, filepath.Join(dir, "pkg", "a", "a.go"), "package a\nfunc A() {}\n")
	writeFile(t, filepath.Join(dir, "pkg", "a", "a_test.go"), "package a\n")
	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "-m", "change")

	got, err := ChangedFiles(context.Background(), dir, "HEAD~1", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"pkg/a/a.go", "pkg/a/a_test.go"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("changed files = %v, want %v", got, want)
	}
}

func TestPackageScopes(t *testing.T) {
	root := t.TempDir()
	pkgs := []analyzer.LoadedPackage{
		{
			ImportPath: "github.com/example/project/internal/a",
			Dir:        filepath.Join(root, "internal", "a"),
		},
		{
			ImportPath:      "github.com/example/project/internal/b",
			Dir:             filepath.Join(root, "internal", "b"),
			InternalImports: []string{"github.com/example/project/internal/a"},
		},
		{
			ImportPath: "github.com/example/project/internal/c",
			Dir:        filepath.Join(root, "internal", "c"),
		},
	}
	scopes := PackageScopes(root, pkgs, []string{"internal/a/a.go"})
	if scopes["github.com/example/project/internal/a"] != ScopeChanged {
		t.Fatalf("a scope = %q, want CHANGED", scopes["github.com/example/project/internal/a"])
	}
	if scopes["github.com/example/project/internal/b"] != ScopeImpacted {
		t.Fatalf("b scope = %q, want IMPACTED", scopes["github.com/example/project/internal/b"])
	}
	if _, ok := scopes["github.com/example/project/internal/c"]; ok {
		t.Fatal("unrelated package should not be included")
	}
}

func TestPackageScopesAcrossModules(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", "..", "testdata", "multi-module-repo"))
	if err != nil {
		t.Fatal(err)
	}
	loaded, _, err := loadReviewPackages(context.Background(), repo)
	if err != nil {
		t.Fatalf("load review packages: %v", err)
	}
	changed, err := ChangedGoFiles(repo, []string{"service-a/internal/handlers/handler.go"})
	if err != nil {
		t.Fatal(err)
	}
	scopes := PackageScopes(repo, loaded, changed)
	if scopes["example.com/monorepo/service-a/internal/handlers"] != ScopeChanged {
		t.Fatalf("handler package not changed: %+v", scopes)
	}
	if _, ok := scopes["example.com/monorepo/service-b"]; ok {
		t.Fatalf("service-b should not be impacted by service-a handler change: %+v", scopes)
	}
}

func TestChangedGoFilesIgnoresGeneratedDeletedAndVendor(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "pkg", "a.go"), "package pkg\n")
	writeFile(t, filepath.Join(root, "pkg", "mock_client.go"), "package pkg\n")
	writeFile(t, filepath.Join(root, "vendor", "x", "x.go"), "package x\n")
	got, err := ChangedGoFiles(root, []string{
		"pkg/a.go",
		"pkg/mock_client.go",
		"vendor/x/x.go",
		"pkg/deleted.go",
		"README.md",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "pkg/a.go" {
		t.Fatalf("changed Go files = %v, want [pkg/a.go]", got)
	}
}

func TestWorktreeArgs(t *testing.T) {
	add := strings.Join(worktreeAddArgs("/tmp/faultline-base", "origin/main"), " ")
	if add != "worktree add --detach /tmp/faultline-base origin/main" {
		t.Fatalf("add args = %q", add)
	}
	remove := strings.Join(worktreeRemoveArgs("/tmp/faultline-base"), " ")
	if remove != "worktree remove --force /tmp/faultline-base" {
		t.Fatalf("remove args = %q", remove)
	}
}

func TestWithBaseWorktreeCleansUpAndDoesNotMutateCaller(t *testing.T) {
	dir := newPRFixtureRepo(t)
	headBefore := gitOutputForTest(t, dir, "rev-parse", "HEAD")
	branchBefore := gitOutputForTest(t, dir, "rev-parse", "--abbrev-ref", "HEAD")
	var worktreePath string
	err := WithBaseWorktree(context.Background(), dir, "HEAD~1", func(path string) error {
		worktreePath = path
		if _, err := os.Stat(filepath.Join(path, "go.mod")); err != nil {
			t.Fatalf("expected base worktree files: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if worktreePath == "" {
		t.Fatal("worktree path was not captured")
	}
	if _, err := os.Stat(worktreePath); !os.IsNotExist(err) {
		t.Fatalf("expected worktree cleanup, stat err=%v", err)
	}
	if got := gitOutputForTest(t, dir, "rev-parse", "HEAD"); got != headBefore {
		t.Fatalf("caller HEAD changed: got %s want %s", got, headBefore)
	}
	if got := gitOutputForTest(t, dir, "rev-parse", "--abbrev-ref", "HEAD"); got != branchBefore {
		t.Fatalf("caller branch changed: got %s want %s", got, branchBefore)
	}

	var failedWorktreePath string
	sentinel := errors.New("forced scan failure")
	err = WithBaseWorktree(context.Background(), dir, "HEAD~1", func(path string) error {
		failedWorktreePath = path
		return sentinel
	})
	if err == nil || !strings.Contains(err.Error(), sentinel.Error()) {
		t.Fatalf("expected callback error, got %v", err)
	}
	if _, statErr := os.Stat(failedWorktreePath); !os.IsNotExist(statErr) {
		t.Fatalf("expected failed worktree cleanup, stat err=%v", statErr)
	}
}

func TestWithHeadWorktreeCleansUpOnCallbackFailure(t *testing.T) {
	dir := newExternalHeadRepo(t)
	var failedWorktreePath string
	sentinel := errors.New("forced head scan failure")
	err := WithRefWorktree(context.Background(), dir, "head", "feature/foo", func(path string) error {
		failedWorktreePath = path
		return sentinel
	})
	if err == nil || !strings.Contains(err.Error(), sentinel.Error()) {
		t.Fatalf("expected callback error, got %v", err)
	}
	if _, statErr := os.Stat(failedWorktreePath); !os.IsNotExist(statErr) {
		t.Fatalf("expected failed head worktree cleanup, stat err=%v", statErr)
	}
	assertOnlyCallerWorktree(t, dir)
}

func TestRunWorktreeDetectsNewBoundaryFindingAgainstBase(t *testing.T) {
	dir := newPRFixtureRepo(t)
	review, body, err := Run(context.Background(), Options{
		RepoRoot:    dir,
		Base:        "HEAD~1",
		Head:        "HEAD",
		CompareMode: string(CompareModeWorktree),
		Config:      boundaryConfig(),
		CommentOut:  filepath.Join(t.TempDir(), "review.md"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if review.CompareModeUsed != string(CompareModeWorktree) {
		t.Fatalf("compare mode = %q, want worktree", review.CompareModeUsed)
	}
	if review.NewBoundaryFindings != 1 || review.NewHighFindings != 1 {
		t.Fatalf("new counts = boundary %d high %d, want 1/1\n%s", review.NewBoundaryFindings, review.NewHighFindings, body)
	}
	if !strings.Contains(body, "FL-BND-001") || !strings.Contains(body, "Compare mode used: worktree") {
		t.Fatalf("markdown missing worktree boundary result:\n%s", body)
	}
	if !strings.Contains(body, "Changed File Owners") || !strings.Contains(body, "Request review from CODEOWNERS owner(s): @handlers-team") {
		t.Fatalf("markdown missing file owner summary or guidance:\n%s", body)
	}
}

func TestRunWorktreeUsesExternalHeadWorktree(t *testing.T) {
	dir := newExternalHeadRepo(t)
	headBefore := gitOutputForTest(t, dir, "rev-parse", "HEAD")
	branchBefore := gitOutputForTest(t, dir, "rev-parse", "--abbrev-ref", "HEAD")
	review, body, err := Run(context.Background(), Options{
		RepoRoot:     dir,
		Base:         "main",
		Head:         "feature/foo",
		HeadExplicit: true,
		CompareMode:  string(CompareModeWorktree),
		Config:       boundaryConfig(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if review.HeadScanPathType != string(ScanPathWorktree) || review.BaseScanPathType != string(ScanPathWorktree) {
		t.Fatalf("scan path types = base %q head %q, want worktree/worktree", review.BaseScanPathType, review.HeadScanPathType)
	}
	if review.ChangedPackages != 1 || review.NewBoundaryFindings != 1 {
		t.Fatalf("changed/new boundary = %d/%d\n%s", review.ChangedPackages, review.NewBoundaryFindings, body)
	}
	if len(review.ChangedFiles) != 1 || review.ChangedFiles[0] != "internal/handlers/handlers.go" {
		t.Fatalf("changed files = %v, want handlers diff from main...feature/foo", review.ChangedFiles)
	}
	if !strings.Contains(body, "Head scan path type: worktree") || !strings.Contains(body, "Base scan path type: worktree") {
		t.Fatalf("markdown missing scan path types:\n%s", body)
	}
	assertOnlyCallerWorktree(t, dir)
	if got := gitOutputForTest(t, dir, "rev-parse", "HEAD"); got != headBefore {
		t.Fatalf("caller HEAD changed: got %s want %s", got, headBefore)
	}
	if got := gitOutputForTest(t, dir, "rev-parse", "--abbrev-ref", "HEAD"); got != branchBefore {
		t.Fatalf("caller branch changed: got %s want %s", got, branchBefore)
	}
}

func TestRunWritesPRSARIFForOnlyNewFindings(t *testing.T) {
	dir := newExternalHeadRepo(t)
	out := filepath.Join(t.TempDir(), "faultline-pr.sarif")
	review, body, err := Run(context.Background(), Options{
		RepoRoot:     dir,
		Base:         "main",
		Head:         "feature/foo",
		HeadExplicit: true,
		CompareMode:  string(CompareModeWorktree),
		Config:       boundaryConfig(),
		SARIFOut:     out,
	})
	if err != nil {
		t.Fatal(err)
	}
	if review.SARIFOut != out {
		t.Fatalf("SARIFOut = %q, want %q", review.SARIFOut, out)
	}
	if !strings.Contains(body, "Inline annotations available via uploaded SARIF.") {
		t.Fatalf("markdown missing SARIF note:\n%s", body)
	}
	doc := readSARIF(t, out)
	if len(doc.Runs) != 1 || len(doc.Runs[0].Results) != 1 {
		t.Fatalf("SARIF results = %+v, want one new finding", doc.Runs)
	}
	result := doc.Runs[0].Results[0]
	if result.RuleID != "FL-BND-001" {
		t.Fatalf("rule ID = %q, want FL-BND-001", result.RuleID)
	}
	if got := result.Locations[0].PhysicalLocation.ArtifactLocation.URI; got != "internal/handlers/handlers.go" {
		t.Fatalf("location = %q, want internal/handlers/handlers.go", got)
	}
	if len(result.Properties.FileOwners) != 1 || result.Properties.FileOwners[0] != "@handlers-team" ||
		result.Properties.CodeownersPattern != "/internal/handlers/" {
		t.Fatalf("missing SARIF file owner properties: %+v", result.Properties)
	}
	props := doc.Runs[0].Properties
	if props["faultline.pr.base_ref"] != "main" ||
		props["faultline.pr.head_ref"] != "feature/foo" ||
		props["faultline.pr.compare_mode"] != "worktree" ||
		props["faultline.pr.changed_package_count"] != "1" {
		t.Fatalf("unexpected PR SARIF properties: %+v", props)
	}
}

func TestChangedFileOwnerSummaryMismatch(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "CODEOWNERS"), `/internal/handlers/ @handlers-team
README.md @docs-team
`)
	writeFile(t, filepath.Join(root, "internal", "handlers", "handlers.go"), "package handlers\n")
	writeFile(t, filepath.Join(root, "README.md"), "# docs\n")
	packageOwner := "@package-team"
	packages := []report.PackageRisk{{
		ImportPath:    "github.com/example/project/internal/handlers",
		Dir:           "internal/handlers",
		DominantOwner: &packageOwner,
	}}
	owned, unowned, mismatches := changedFileOwnerSummary(root, []string{"internal/handlers/handlers.go", "README.md", "missing.go"}, packages)
	if len(unowned) != 0 {
		t.Fatalf("unowned = %v, want none", unowned)
	}
	if len(owned) != 2 {
		t.Fatalf("owned = %+v, want two entries", owned)
	}
	if len(mismatches) != 1 || mismatches[0].Path != "internal/handlers/handlers.go" {
		t.Fatalf("mismatches = %+v, want handlers mismatch", mismatches)
	}
	body := RenderMarkdown(&Review{
		ChangedFileOwners:   owned,
		ChangedFilesUnowned: unowned,
		OwnerMismatches:     mismatches,
	})
	if !strings.Contains(body, "Changed File Owners") ||
		!strings.Contains(body, "@handlers-team") ||
		!strings.Contains(body, "mismatch") ||
		!strings.Contains(body, "Request review from CODEOWNERS owner(s): @docs-team, @handlers-team") {
		t.Fatalf("markdown missing owner summary:\n%s", body)
	}
}

func TestPRSARIFOmitSuppressedAndResolvedFindings(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "pkg", "pkg.go"), "package pkg\n")
	active := report.Finding{ID: "FL-COV-001", Severity: report.SeverityMedium, Title: "Low coverage", Description: "Coverage is low."}
	suppressed := report.Finding{ID: "FL-OWN-001", Severity: report.SeverityLow, Title: "No owner found", Description: "No owner.", Suppressed: true}
	resolved := report.Finding{ID: "FL-GEN-001", Severity: report.SeverityLow, Title: "Generated-heavy", Description: "Generated heavy."}
	head := &report.Report{
		Meta: report.ScanMeta{Version: "test", RepoPath: root},
		Packages: []report.PackageRisk{{
			ImportPath: "github.com/example/project/pkg",
			Dir:        "pkg",
			Findings:   []report.Finding{active, suppressed},
		}},
	}
	review := &Review{
		Base:                 "main",
		Head:                 "feature/foo",
		CompareModeRequested: "worktree",
		CompareModeUsed:      "worktree",
		ChangedPackages:      1,
		Packages: []PackageReview{{
			Package:          head.Packages[0],
			Scope:            ScopeChanged,
			NewFindings:      []report.Finding{active},
			ResolvedFindings: []report.Finding{resolved},
		}},
	}
	out1 := filepath.Join(t.TempDir(), "one.sarif")
	out2 := filepath.Join(t.TempDir(), "two.sarif")
	if err := writePRSARIF(out1, head, review); err != nil {
		t.Fatal(err)
	}
	if err := writePRSARIF(out2, head, review); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(out1)
	if err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(out2)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("PR SARIF output is not deterministic")
	}
	doc := readSARIF(t, out1)
	if len(doc.Runs[0].Results) != 1 || doc.Runs[0].Results[0].RuleID != "FL-COV-001" {
		t.Fatalf("unexpected filtered results: %+v", doc.Runs[0].Results)
	}
}

func TestRunOmittedAndCurrentHeadUseCallerWorktree(t *testing.T) {
	tests := []struct {
		name         string
		head         string
		headExplicit bool
	}{
		{name: "omitted"},
		{name: "explicit current", head: "HEAD", headExplicit: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := newPRFixtureRepo(t)
			review, _, err := Run(context.Background(), Options{
				RepoRoot:     dir,
				Base:         "HEAD~1",
				Head:         tt.head,
				HeadExplicit: tt.headExplicit,
				CompareMode:  string(CompareModeHistory),
				Config:       boundaryConfig(),
			})
			if err != nil {
				t.Fatal(err)
			}
			if review.HeadScanPathType != string(ScanPathCaller) {
				t.Fatalf("head scan path type = %q, want caller", review.HeadScanPathType)
			}
			assertOnlyCallerWorktree(t, dir)
		})
	}
}

func TestRunAutoFallsBackToHistoryWhenBaseUnavailable(t *testing.T) {
	dir := newPRFixtureRepo(t)
	review, _, err := Run(context.Background(), Options{
		RepoRoot:    dir,
		Base:        "refs/heads/does-not-exist",
		Head:        "HEAD",
		CompareMode: string(CompareModeAuto),
		Config:      boundaryConfig(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if review.CompareModeUsed != string(CompareModeHistory) {
		t.Fatalf("compare mode = %q, want history", review.CompareModeUsed)
	}
	if review.FallbackReason == "" || !containsWarning(review.Warnings, "falling back to local history") {
		t.Fatalf("expected fallback warning, reason=%q warnings=%v", review.FallbackReason, review.Warnings)
	}
}

func TestRenderMarkdownDeterministicAndMarker(t *testing.T) {
	review := &Review{
		Base:                 "origin/main",
		Head:                 "HEAD",
		ChangedPackages:      1,
		ImpactedPackages:     1,
		NewHighFindings:      1,
		CompareModeRequested: "auto",
		CompareModeUsed:      "worktree",
		BaseScanPathType:     "worktree",
		HeadScanPathType:     "caller",
		MatchMethod:          "worktree",
		Packages: []PackageReview{
			{
				Scope: ScopeChanged,
				Package: report.PackageRisk{
					ImportPath: "github.com/example/project/internal/a",
					RiskScore:  80,
				},
				NewFindings: []report.Finding{{ID: "FL-BND-001", Severity: report.SeverityHigh, Title: "Architecture boundary violation"}},
			},
		},
	}
	first := RenderMarkdown(review)
	second := RenderMarkdown(review)
	if first != second {
		t.Fatal("markdown output is not deterministic")
	}
	if !strings.Contains(first, CommentMarker) || !strings.Contains(first, "FL-BND-001") {
		t.Fatalf("markdown missing marker or finding:\n%s", first)
	}
}

func TestRenderMarkdownIncludesResolvedFindings(t *testing.T) {
	review := &Review{
		Base:                 "origin/main",
		Head:                 "HEAD",
		CompareModeRequested: "worktree",
		CompareModeUsed:      "worktree",
		BaseScanPathType:     "worktree",
		HeadScanPathType:     "caller",
		MatchMethod:          "worktree",
		Packages: []PackageReview{
			{
				Scope:   ScopeChanged,
				Package: report.PackageRisk{ImportPath: "github.com/example/project/internal/a", RiskScore: 10},
				ResolvedFindings: []report.Finding{{
					ID:       "FL-COV-001",
					Severity: report.SeverityMedium,
					Title:    "Low package coverage",
				}},
			},
		},
	}
	body := RenderMarkdown(review)
	if !strings.Contains(body, "## Resolved Findings") || !strings.Contains(body, "FL-COV-001") {
		t.Fatalf("resolved findings missing:\n%s", body)
	}
}

func TestRenderMarkdownIncludesSARIFNote(t *testing.T) {
	body := RenderMarkdown(&Review{
		Base:                 "main",
		Head:                 "feature/foo",
		CompareModeRequested: "worktree",
		CompareModeUsed:      "worktree",
		BaseScanPathType:     "worktree",
		HeadScanPathType:     "worktree",
		SARIFOut:             "faultline-pr.sarif",
	})
	if !strings.Contains(body, "Inline annotations available via uploaded SARIF.") {
		t.Fatalf("markdown missing SARIF note:\n%s", body)
	}
}

func TestHasFailingNewFinding(t *testing.T) {
	review := &Review{Packages: []PackageReview{{NewFindings: []report.Finding{{ID: "FL-COV-001", Severity: report.SeverityMedium}}}}}
	if HasFailingNewFinding(review, report.SeverityHigh) {
		t.Fatal("medium finding should not fail high threshold")
	}
	review.Packages[0].NewFindings = append(review.Packages[0].NewFindings, report.Finding{ID: "FL-BND-001", Severity: report.SeverityHigh})
	if !HasFailingNewFinding(review, report.SeverityHigh) {
		t.Fatal("high finding should fail high threshold")
	}
}

func TestPostReviewNoToken(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	err := PostReview(context.Background(), "owner/repo", "1", "body")
	if err == nil || !strings.Contains(err.Error(), "GITHUB_TOKEN") {
		t.Fatalf("expected missing token error, got %v", err)
	}
}

func newPRFixtureRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"), "module github.com/example/worktree\n\ngo 1.26\n")
	writeFile(t, filepath.Join(dir, "CODEOWNERS"), "/internal/handlers/ @handlers-team\n")
	writeFile(t, filepath.Join(dir, "internal", "storage", "storage.go"), "package storage\n\nfunc Store() {}\n")
	writeFile(t, filepath.Join(dir, "internal", "handlers", "handlers.go"), "package handlers\n\nfunc Handle() {}\n")
	runGit(t, dir, "init")
	runGit(t, dir, "config", "user.email", "test@example.com")
	runGit(t, dir, "config", "user.name", "Test")
	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "-m", "base")
	writeFile(t, filepath.Join(dir, "internal", "handlers", "handlers.go"), `package handlers

import _ "github.com/example/worktree/internal/storage"

func Handle() {}
`)
	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "-m", "introduce boundary violation")
	return dir
}

func newExternalHeadRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"), "module github.com/example/worktree\n\ngo 1.26\n")
	writeFile(t, filepath.Join(dir, "CODEOWNERS"), "/internal/handlers/ @handlers-team\n")
	writeFile(t, filepath.Join(dir, "internal", "storage", "storage.go"), "package storage\n\nfunc Store() {}\n")
	writeFile(t, filepath.Join(dir, "internal", "handlers", "handlers.go"), "package handlers\n\nfunc Handle() {}\n")
	runGit(t, dir, "init")
	runGit(t, dir, "config", "user.email", "test@example.com")
	runGit(t, dir, "config", "user.name", "Test")
	runGit(t, dir, "checkout", "-b", "main")
	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "-m", "base")
	runGit(t, dir, "checkout", "-b", "feature/foo")
	writeFile(t, filepath.Join(dir, "internal", "handlers", "handlers.go"), `package handlers

import _ "github.com/example/worktree/internal/storage"

func Handle() {}
`)
	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "-m", "introduce boundary violation")
	runGit(t, dir, "checkout", "main")
	return dir
}

func boundaryConfig() policy.Config {
	cfg := policy.DefaultConfig()
	cfg.Boundaries = []policy.BoundaryRule{
		{
			Name: "handlers-must-not-import-storage",
			From: "*/internal/handlers",
			Deny: []string{"*/internal/storage"},
		},
	}
	return cfg
}

func containsWarning(warnings []string, needle string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, needle) {
			return true
		}
	}
	return false
}

func gitOutputForTest(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return strings.TrimSpace(string(out))
}

type sarifDocumentForTest struct {
	Runs []struct {
		Results []struct {
			RuleID    string `json:"ruleId"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
				} `json:"physicalLocation"`
			} `json:"locations"`
			Properties struct {
				FileOwners        []string `json:"fileOwners"`
				CodeownersPattern string   `json:"codeownersPattern"`
			} `json:"properties"`
		} `json:"results"`
		Properties map[string]string `json:"properties"`
	} `json:"runs"`
}

func readSARIF(t *testing.T, path string) sarifDocumentForTest {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc sarifDocumentForTest
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal SARIF: %v", err)
	}
	return doc
}

func assertOnlyCallerWorktree(t *testing.T, dir string) {
	t.Helper()
	cmd := exec.Command("git", "worktree", "list", "--porcelain")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git worktree list: %v", err)
	}
	count := 0
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "worktree ") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected only caller worktree, got %d:\n%s", count, string(out))
	}
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, string(out))
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}
