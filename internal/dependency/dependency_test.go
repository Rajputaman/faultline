package dependency

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/faultline-go/faultline/internal/report"
)

func TestAnalyzeGoModParsingAndRiskSignals(t *testing.T) {
	repo := t.TempDir()
	writeFile(t, filepath.Join(repo, "go.mod"), `module example.com/app

go 1.26

require (
	github.com/acme/used v1.2.3
	github.com/acme/unused v1.0.0
	github.com/acme/pseudo v0.0.0-20240102030405-abcdef123456
	github.com/acme/local v1.0.0
	github.com/acme/renamed v1.0.0
)

replace github.com/acme/local => ./local
replace github.com/acme/renamed => github.com/other/renamed v1.1.0
`)
	writeFile(t, filepath.Join(repo, "go.sum"), `github.com/acme/used v1.2.3 h1:abc
github.com/acme/used v1.2.3/go.mod h1:def
`)
	result := Analyze(context.Background(), Options{
		RepoPath: repo,
		Packages: []PackageImports{
			{ImportPath: "example.com/app/a", Imports: []string{"github.com/acme/used/pkg", "github.com/acme/pseudo"}},
			{ImportPath: "example.com/app/b", Imports: []string{"github.com/acme/used/pkg"}},
			{ImportPath: "example.com/app/c", Imports: []string{"github.com/acme/used/other"}},
		},
		Govulncheck: "off",
	})
	if len(result.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %+v", result.Warnings)
	}
	if len(result.Dependencies) != 5 {
		t.Fatalf("dependencies = %d, want 5: %+v", len(result.Dependencies), result.Dependencies)
	}
	assertFinding(t, result.Findings, "FL-DEP-002")
	assertFinding(t, result.Findings, "FL-DEP-003")
	assertFinding(t, result.Findings, "FL-DEP-004")
	assertFinding(t, result.Findings, "FL-DEP-005")
	assertFinding(t, result.Findings, "FL-DEP-006")
	used := dependencyByPath(result.Dependencies, "github.com/acme/used")
	if used == nil || !used.Used || used.ImportingPackageCount != 3 || !used.GoSumPresent {
		t.Fatalf("unexpected used dependency: %+v", used)
	}
	local := dependencyByPath(result.Dependencies, "github.com/acme/local")
	if local == nil || !local.LocalReplace || local.Replace == nil || local.Replace.NewPath != "./local" {
		t.Fatalf("local replace not detected: %+v", local)
	}
}

func TestUnusedDependencySkipsIndirectRequire(t *testing.T) {
	repo := t.TempDir()
	writeFile(t, filepath.Join(repo, "go.mod"), `module example.com/app

go 1.26

require github.com/acme/transitive v1.0.0 // indirect
`)
	result := Analyze(context.Background(), Options{RepoPath: repo})
	if hasFinding(result.Findings, "FL-DEP-004") {
		t.Fatalf("indirect dependency should not be flagged unused: %+v", result.Findings)
	}
}

func TestGovulncheckOffDoesNotRequireBinary(t *testing.T) {
	repo := t.TempDir()
	writeFile(t, filepath.Join(repo, "go.mod"), "module example.com/app\n\ngo 1.26\n")
	result := Analyze(context.Background(), Options{RepoPath: repo, Govulncheck: "off"})
	if result.Govulncheck != nil {
		t.Fatalf("govulncheck off should not run: %+v", result.Govulncheck)
	}
}

func TestGovulncheckAutoMissingGraceful(t *testing.T) {
	repo := t.TempDir()
	writeFile(t, filepath.Join(repo, "go.mod"), "module example.com/app\n\ngo 1.26\n")
	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", "")
	t.Cleanup(func() { _ = os.Setenv("PATH", oldPath) })
	result := Analyze(context.Background(), Options{RepoPath: repo, Govulncheck: "auto"})
	if result.Govulncheck == nil || result.Govulncheck.Ran {
		t.Fatalf("expected unavailable govulncheck result: %+v", result.Govulncheck)
	}
	if len(result.Warnings) == 0 || !strings.Contains(result.Warnings[0].Message, "not found") {
		t.Fatalf("expected graceful warning: %+v", result.Warnings)
	}
}

func TestCrossModuleLocalReplace(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", "..", "testdata", "multi-module-repo"))
	if err != nil {
		t.Fatal(err)
	}
	result := Analyze(context.Background(), Options{
		RepoPath: filepath.Join(repo, "service-a"),
		RepoRoot: repo,
		Module: report.ModuleInfo{
			ModulePath: "example.com/monorepo/service-a",
			ModuleRoot: "service-a",
			GoModPath:  "service-a/go.mod",
		},
		AllModules: []report.ModuleInfo{
			{ModulePath: "example.com/monorepo/service-a", ModuleRoot: "service-a"},
			{ModulePath: "example.com/monorepo/shared", ModuleRoot: "shared"},
		},
		Packages: []PackageImports{{ImportPath: "example.com/monorepo/service-a", Imports: []string{"example.com/monorepo/shared"}}},
	})
	assertFinding(t, result.Findings, "FL-DEP-007")
	dep := dependencyByPath(result.Dependencies, "example.com/monorepo/shared")
	if dep == nil || !dep.CrossModuleReplace || dep.ReplaceModuleRoot != "shared" {
		t.Fatalf("cross-module replace not recorded: %+v", dep)
	}
}

func assertFinding(t *testing.T, findings []report.Finding, id string) {
	t.Helper()
	if !hasFinding(findings, id) {
		t.Fatalf("missing finding %s in %+v", id, findings)
	}
}

func hasFinding(findings []report.Finding, id string) bool {
	for _, finding := range findings {
		if finding.ID == id {
			return true
		}
	}
	return false
}

func dependencyByPath(deps []report.DependencyRisk, modulePath string) *report.DependencyRisk {
	for i := range deps {
		if deps[i].ModulePath == modulePath {
			return &deps[i]
		}
	}
	return nil
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}
