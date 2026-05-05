package analyzer

import (
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/faultline-go/faultline/internal/coverage"
	"github.com/faultline-go/faultline/internal/dependency"
	fgit "github.com/faultline-go/faultline/internal/git"
	fmodule "github.com/faultline-go/faultline/internal/module"
	"github.com/faultline-go/faultline/internal/ownership"
	"github.com/faultline-go/faultline/internal/policy"
	"github.com/faultline-go/faultline/internal/report"
	"github.com/faultline-go/faultline/internal/scoring"
	"github.com/faultline-go/faultline/internal/version"
)

type VerboseWriter io.Writer

// Scanner coordinates package loading, enrichment, scoring, and report assembly.
type Scanner struct {
	RepoPath         string
	Config           policy.Config
	ConfigPath       string
	CoveragePath     string
	BuildTags        []string
	IncludeGenerated bool
	ExcludeGlobs     []string
	Govulncheck      string
	Modules          []report.ModuleInfo
	GoWorkPath       string
	VerboseWriter    VerboseWriter
	IncidentIndex    map[string][]report.SnapshotIncident
	Incidents        []report.SnapshotIncident
}

// Scan analyzes the requested package patterns and returns a report. Best-effort
// data sources such as git history, coverage, and CODEOWNERS degrade to evidence
// and findings instead of aborting the scan.
func (s Scanner) Scan(ctx context.Context, patterns []string) (*report.Report, error) {
	repoPath, err := filepath.Abs(s.RepoPath)
	if err != nil {
		return nil, fmt.Errorf("resolve repo path: %w", err)
	}
	if s.Config.Version == 0 {
		s.Config = policy.DefaultConfig()
	}

	loaded, loadIssues, err := s.loadPackages(ctx, repoPath, patterns)
	if err != nil {
		return nil, err
	}
	var warnings []report.Warning
	for _, issue := range loadIssues {
		warnings = append(warnings, report.Warning{Message: issue.Error, Source: "go/packages"})
	}

	coverageByPackage := map[string]float64{}
	coverageErr := ""
	coverageWarnings := []string{}
	if s.CoveragePath != "" {
		profile, err := coverage.ParseProfile(s.CoveragePath)
		if err != nil {
			coverageErr = err.Error()
			warnings = append(warnings, report.Warning{Message: coverageErr, Source: "coverage"})
		} else {
			coverageByPackage = profile.Packages
			coverageWarnings = profile.Warnings
			for _, warning := range profile.Warnings {
				warnings = append(warnings, report.Warning{Message: warning, Source: "coverage"})
			}
		}
	} else {
		warnings = append(warnings, report.Warning{Message: "coverage profile was not supplied; coverage is unknown", Source: "coverage"})
	}

	gitRoot, gitErr := fgit.RepoRoot(ctx, repoPath)
	if gitErr != nil {
		gitRoot = repoPath
		warnings = append(warnings, report.Warning{Message: "git history unavailable; churn and author signals default to zero", Source: "git"})
	} else if fgit.IsShallow(ctx, gitRoot) {
		warnings = append(warnings, report.Warning{Message: "git repository is shallow; churn and author signals may be incomplete", Source: "git"})
	}

	codeownersRoot := repoPath
	codeowners, coErr := ownership.LoadCodeowners(codeownersRoot)
	if codeowners == nil && coErr == nil && gitRoot != repoPath {
		codeownersRoot = gitRoot
		codeowners, coErr = ownership.LoadCodeowners(codeownersRoot)
	}
	if coErr != nil {
		warnings = append(warnings, report.Warning{Message: coErr.Error(), Source: "CODEOWNERS"})
		codeowners = nil
	}
	if codeowners != nil {
		for _, diagnostic := range codeowners.Diagnostics {
			warnings = append(warnings, report.Warning{Message: formatCodeownersDiagnostic(codeownersRoot, codeowners.Path, diagnostic), Source: "CODEOWNERS"})
		}
	}

	reverseImports := computeReverseImports(loaded)
	risks := s.computePackageRisks(ctx, packageRiskContext{
		repoPath:         repoPath,
		loaded:           loaded,
		loadIssues:       loadIssues,
		coverageResolver: newCoverageResolver(coverageByPackage, loaded, repoPath),
		coverageErr:      coverageErr,
		coverageWarnings: coverageWarnings,
		reverseImports:   reverseImports,
		gitRoot:          gitRoot,
		gitErr:           gitErr,
		codeownersRoot:   codeownersRoot,
		codeowners:       codeowners,
		codeownersErr:    coErr,
		multiModule:      len(fmodule.Selected(s.Modules)) > 1,
		coverageSupplied: s.CoveragePath != "",
		coverageUsable:   coverageErr == "",
		codeownersLoaded: codeowners != nil,
	})

	boundaryFindings, boundaryWarnings := policy.EvaluateBoundaries(s.Config, packageFacts(risks))
	warnings = append(warnings, boundaryWarnings...)
	for i := range risks {
		if findings := boundaryFindings[risks[i].ImportPath]; len(findings) > 0 {
			for j := range findings {
				findings[j] = enrichBoundaryFinding(repoPath, codeownersRoot, codeowners, risks[i], findings[j])
			}
			risks[i].Findings = append(risks[i].Findings, findings...)
			sort.SliceStable(risks[i].Findings, func(a, b int) bool {
				return risks[i].Findings[a].ID < risks[i].Findings[b].ID
			})
		}
	}
	var suppressed []report.SuppressedFinding
	var suppressionWarnings []report.Warning
	risks, suppressed, suppressionWarnings = policy.ApplySuppressions(s.Config, risks, time.Now().UTC())
	warnings = append(warnings, suppressionWarnings...)

	dependencyResult := s.analyzeDependencies(ctx, repoPath, loaded, patterns)
	warnings = append(warnings, dependencyResult.Warnings...)

	rep := &report.Report{
		Meta: report.ScanMeta{
			Version:    version.Version,
			Commit:     version.Commit,
			ScanTime:   time.Now().UTC(),
			RepoPath:   repoPath,
			Patterns:   append([]string{}, patterns...),
			BuildTags:  append([]string{}, s.BuildTags...),
			ConfigPath: s.ConfigPath,
			GoWorkPath: s.GoWorkPath,
		},
		Warnings:           warnings,
		ScoringVersion:     scoring.Version,
		ConfigSummary:      s.Config.Summary(),
		SuppressedFindings: suppressed,
		Modules:            append([]report.ModuleInfo{}, s.Modules...),
		Dependencies:       dependencyResult.Dependencies,
		DependencyFindings: dependencyResult.Findings,
		Govulncheck:        dependencyResult.Govulncheck,
		Incidents:          append([]report.SnapshotIncident{}, s.Incidents...),
		Packages:           risks,
		Summary:            report.ComputeSummaryWithDependencies(risks, warnings, dependencyResult.Findings),
	}
	rep.Summary.DependencyCount = len(rep.Dependencies)
	return rep, nil
}

type packageRiskContext struct {
	repoPath         string
	loaded           []LoadedPackage
	loadIssues       []LoadIssue
	coverageResolver coverageResolver
	coverageErr      string
	coverageWarnings []string
	reverseImports   map[string]int
	gitRoot          string
	gitErr           error
	codeownersRoot   string
	codeowners       *ownership.Codeowners
	codeownersErr    error
	multiModule      bool
	coverageSupplied bool
	coverageUsable   bool
	codeownersLoaded bool
}

func (s Scanner) computePackageRisks(ctx context.Context, scan packageRiskContext) []report.PackageRisk {
	risks := make([]report.PackageRisk, 0, len(scan.loaded))
	for _, pkg := range scan.loaded {
		if shouldSkipDir(scan.repoPath, pkg.Dir) || matchesExclude(scan.repoPath, pkg.Dir, s.ExcludeGlobs) {
			continue
		}
		risks = append(risks, s.computePackageRisk(ctx, pkg, scan))
	}
	sort.SliceStable(risks, func(i, j int) bool {
		return risks[i].ImportPath < risks[j].ImportPath
	})
	return risks
}

func (s Scanner) computePackageRisk(ctx context.Context, pkg LoadedPackage, scan packageRiskContext) report.PackageRisk {
	metrics, err := CollectMetrics(pkg.Dir, MetricOptions{IncludeGenerated: s.IncludeGenerated})
	if err != nil {
		metrics.Errors = append(metrics.Errors, err.Error())
	}

	pr := packageRiskFromMetrics(pkg, metrics, scan.repoPath, scan.reverseImports[pkg.ImportPath])
	addPackageLoadErrors(&pr, pkg, scan.loadIssues, metrics.Errors, scan.coverageErr, scan.coverageWarnings, scan.codeownersErr)
	s.addIncidentEvidence(&pr, pkg)
	s.applyCoverage(&pr, pkg, scan)
	authorCounts := applyGitMetrics(ctx, &pr, pkg, scan.gitRoot, scan.gitErr)
	ownerResolution := s.applyOwnership(&pr, pkg, authorCounts, scan)
	s.applyScoring(&pr, ownerResolution, scan)
	return pr
}

func packageRiskFromMetrics(pkg LoadedPackage, metrics Metrics, repoPath string, reverseImportCount int) report.PackageRisk {
	return report.PackageRisk{
		PackageID:             pkg.ID,
		ImportPath:            pkg.ImportPath,
		Dir:                   safeRel(repoPath, pkg.Dir),
		ModulePath:            pkg.ModulePath,
		ModuleRoot:            pkg.ModuleRoot,
		LOC:                   metrics.LOC,
		TestLOC:               metrics.TestLOC,
		TestFileCount:         metrics.TestFileCount,
		HasTestFile:           metrics.HasTestFile,
		TestFuncCount:         metrics.TestFuncCount,
		BenchmarkCount:        metrics.BenchmarkCount,
		FuzzCount:             metrics.FuzzCount,
		ExampleCount:          metrics.ExampleCount,
		TestToCodeRatio:       testToCodeRatio(metrics),
		GeneratedLOC:          metrics.GeneratedLOC,
		FileCount:             metrics.FileCount,
		GeneratedFileCount:    metrics.GeneratedFileCount,
		ImportCount:           len(pkg.Imports),
		ReverseImportCount:    reverseImportCount,
		DirectInternalImports: append([]string{}, pkg.InternalImports...),
		LoadErrors:            append([]string{}, pkg.Errors...),
	}
}

func testToCodeRatio(metrics Metrics) float64 {
	if metrics.LOC == 0 {
		return 0
	}
	return float64(metrics.TestLOC) / float64(metrics.LOC)
}

func addPackageLoadErrors(pr *report.PackageRisk, pkg LoadedPackage, loadIssues []LoadIssue, metricErrors []string, coverageErr string, coverageWarnings []string, codeownersErr error) {
	pr.LoadErrors = append(pr.LoadErrors, metricErrors...)
	if coverageErr != "" {
		pr.LoadErrors = append(pr.LoadErrors, coverageErr)
	}
	pr.LoadErrors = append(pr.LoadErrors, coverageWarnings...)
	if codeownersErr != nil {
		pr.LoadErrors = append(pr.LoadErrors, codeownersErr.Error())
	}
	for _, issue := range loadIssues {
		if issue.PackageID == pkg.ID || issue.ImportPath == pkg.ImportPath {
			pr.LoadErrors = appendUnique(pr.LoadErrors, issue.Error)
		}
	}
}

func (s Scanner) addIncidentEvidence(pr *report.PackageRisk, pkg LoadedPackage) {
	incidentItems := s.IncidentIndex[pkg.ImportPath]
	if len(incidentItems) == 0 {
		return
	}
	ids := make([]string, 0, len(incidentItems))
	for _, inc := range incidentItems {
		if inc.ID != "" {
			ids = append(ids, inc.ID)
		}
	}
	sort.Strings(ids)
	pr.IncidentIDs = ids
	pr.IncidentCount = len(ids)
	for _, id := range ids {
		pr.Evidence = append(pr.Evidence, report.Evidence{Key: "incident_id", Value: id, Source: "incidents"})
	}
}

func (s Scanner) applyCoverage(pr *report.PackageRisk, pkg LoadedPackage, scan packageRiskContext) {
	if match, ok := scan.coverageResolver.ForPackage(pkg); ok {
		v := round2(match.Pct)
		pr.CoveragePct = &v
		pr.Evidence = append(pr.Evidence, report.Evidence{Key: "coverage_pct", Value: fmt.Sprintf("%.2f", v), Source: "coverage"})
		if match.Key != "" {
			pr.Evidence = append(pr.Evidence, report.Evidence{Key: "coverage_key", Value: match.Key, Source: "coverage"})
		}
		return
	}
	if s.CoveragePath != "" && scan.coverageErr == "" {
		pr.Evidence = append(pr.Evidence, report.Evidence{Key: "coverage", Value: "unknown for package", Source: "coverage"})
	}
}

func applyGitMetrics(ctx context.Context, pr *report.PackageRisk, pkg LoadedPackage, gitRoot string, gitErr error) map[string]int {
	authorCounts := map[string]int{}
	if gitErr != nil {
		return authorCounts
	}
	churn, err := fgit.PackageChurn(ctx, gitRoot, pkg.Dir)
	if err == nil {
		pr.Churn30d = churn.Churn30d
		pr.Churn90d = churn.Churn90d
		pr.AuthorCount90d = churn.AuthorCount90d
		pr.Evidence = append(pr.Evidence,
			report.Evidence{Key: "git_window_30d", Value: fgit.Window30d, Source: "git"},
			report.Evidence{Key: "git_window_90d", Value: fgit.Window90d, Source: "git"},
			report.Evidence{Key: "churn_unit", Value: "added+deleted lines", Source: "git"},
		)
	} else {
		pr.LoadErrors = append(pr.LoadErrors, err.Error())
	}
	authorCounts, err = fgit.PackageAuthorCounts(ctx, gitRoot, pkg.Dir)
	if err == nil {
		pr.OwnershipEntropy = round2(ownership.NormalizedEntropy(authorCounts))
	}
	return authorCounts
}

func (s Scanner) applyOwnership(pr *report.PackageRisk, pkg LoadedPackage, authorCounts map[string]int, scan packageRiskContext) ownership.Resolution {
	if scan.codeowners != nil {
		pr.Evidence = append(pr.Evidence, report.Evidence{Key: "codeowners_file", Value: safeRel(scan.codeownersRoot, scan.codeowners.Path), Source: "CODEOWNERS"})
	} else {
		pr.Evidence = append(pr.Evidence, report.Evidence{Key: "codeowners_file", Value: "not found", Source: "CODEOWNERS"})
	}
	resolution := ownership.Resolve(ownership.ResolveInput{
		Config:         s.Config.Owners,
		ModulePath:     pkg.ModulePath,
		ModuleRoot:     pkg.ModuleRoot,
		RepoRoot:       scan.repoPath,
		CodeownersRoot: scan.codeownersRoot,
		PackageDir:     pkg.Dir,
		Codeowners:     scan.codeowners,
		AuthorCounts:   authorCounts,
		MultiModule:    scan.multiModule,
	})
	if resolution.Owner != "" {
		owner := resolution.Owner
		pr.DominantOwner = &owner
	}
	pr.OwnerSource = resolution.Source
	pr.CandidateOwners = append([]report.OwnerCandidate{}, resolution.Candidates...)
	pr.OwnershipConfidence = round2(resolution.Confidence)
	pr.Evidence = append(pr.Evidence, resolution.Evidence...)
	return resolution
}

func (s Scanner) applyScoring(pr *report.PackageRisk, ownerResolution ownership.Resolution, scan packageRiskContext) {
	result := scoring.ScorePackage(*pr, scoring.Options{
		Config:           s.Config,
		CoverageSupplied: scan.coverageSupplied,
		CoverageUsable:   scan.coverageUsable,
		GitAvailable:     scan.gitErr == nil,
		CodeownersUsed:   scan.codeownersLoaded,
	})
	pr.ComplexityScore = result.ComplexityScore
	pr.RiskScore = result.RiskScore
	pr.ScoreBreakdown = result.Breakdown
	pr.Evidence = append(pr.Evidence, result.Evidence...)
	pr.Findings = result.Findings
	pr.Findings = append(pr.Findings, ownershipFindings(*pr, ownerResolution)...)
}

func packageFacts(pkgs []report.PackageRisk) []policy.PackageFacts {
	facts := make([]policy.PackageFacts, 0, len(pkgs))
	for _, pkg := range pkgs {
		facts = append(facts, policy.PackageFacts{
			ImportPath:            pkg.ImportPath,
			Dir:                   pkg.Dir,
			DirectInternalImports: append([]string{}, pkg.DirectInternalImports...),
		})
	}
	return facts
}

func formatCodeownersDiagnostic(root, path string, diagnostic ownership.Diagnostic) string {
	location := safeRel(root, path)
	if diagnostic.Line > 0 {
		location = fmt.Sprintf("%s:%d", location, diagnostic.Line)
	}
	if diagnostic.Pattern != "" {
		return fmt.Sprintf("%s: %s (%s)", location, diagnostic.Message, diagnostic.Pattern)
	}
	return fmt.Sprintf("%s: %s", location, diagnostic.Message)
}

func enrichBoundaryFinding(repoPath, codeownersRoot string, codeowners *ownership.Codeowners, pkg report.PackageRisk, finding report.Finding) report.Finding {
	if finding.ID != "FL-BND-001" {
		return finding
	}
	deniedImport := evidenceValue(finding.Evidence, "matched_import")
	if deniedImport == "" {
		return finding
	}
	pkgDir := filepath.Join(repoPath, filepath.FromSlash(pkg.Dir))
	importFile, importLine, ok := findImportLocation(repoPath, pkgDir, deniedImport)
	if !ok {
		return finding
	}
	finding.Evidence = append(finding.Evidence,
		report.Evidence{Key: "importing_file", Value: importFile, Source: "filesystem"},
		report.Evidence{Key: "importing_line", Value: fmt.Sprintf("%d", importLine), Source: "filesystem"},
	)
	if codeowners == nil {
		return finding
	}
	match := codeowners.ResolveFileOwner(importFile)
	if len(match.Owners) == 0 {
		finding.Evidence = append(finding.Evidence, report.Evidence{Key: "file_owner", Value: "unknown", Source: "CODEOWNERS"})
		return finding
	}
	finding.Evidence = append(finding.Evidence,
		report.Evidence{Key: "file_owner", Value: strings.Join(match.Owners, ","), Source: "CODEOWNERS"},
		report.Evidence{Key: "file_codeowners_file", Value: safeRel(codeownersRoot, match.File), Source: "CODEOWNERS"},
		report.Evidence{Key: "file_codeowners_line", Value: fmt.Sprintf("%d", match.Line), Source: "CODEOWNERS"},
		report.Evidence{Key: "file_codeowners_pattern", Value: match.Pattern, Source: "CODEOWNERS"},
	)
	return finding
}

func findImportLocation(repoRoot, pkgDir, deniedImport string) (string, int, bool) {
	files, err := goFiles(pkgDir)
	if err != nil {
		return "", 0, false
	}
	needle := `"` + deniedImport + `"`
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			if strings.Contains(line, needle) {
				rel, err := filepath.Rel(repoRoot, file)
				if err != nil {
					return filepath.ToSlash(file), i + 1, true
				}
				return filepath.ToSlash(rel), i + 1, true
			}
		}
	}
	return "", 0, false
}

func goFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		files = append(files, filepath.Join(dir, entry.Name()))
	}
	sort.Strings(files)
	return files, nil
}

func ownershipFindings(pkg report.PackageRisk, resolution ownership.Resolution) []report.Finding {
	var findings []report.Finding
	if resolution.DominantGitOwner != "" && len(resolution.CodeownersOwners) > 0 && !containsString(resolution.CodeownersOwners, resolution.DominantGitOwner) {
		findings = append(findings, report.Finding{
			ID:          "FL-OWN-003",
			Category:    report.CategoryOwnership,
			Severity:    report.SeverityMedium,
			Title:       "CODEOWNERS owner differs from dominant git author",
			Description: "The CODEOWNERS owner for this package differs from the dominant recent git author or configured ownership alias.",
			Evidence: []report.Evidence{
				{Key: "codeowners_matched_file", Value: resolution.CodeownersFile, Source: "CODEOWNERS"},
				{Key: "codeowners_matched_line", Value: fmt.Sprintf("%d", resolution.CodeownersLine), Source: "CODEOWNERS"},
				{Key: "codeowners_matched_pattern", Value: resolution.CodeownersPattern, Source: "CODEOWNERS"},
				{Key: "codeowners_owners", Value: strings.Join(resolution.CodeownersOwners, ","), Source: "CODEOWNERS"},
				{Key: "dominant_git_author", Value: resolution.DominantGitAuthor, Source: "git"},
				{Key: "dominant_git_owner", Value: resolution.DominantGitOwner, Source: "ownership"},
				{Key: "dominant_git_share", Value: fmt.Sprintf("%.2f", resolution.DominantGitShare), Source: "git"},
			},
			Recommendation: "Confirm whether CODEOWNERS reflects current stewardship, then update CODEOWNERS or ownership aliases if responsibility moved.",
			Confidence:     0.7,
		})
	}
	if resolution.ModuleOwnerMissing {
		findings = append(findings, report.Finding{
			ID:          "FL-OWN-004",
			Category:    report.CategoryOwnership,
			Severity:    report.SeverityLow,
			Title:       "Module owner missing in multi-module repository",
			Description: "This package belongs to a module without an explicit owners.modules entry in a multi-module repository.",
			Evidence: []report.Evidence{
				{Key: "module_path", Value: pkg.ModulePath, Source: "module"},
				{Key: "module_root", Value: pkg.ModuleRoot, Source: "module"},
			},
			Recommendation: "Add an owners.modules entry for the module so package ownership remains stable across monorepo refactors.",
			Confidence:     0.85,
		})
	}
	return findings
}

func dependencyPackages(pkgs []LoadedPackage) []dependency.PackageImports {
	out := make([]dependency.PackageImports, 0, len(pkgs))
	for _, pkg := range pkgs {
		if strings.TrimSpace(pkg.ImportPath) == "" {
			continue
		}
		out = append(out, dependency.PackageImports{
			ImportPath: pkg.ImportPath,
			Imports:    append([]string{}, pkg.Imports...),
		})
	}
	return out
}

func (s Scanner) loadPackages(ctx context.Context, repoPath string, patterns []string) ([]LoadedPackage, []LoadIssue, error) {
	selected := fmodule.Selected(s.Modules)
	if len(selected) == 0 {
		return LoadPackages(ctx, repoPath, patterns, s.BuildTags)
	}
	var all []LoadedPackage
	var issues []LoadIssue
	for _, mod := range selected {
		root := filepath.Join(repoPath, filepath.FromSlash(mod.ModuleRoot))
		loaded, loadIssues, err := LoadPackagesInDir(ctx, repoPath, root, mod.ModulePath, mod.ModuleRoot, patternsForModule(patterns), s.BuildTags)
		if err != nil {
			return nil, nil, fmt.Errorf("load packages for module %s: %w", mod.ModulePath, err)
		}
		all = append(all, loaded...)
		issues = append(issues, loadIssues...)
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].ModuleRoot != all[j].ModuleRoot {
			return all[i].ModuleRoot < all[j].ModuleRoot
		}
		return all[i].ImportPath < all[j].ImportPath
	})
	return all, issues, nil
}

func patternsForModule(patterns []string) []string {
	if len(patterns) == 0 || (len(patterns) == 1 && patterns[0] == "./...") {
		return []string{"./..."}
	}
	return append([]string{}, patterns...)
}

func (s Scanner) analyzeDependencies(ctx context.Context, repoPath string, loaded []LoadedPackage, patterns []string) dependency.Result {
	selected := fmodule.Selected(s.Modules)
	if len(selected) == 0 {
		return dependency.Analyze(ctx, dependency.Options{
			RepoPath:        repoPath,
			RepoRoot:        repoPath,
			Packages:        dependencyPackages(loaded),
			Govulncheck:     s.Govulncheck,
			GovulncheckArgs: append([]string{}, patterns...),
		})
	}
	byModule := map[string][]dependency.PackageImports{}
	for _, pkg := range loaded {
		byModule[pkg.ModuleRoot] = append(byModule[pkg.ModuleRoot], dependency.PackageImports{
			ImportPath: pkg.ImportPath,
			Imports:    append([]string{}, pkg.Imports...),
		})
	}
	var combined dependency.Result
	for i, mod := range selected {
		root := filepath.Join(repoPath, filepath.FromSlash(mod.ModuleRoot))
		govulncheck := "off"
		if i == 0 {
			govulncheck = s.Govulncheck
		}
		result := dependency.Analyze(ctx, dependency.Options{
			RepoPath:        root,
			RepoRoot:        repoPath,
			Module:          mod,
			AllModules:      append([]report.ModuleInfo{}, s.Modules...),
			Packages:        byModule[mod.ModuleRoot],
			Govulncheck:     govulncheck,
			GovulncheckArgs: append([]string{}, patternsForModule(patterns)...),
		})
		combined.Dependencies = append(combined.Dependencies, result.Dependencies...)
		combined.Findings = append(combined.Findings, result.Findings...)
		combined.Warnings = append(combined.Warnings, result.Warnings...)
		if combined.Govulncheck == nil && result.Govulncheck != nil {
			combined.Govulncheck = result.Govulncheck
		}
	}
	sort.SliceStable(combined.Dependencies, func(i, j int) bool {
		if combined.Dependencies[i].SourceModuleRoot != combined.Dependencies[j].SourceModuleRoot {
			return combined.Dependencies[i].SourceModuleRoot < combined.Dependencies[j].SourceModuleRoot
		}
		return combined.Dependencies[i].ModulePath < combined.Dependencies[j].ModulePath
	})
	sort.SliceStable(combined.Findings, func(i, j int) bool {
		left := findingSortKey(combined.Findings[i])
		right := findingSortKey(combined.Findings[j])
		return left < right
	})
	return combined
}

func findingSortKey(finding report.Finding) string {
	return evidenceValue(finding.Evidence, "source_module_root") + "\x00" + evidenceValue(finding.Evidence, "module_path") + "\x00" + finding.ID
}

func evidenceValue(items []report.Evidence, key string) string {
	for _, item := range items {
		if item.Key == key {
			return item.Value
		}
	}
	return ""
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func containsString(values []string, value string) bool {
	for _, existing := range values {
		if existing == value {
			return true
		}
	}
	return false
}

func computeReverseImports(pkgs []LoadedPackage) map[string]int {
	known := make(map[string]struct{}, len(pkgs))
	for _, pkg := range pkgs {
		known[pkg.ImportPath] = struct{}{}
	}
	reverse := make(map[string]int, len(pkgs))
	for _, pkg := range pkgs {
		for _, imp := range pkg.InternalImports {
			if _, ok := known[imp]; ok {
				reverse[imp]++
			}
		}
	}
	return reverse
}

func matchesExclude(repoPath, dir string, patterns []string) bool {
	if len(patterns) == 0 {
		return false
	}
	rel := safeRel(repoPath, dir)
	rel = filepath.ToSlash(rel)
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(filepath.ToSlash(pattern))
		if pattern == "" {
			continue
		}
		matched, err := path.Match(pattern, rel)
		if err == nil && matched {
			return true
		}
		if strings.HasSuffix(pattern, "/...") {
			prefix := strings.TrimSuffix(pattern, "/...")
			if rel == prefix || strings.HasPrefix(rel, prefix+"/") {
				return true
			}
		}
	}
	return false
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}
