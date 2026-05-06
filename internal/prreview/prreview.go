package prreview

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/faultline-go/faultline/internal/analyzer"
	fmodule "github.com/faultline-go/faultline/internal/module"
	"github.com/faultline-go/faultline/internal/ownership"
	"github.com/faultline-go/faultline/internal/policy"
	"github.com/faultline-go/faultline/internal/report"
	"github.com/faultline-go/faultline/internal/sarif"
	"github.com/faultline-go/faultline/internal/storage"
)

const CommentMarker = "<!-- faultline-pr-review -->"

type Options struct {
	RepoRoot        string
	Base            string
	Head            string
	HeadExplicit    bool
	Repo            string
	PRNumber        string
	CompareMode     string
	Config          policy.Config
	ConfigPath      string
	ConfigWarnings  []report.Warning
	ConfigRulePacks []report.ConfigRulePack
	ConfigHash      string
	CoveragePath    string
	StrictConfig    bool
	CommentOut      string
	SARIFOut        string
	Post            bool
	FailOn          report.Severity
}

type CompareMode string

const (
	CompareModeAuto     CompareMode = "auto"
	CompareModeHistory  CompareMode = "history"
	CompareModeWorktree CompareMode = "worktree"
)

type ScanPathType string

const (
	ScanPathCaller   ScanPathType = "caller"
	ScanPathWorktree ScanPathType = "worktree"
)

type PackageScope string

const (
	ScopeChanged  PackageScope = "CHANGED"
	ScopeImpacted PackageScope = "IMPACTED"
)

type PackageReview struct {
	Package          report.PackageRisk
	Scope            PackageScope
	NewFindings      []report.Finding
	ResolvedFindings []report.Finding
}

type Review struct {
	Base                 string
	Head                 string
	Repo                 string
	PRNumber             string
	CompareModeRequested string
	CompareModeUsed      string
	BaseScanPathType     string
	HeadScanPathType     string
	ConfigHash           string
	ConfigRulePacks      []report.ConfigRulePack
	SARIFOut             string
	FallbackReason       string
	ChangedFiles         []string
	ChangedGoFiles       []string
	ChangedPackages      int
	ImpactedPackages     int
	NewHighFindings      int
	NewBoundaryFindings  int
	WorstDeltaPackage    string
	WorstDelta           *float64
	MatchMethod          string
	Warnings             []string
	ChangedFileOwners    []FileOwnerSummary
	ChangedFilesUnowned  []string
	OwnerMismatches      []FileOwnerSummary
	Packages             []PackageReview
	HeadReport           *report.Report
}

type FileOwnerSummary struct {
	Path              string   `json:"path"`
	Owners            []string `json:"owners,omitempty"`
	CodeownersFile    string   `json:"codeowners_file,omitempty"`
	CodeownersLine    int      `json:"codeowners_line,omitempty"`
	CodeownersPattern string   `json:"codeowners_pattern,omitempty"`
	PackageImportPath string   `json:"package_import_path,omitempty"`
	PackageOwner      string   `json:"package_owner,omitempty"`
	OwnerMismatch     bool     `json:"owner_mismatch,omitempty"`
}

func Run(ctx context.Context, opts Options) (*Review, string, error) {
	repoRoot, err := filepath.Abs(opts.RepoRoot)
	if err != nil {
		return nil, "", fmt.Errorf("resolve repo root: %w", err)
	}
	if opts.Base == "" {
		opts.Base = detectedBase(ctx, repoRoot)
	}
	if opts.Head == "" {
		opts.Head = detectedHead()
	}
	if opts.Repo == "" {
		opts.Repo = os.Getenv("GITHUB_REPOSITORY")
	}
	if opts.PRNumber == "" {
		opts.PRNumber = detectedPRNumber()
	}
	if opts.Config.Version == 0 {
		opts.Config = policy.DefaultConfig()
	}
	mode, err := normalizeCompareMode(opts.CompareMode)
	if err != nil {
		return nil, "", err
	}

	review := &Review{
		Base:                 opts.Base,
		Head:                 opts.Head,
		Repo:                 opts.Repo,
		PRNumber:             opts.PRNumber,
		CompareModeRequested: string(mode),
		SARIFOut:             opts.SARIFOut,
	}
	for _, warning := range opts.ConfigWarnings {
		review.Warnings = append(review.Warnings, fmt.Sprintf("%s: %s", warning.Source, warning.Message))
	}
	headTarget, err := prepareHeadTarget(ctx, repoRoot, opts)
	if err != nil {
		return nil, "", err
	}
	defer headTarget.Cleanup()
	review.HeadScanPathType = string(headTarget.PathType)

	changed, err := ChangedFiles(ctx, repoRoot, opts.Base, opts.Head)
	if err != nil {
		review.Warnings = append(review.Warnings, fmt.Sprintf("changed file detection failed: %v", err))
	}
	review.ChangedFiles = changed
	changedGo, err := ChangedGoFiles(headTarget.Path, changed)
	if err != nil {
		review.Warnings = append(review.Warnings, err.Error())
	}
	review.ChangedGoFiles = changedGo

	loaded, _, err := loadReviewPackages(ctx, headTarget.Path)
	if err != nil {
		return nil, "", fmt.Errorf("load packages for PR review: %w", err)
	}
	scopes := PackageScopes(headTarget.Path, loaded, changedGo)

	rep, err := scanRepo(ctx, headTarget.Path, opts)
	if err != nil {
		return nil, "", err
	}
	review.HeadReport = rep
	for _, warning := range rep.Warnings {
		review.Warnings = append(review.Warnings, fmt.Sprintf("%s: %s", warning.Source, warning.Message))
	}
	if opts.StrictConfig && reportHasWarningSource(rep, "CODEOWNERS") {
		return nil, "", fmt.Errorf("strict config validation failed on CODEOWNERS diagnostics")
	}
	if opts.ConfigHash != "" {
		rep.Meta.ConfigHash = opts.ConfigHash
	} else {
		rep.Meta.ConfigHash = storage.ConfigHash(opts.ConfigPath, opts.Config)
	}
	rep.Meta.RulePacks = append([]report.ConfigRulePack{}, opts.ConfigRulePacks...)
	review.ConfigHash = rep.Meta.ConfigHash
	review.ConfigRulePacks = append([]report.ConfigRulePack{}, opts.ConfigRulePacks...)
	identity := storage.ComputeRepoIdentity(ctx, repoRoot, packageImportPaths(rep))
	rep.Meta.RepoFingerprint = identity.Fingerprint
	rep.Meta.RepoDisplayName = identity.DisplayName
	review.ChangedFileOwners, review.ChangedFilesUnowned, review.OwnerMismatches = changedFileOwnerSummary(headTarget.Path, changed, rep.Packages)

	comparison, err := buildComparison(ctx, repoRoot, opts, mode, rep, identity, review)
	if err != nil {
		return nil, "", err
	}

	for _, pkg := range rep.Packages {
		scope, ok := scopes[pkg.ImportPath]
		if !ok {
			continue
		}
		pr := PackageReview{
			Package:          pkg,
			Scope:            scope,
			NewFindings:      comparison.NewFindings(pkg.ImportPath, pkg.Findings),
			ResolvedFindings: comparison.ResolvedFindings(pkg.ImportPath, pkg.Findings),
		}
		sortFindings(pr.NewFindings)
		sortFindings(pr.ResolvedFindings)
		addNewFindingCounts(review, pr.NewFindings)
		if scope == ScopeChanged {
			review.ChangedPackages++
		} else {
			review.ImpactedPackages++
		}
		if pkg.RiskDelta != nil && (review.WorstDelta == nil || *pkg.RiskDelta > *review.WorstDelta) {
			delta := *pkg.RiskDelta
			review.WorstDelta = &delta
			review.WorstDeltaPackage = pkg.ImportPath
		}
		review.Packages = append(review.Packages, pr)
	}
	sort.SliceStable(review.Packages, func(i, j int) bool {
		if review.Packages[i].Package.RiskScore == review.Packages[j].Package.RiskScore {
			return review.Packages[i].Package.ImportPath < review.Packages[j].Package.ImportPath
		}
		return review.Packages[i].Package.RiskScore > review.Packages[j].Package.RiskScore
	})

	if opts.SARIFOut != "" {
		if err := writePRSARIF(opts.SARIFOut, rep, review); err != nil {
			return review, "", err
		}
	}
	body := RenderMarkdown(review)
	if opts.CommentOut != "" {
		if err := os.WriteFile(opts.CommentOut, []byte(body), 0644); err != nil {
			return review, body, fmt.Errorf("write comment output: %w", err)
		}
	}
	if opts.Post {
		if err := PostReview(ctx, opts.Repo, opts.PRNumber, body); err != nil {
			review.Warnings = append(review.Warnings, fmt.Sprintf("GitHub comment not posted: %v", err))
			body = RenderMarkdown(review)
			if opts.CommentOut != "" {
				if err := os.WriteFile(opts.CommentOut, []byte(body), 0644); err != nil {
					return review, body, fmt.Errorf("write comment output with warning: %w", err)
				}
			}
		}
	}
	return review, body, nil
}

func ChangedFiles(ctx context.Context, repoRoot, base, head string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "git", "diff", "--name-only", base+"..."+head)
	cmd.Dir = repoRoot
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git diff --name-only %s...%s: %w", base, head, err)
	}
	var files []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(filepath.ToSlash(line))
		if line != "" {
			files = append(files, line)
		}
	}
	sort.Strings(files)
	return files, nil
}

func ChangedGoFiles(repoRoot string, files []string) ([]string, error) {
	var out []string
	for _, rel := range files {
		if !strings.HasSuffix(rel, ".go") || skipped(rel) {
			continue
		}
		path := filepath.Join(repoRoot, filepath.FromSlash(rel))
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read changed file %s: %w", rel, err)
		}
		if analyzer.IsGeneratedFile(filepath.Base(path), data) {
			continue
		}
		out = append(out, rel)
	}
	sort.Strings(out)
	return out, nil
}

func PackageScopes(repoRoot string, pkgs []analyzer.LoadedPackage, changedFiles []string) map[string]PackageScope {
	byDir := make(map[string]analyzer.LoadedPackage)
	for _, pkg := range pkgs {
		rel, err := filepath.Rel(repoRoot, pkg.Dir)
		if err != nil {
			continue
		}
		byDir[filepath.ToSlash(rel)] = pkg
	}
	scopes := make(map[string]PackageScope)
	for _, file := range changedFiles {
		dir := filepath.ToSlash(filepath.Dir(file))
		if pkg, ok := byDir[dir]; ok {
			scopes[pkg.ImportPath] = ScopeChanged
		}
	}
	for _, pkg := range pkgs {
		if _, changed := scopes[pkg.ImportPath]; changed {
			continue
		}
		for _, imp := range pkg.InternalImports {
			if scopes[imp] == ScopeChanged {
				scopes[pkg.ImportPath] = ScopeImpacted
				break
			}
		}
	}
	return scopes
}

type scanTarget struct {
	Path     string
	PathType ScanPathType
	cleanup  func()
}

func (t scanTarget) Cleanup() {
	if t.cleanup != nil {
		t.cleanup()
	}
}

func prepareHeadTarget(ctx context.Context, repoRoot string, opts Options) (scanTarget, error) {
	caller := scanTarget{Path: repoRoot, PathType: ScanPathCaller}
	if !opts.HeadExplicit {
		return caller, nil
	}
	same, err := refEqualsCurrentHead(ctx, repoRoot, opts.Head)
	if err != nil {
		return scanTarget{}, fmt.Errorf("resolve explicit head ref %q: %w", opts.Head, err)
	}
	if same {
		return caller, nil
	}
	wt, err := NewTempWorktree(ctx, repoRoot, "head", opts.Head)
	if err != nil {
		return scanTarget{}, fmt.Errorf("create head worktree for %q: %w", opts.Head, err)
	}
	return scanTarget{
		Path:     wt.Path,
		PathType: ScanPathWorktree,
		cleanup: func() {
			_ = wt.Cleanup()
		},
	}, nil
}

type comparisonSource struct {
	mode             CompareMode
	matchMethod      string
	previousFindings map[string]bool
	baseFindings     map[string]map[string]report.Finding
}

func (c comparisonSource) NewFindings(importPath string, current []report.Finding) []report.Finding {
	if c.mode == CompareModeWorktree {
		base := c.baseFindings[importPath]
		var out []report.Finding
		for _, finding := range current {
			if finding.Suppressed {
				continue
			}
			if _, ok := base[storage.FindingKey(importPath, finding)]; !ok {
				out = append(out, finding)
			}
		}
		return out
	}
	var out []report.Finding
	for _, finding := range current {
		if finding.Suppressed {
			continue
		}
		if c.previousFindings[storage.FindingKey(importPath, finding)] {
			continue
		}
		out = append(out, finding)
	}
	return out
}

func (c comparisonSource) ResolvedFindings(importPath string, current []report.Finding) []report.Finding {
	if c.mode != CompareModeWorktree {
		return nil
	}
	currentKeys := findingSet(importPath, current)
	var out []report.Finding
	for key, finding := range c.baseFindings[importPath] {
		if !currentKeys[key] {
			out = append(out, finding)
		}
	}
	return out
}

func buildComparison(ctx context.Context, repoRoot string, opts Options, mode CompareMode, head *report.Report, identity storage.RepoIdentity, review *Review) (comparisonSource, error) {
	switch mode {
	case CompareModeHistory:
		return historyComparison(ctx, repoRoot, identity, head, review)
	case CompareModeWorktree:
		base, err := scanBaseWithWorktree(ctx, repoRoot, opts.Base, opts)
		if err != nil {
			return comparisonSource{}, fmt.Errorf("worktree base comparison: %w", err)
		}
		return worktreeComparison(head, base, review), nil
	case CompareModeAuto:
		if !BaseRefAvailable(ctx, repoRoot, opts.Base) {
			reason := fmt.Sprintf("base ref %q is not available locally", opts.Base)
			review.FallbackReason = reason
			review.Warnings = append(review.Warnings, "worktree comparison unavailable: "+reason+"; falling back to local history")
			return historyComparison(ctx, repoRoot, identity, head, review)
		}
		base, err := scanBaseWithWorktree(ctx, repoRoot, opts.Base, opts)
		if err != nil {
			reason := err.Error()
			review.FallbackReason = reason
			review.Warnings = append(review.Warnings, "worktree comparison failed: "+reason+"; falling back to local history")
			return historyComparison(ctx, repoRoot, identity, head, review)
		}
		return worktreeComparison(head, base, review), nil
	default:
		return comparisonSource{}, fmt.Errorf("unsupported compare mode %q", mode)
	}
}

func historyComparison(ctx context.Context, repoRoot string, identity storage.RepoIdentity, head *report.Report, review *Review) (comparisonSource, error) {
	source := comparisonSource{
		mode:             CompareModeHistory,
		matchMethod:      string(storage.HistoryMatchNone),
		previousFindings: map[string]bool{},
	}
	store, err := storage.Open(storage.DefaultPath(repoRoot))
	if err != nil {
		review.Warnings = append(review.Warnings, fmt.Sprintf("history unavailable: %v", err))
		review.CompareModeUsed = string(CompareModeHistory)
		review.BaseScanPathType = string(ScanPathCaller)
		review.MatchMethod = source.matchMethod
		head.Meta.HistoryMatchMethod = source.matchMethod
		return source, nil
	}
	defer store.Close()

	previousScores, method, err := store.PreviousPackageScores(ctx, identity)
	if err != nil {
		review.Warnings = append(review.Warnings, fmt.Sprintf("history score comparison unavailable: %v", err))
	} else {
		source.matchMethod = string(method)
		storage.ApplyTrends(head, previousScores)
	}
	keys, _, err := store.PreviousFindingKeys(ctx, identity)
	if err != nil {
		review.Warnings = append(review.Warnings, fmt.Sprintf("history finding comparison unavailable: %v", err))
	} else {
		source.previousFindings = keys
	}
	review.CompareModeUsed = string(CompareModeHistory)
	review.BaseScanPathType = string(ScanPathCaller)
	review.MatchMethod = source.matchMethod
	head.Meta.HistoryMatchMethod = source.matchMethod
	return source, nil
}

func worktreeComparison(head, base *report.Report, review *Review) comparisonSource {
	baseScores := make(map[string]float64, len(base.Packages))
	for _, pkg := range base.Packages {
		baseScores[pkg.ImportPath] = pkg.RiskScore
	}
	storage.ApplyTrends(head, baseScores)
	source := comparisonSource{
		mode:         CompareModeWorktree,
		matchMethod:  string(CompareModeWorktree),
		baseFindings: findingMap(base.Packages),
	}
	review.CompareModeUsed = string(CompareModeWorktree)
	review.BaseScanPathType = string(ScanPathWorktree)
	review.MatchMethod = string(CompareModeWorktree)
	head.Meta.HistoryMatchMethod = string(CompareModeWorktree)
	return source
}

func scanRepo(ctx context.Context, repoRoot string, opts Options) (*report.Report, error) {
	modules, goWork := reviewModules(repoRoot)
	scanner := analyzer.Scanner{
		RepoPath:     repoRoot,
		Config:       opts.Config,
		ConfigPath:   opts.ConfigPath,
		CoveragePath: opts.CoveragePath,
		Modules:      modules,
		GoWorkPath:   goWork,
	}
	return scanner.Scan(ctx, []string{"./..."})
}

func changedFileOwnerSummary(repoRoot string, changedFiles []string, packages []report.PackageRisk) ([]FileOwnerSummary, []string, []FileOwnerSummary) {
	codeowners, err := ownership.LoadCodeowners(repoRoot)
	if err != nil || codeowners == nil {
		return nil, nil, nil
	}
	var owned []FileOwnerSummary
	var unowned []string
	var mismatches []FileOwnerSummary
	for _, file := range changedFiles {
		file = filepath.ToSlash(strings.TrimSpace(file))
		if file == "" || skipped(file) {
			continue
		}
		if _, err := os.Stat(filepath.Join(repoRoot, filepath.FromSlash(file))); os.IsNotExist(err) {
			continue
		}
		match := codeowners.ResolveFileOwner(file)
		if len(match.Owners) == 0 {
			unowned = append(unowned, file)
			continue
		}
		summary := FileOwnerSummary{
			Path:              file,
			Owners:            append([]string{}, match.Owners...),
			CodeownersFile:    relPath(repoRoot, match.File),
			CodeownersLine:    match.Line,
			CodeownersPattern: match.Pattern,
		}
		if pkg, ok := packageForFile(packages, file); ok {
			summary.PackageImportPath = pkg.ImportPath
			if pkg.DominantOwner != nil {
				summary.PackageOwner = *pkg.DominantOwner
				summary.OwnerMismatch = !containsOwner(summary.Owners, summary.PackageOwner)
			}
		}
		owned = append(owned, summary)
		if summary.OwnerMismatch {
			mismatches = append(mismatches, summary)
		}
	}
	sortFileOwnerSummaries(owned)
	sort.Strings(unowned)
	sortFileOwnerSummaries(mismatches)
	return owned, unowned, mismatches
}

func packageForFile(packages []report.PackageRisk, file string) (report.PackageRisk, bool) {
	dir := filepath.ToSlash(filepath.Dir(file))
	var best report.PackageRisk
	bestLen := -1
	for _, pkg := range packages {
		pkgDir := filepath.ToSlash(pkg.Dir)
		if pkgDir == "." {
			pkgDir = ""
		}
		matches := dir == pkgDir || (pkgDir != "" && strings.HasPrefix(dir, pkgDir+"/"))
		if !matches {
			continue
		}
		if len(pkgDir) > bestLen {
			best = pkg
			bestLen = len(pkgDir)
		}
	}
	return best, bestLen >= 0
}

func containsOwner(owners []string, owner string) bool {
	for _, candidate := range owners {
		if candidate == owner {
			return true
		}
	}
	return false
}

func sortFileOwnerSummaries(items []FileOwnerSummary) {
	sort.SliceStable(items, func(i, j int) bool {
		return items[i].Path < items[j].Path
	})
}

func relPath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}

func reportHasWarningSource(rep *report.Report, source string) bool {
	for _, warning := range rep.Warnings {
		if warning.Source == source {
			return true
		}
	}
	return false
}

func loadReviewPackages(ctx context.Context, repoRoot string) ([]analyzer.LoadedPackage, []analyzer.LoadIssue, error) {
	modules, _ := reviewModules(repoRoot)
	selected := fmodule.Selected(modules)
	if len(selected) == 0 {
		return analyzer.LoadPackages(ctx, repoRoot, []string{"./..."}, nil)
	}
	var all []analyzer.LoadedPackage
	var issues []analyzer.LoadIssue
	for _, mod := range selected {
		root := filepath.Join(repoRoot, filepath.FromSlash(mod.ModuleRoot))
		loaded, loadIssues, err := analyzer.LoadPackagesInDir(ctx, repoRoot, root, mod.ModulePath, mod.ModuleRoot, []string{"./..."}, nil)
		if err != nil {
			return nil, nil, err
		}
		all = append(all, loaded...)
		issues = append(issues, loadIssues...)
	}
	return all, issues, nil
}

func reviewModules(repoRoot string) ([]report.ModuleInfo, string) {
	discovery, err := fmodule.Discover(repoRoot)
	if err != nil {
		return nil, ""
	}
	modules, _ := fmodule.Select(discovery, fmodule.SelectionOptions{CWD: repoRoot, AllModules: true})
	return modules, discovery.GoWork
}

func scanBaseWithWorktree(ctx context.Context, repoRoot, baseRef string, opts Options) (*report.Report, error) {
	var baseReport *report.Report
	err := WithRefWorktree(ctx, repoRoot, "base", baseRef, func(worktreePath string) error {
		rep, err := scanRepo(ctx, worktreePath, opts)
		if err != nil {
			return err
		}
		baseReport = rep
		return nil
	})
	if err != nil {
		return nil, err
	}
	return baseReport, nil
}

func WithBaseWorktree(ctx context.Context, repoRoot, baseRef string, fn func(worktreePath string) error) error {
	return WithRefWorktree(ctx, repoRoot, "base", baseRef, fn)
}

func WithRefWorktree(ctx context.Context, repoRoot, label, ref string, fn func(worktreePath string) error) error {
	wt, err := NewTempWorktree(ctx, repoRoot, label, ref)
	if err != nil {
		return err
	}
	defer func() {
		_ = wt.Cleanup()
	}()
	if err := fn(wt.Path); err != nil {
		return fmt.Errorf("scan %s worktree: %w", label, err)
	}
	return nil
}

type TempWorktree struct {
	RepoRoot string
	Parent   string
	Path     string
	Ref      string
	Added    bool
}

func NewTempWorktree(ctx context.Context, repoRoot, label, ref string) (*TempWorktree, error) {
	label = safeWorktreeLabel(label)
	resolvedRef, err := commitForRef(ctx, repoRoot, ref)
	if err != nil {
		return nil, err
	}
	parent, err := os.MkdirTemp("", "faultline-"+label+"-*")
	if err != nil {
		return nil, fmt.Errorf("create temporary %s worktree parent: %w", label, err)
	}
	wt := &TempWorktree{
		RepoRoot: repoRoot,
		Parent:   parent,
		Path:     filepath.Join(parent, label),
		Ref:      ref,
	}
	if err := addWorktree(ctx, repoRoot, wt.Path, resolvedRef); err != nil {
		_ = os.RemoveAll(parent)
		return nil, err
	}
	wt.Added = true
	return wt, nil
}

func (w *TempWorktree) Cleanup() error {
	if w == nil {
		return nil
	}
	var removeErr error
	if w.Added && w.Path != "" && !samePath(w.Path, w.RepoRoot) {
		removeErr = removeWorktree(context.Background(), w.RepoRoot, w.Path)
	}
	if w.Parent != "" && !samePath(w.Parent, w.RepoRoot) {
		if err := os.RemoveAll(w.Parent); removeErr == nil && err != nil {
			removeErr = err
		}
	}
	w.Added = false
	return removeErr
}

func addWorktree(ctx context.Context, repoRoot, worktreePath, baseRef string) error {
	cmd := exec.CommandContext(ctx, "git", worktreeAddArgs(worktreePath, baseRef)...)
	cmd.Dir = repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git worktree add %s %s: %w: %s", worktreePath, baseRef, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func removeWorktree(ctx context.Context, repoRoot, worktreePath string) error {
	cmd := exec.CommandContext(ctx, "git", worktreeRemoveArgs(worktreePath)...)
	cmd.Dir = repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git worktree remove %s: %w: %s", worktreePath, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func worktreeAddArgs(worktreePath, baseRef string) []string {
	return []string{"worktree", "add", "--detach", worktreePath, baseRef}
}

func worktreeRemoveArgs(worktreePath string) []string {
	return []string{"worktree", "remove", "--force", worktreePath}
}

func BaseRefAvailable(ctx context.Context, repoRoot, baseRef string) bool {
	_, err := commitForRef(ctx, repoRoot, baseRef)
	return err == nil
}

func refEqualsCurrentHead(ctx context.Context, repoRoot, ref string) (bool, error) {
	want, err := commitForRef(ctx, repoRoot, ref)
	if err != nil {
		return false, err
	}
	head, err := commitForRef(ctx, repoRoot, "HEAD")
	if err != nil {
		return false, err
	}
	return want == head, nil
}

func commitForRef(ctx context.Context, repoRoot, ref string) (string, error) {
	var lastErr error
	for _, candidate := range refCandidates(ref) {
		cmd := exec.CommandContext(ctx, "git", "rev-parse", "--verify", candidate+"^{commit}")
		cmd.Dir = repoRoot
		out, err := cmd.CombinedOutput()
		if err == nil {
			return strings.TrimSpace(string(out)), nil
		}
		lastErr = fmt.Errorf("git rev-parse --verify %s^{commit}: %w: %s", candidate, err, strings.TrimSpace(string(out)))
	}
	return "", lastErr
}

func refCandidates(ref string) []string {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "refs/") {
		return []string{ref}
	}
	candidates := []string{ref}
	candidates = append(candidates, "refs/heads/"+ref)
	candidates = append(candidates, "refs/remotes/"+ref)
	if strings.HasPrefix(ref, "origin/") {
		candidates = append(candidates, "refs/remotes/"+ref)
	}
	return candidates
}

func safeWorktreeLabel(label string) string {
	label = strings.ToLower(strings.TrimSpace(label))
	if label == "" {
		return "ref"
	}
	var b strings.Builder
	for _, r := range label {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "ref"
	}
	return b.String()
}

func samePath(a, b string) bool {
	absA, errA := filepath.Abs(a)
	absB, errB := filepath.Abs(b)
	if errA != nil || errB != nil {
		return filepath.Clean(a) == filepath.Clean(b)
	}
	return absA == absB
}

func findingMap(pkgs []report.PackageRisk) map[string]map[string]report.Finding {
	out := make(map[string]map[string]report.Finding, len(pkgs))
	for _, pkg := range pkgs {
		out[pkg.ImportPath] = findingDetails(pkg.ImportPath, pkg.Findings)
	}
	return out
}

func findingDetails(importPath string, findings []report.Finding) map[string]report.Finding {
	out := make(map[string]report.Finding)
	for _, finding := range findings {
		if finding.Suppressed {
			continue
		}
		out[storage.FindingKey(importPath, finding)] = finding
	}
	return out
}

func findingSet(importPath string, findings []report.Finding) map[string]bool {
	out := make(map[string]bool)
	for _, finding := range findings {
		if finding.Suppressed {
			continue
		}
		out[storage.FindingKey(importPath, finding)] = true
	}
	return out
}

func addNewFindingCounts(review *Review, findings []report.Finding) {
	for _, finding := range findings {
		if finding.Severity == report.SeverityHigh || finding.Severity == report.SeverityCritical {
			review.NewHighFindings++
		}
		if finding.ID == "FL-BND-001" {
			review.NewBoundaryFindings++
		}
	}
}

func sortFindings(findings []report.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].ID != findings[j].ID {
			return findings[i].ID < findings[j].ID
		}
		return findings[i].Title < findings[j].Title
	})
}

func writePRSARIF(path string, head *report.Report, review *Review) error {
	if err := ensureOutputDir(path); err != nil {
		return err
	}
	rep := prSARIFReport(head, review)
	return sarif.WriteFileWithOptions(path, rep, sarif.Options{Properties: prSARIFProperties(review)})
}

func prSARIFReport(head *report.Report, review *Review) *report.Report {
	out := *head
	out.Packages = nil
	for _, prpkg := range review.Packages {
		if len(prpkg.NewFindings) == 0 {
			continue
		}
		pkg := prpkg.Package
		pkg.Findings = append([]report.Finding{}, prpkg.NewFindings...)
		out.Packages = append(out.Packages, pkg)
	}
	out.SuppressedFindings = nil
	out.Summary = report.ComputeSummary(out.Packages, nil)
	return &out
}

func prSARIFProperties(review *Review) map[string]string {
	return map[string]string{
		"faultline.pr.base_ref":                review.Base,
		"faultline.pr.changed_package_count":   strconv.Itoa(review.ChangedPackages),
		"faultline.pr.compare_mode":            review.CompareModeUsed,
		"faultline.pr.compare_mode_requested":  review.CompareModeRequested,
		"faultline.pr.head_ref":                review.Head,
		"faultline.pr.impacted_package_count":  strconv.Itoa(review.ImpactedPackages),
		"faultline.pr.new_boundary_violations": strconv.Itoa(review.NewBoundaryFindings),
		"faultline.pr.new_high_findings":       strconv.Itoa(review.NewHighFindings),
	}
}

func ensureOutputDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create SARIF output directory: %w", err)
	}
	return nil
}

func RenderMarkdown(review *Review) string {
	var b strings.Builder
	b.WriteString(CommentMarker + "\n")
	b.WriteString("# Faultline PR Risk Review\n\n")
	b.WriteString("Summary:\n")
	fmt.Fprintf(&b, "- Changed packages: %d\n", review.ChangedPackages)
	fmt.Fprintf(&b, "- Impacted packages: %d\n", review.ImpactedPackages)
	fmt.Fprintf(&b, "- New HIGH findings: %d\n", review.NewHighFindings)
	fmt.Fprintf(&b, "- New boundary violations: %d\n", review.NewBoundaryFindings)
	if review.WorstDelta != nil {
		fmt.Fprintf(&b, "- Worst delta: %s %+0.0f\n", review.WorstDeltaPackage, *review.WorstDelta)
	} else {
		b.WriteString("- Worst delta: n/a\n")
	}
	if len(review.Warnings) > 0 {
		for _, warning := range review.Warnings {
			fmt.Fprintf(&b, "- Warning: %s\n", warning)
		}
	}
	if review.SARIFOut != "" {
		b.WriteString("- Inline annotations available via uploaded SARIF.\n")
	}
	if len(review.ChangedFileOwners) > 0 || len(review.ChangedFilesUnowned) > 0 {
		fmt.Fprintf(&b, "- Changed files with CODEOWNERS owners: %d\n", len(review.ChangedFileOwners))
		fmt.Fprintf(&b, "- Changed files without CODEOWNERS owners: %d\n", len(review.ChangedFilesUnowned))
	}
	b.WriteString("\n## Highest Risk Changes\n\n")
	b.WriteString("| Package | Scope | Risk | Delta | Findings |\n")
	b.WriteString("|--------|------|------|------|---------|\n")
	limit := min(len(review.Packages), 10)
	for _, pkg := range review.Packages[:limit] {
		fmt.Fprintf(&b, "| `%s` | %s | %.2f | %s | %s |\n", pkg.Package.ImportPath, pkg.Scope, pkg.Package.RiskScore, formatDelta(pkg.Package.RiskDelta), findingList(pkg.NewFindings))
	}
	if limit == 0 {
		b.WriteString("| n/a | n/a | n/a | n/a | No changed Go packages detected |\n")
	}
	b.WriteString("\n## New Findings\n")
	newCount := 0
	for _, pkg := range review.Packages {
		for _, finding := range pkg.NewFindings {
			fmt.Fprintf(&b, "- %s `%s` %s\n", finding.ID, pkg.Package.ImportPath, finding.Title)
			if summary := codeownersEvidenceSummary(finding.Evidence); summary != "" {
				fmt.Fprintf(&b, "  - CODEOWNERS: %s\n", summary)
			}
			newCount++
		}
	}
	if newCount == 0 {
		b.WriteString("- No new unsuppressed findings detected for changed or impacted packages.\n")
	}
	resolvedCount := 0
	for _, pkg := range review.Packages {
		resolvedCount += len(pkg.ResolvedFindings)
	}
	if resolvedCount > 0 {
		b.WriteString("\n## Resolved Findings\n")
		for _, pkg := range review.Packages {
			for _, finding := range pkg.ResolvedFindings {
				fmt.Fprintf(&b, "- %s `%s` %s\n", finding.ID, pkg.Package.ImportPath, finding.Title)
			}
		}
	}
	if len(review.ChangedFileOwners) > 0 || len(review.ChangedFilesUnowned) > 0 {
		b.WriteString("\n## Changed File Owners\n")
		if len(review.ChangedFileOwners) > 0 {
			b.WriteString("\n| File | CODEOWNERS owner(s) | Rule | Package owner |\n")
			b.WriteString("|---|---|---|---|\n")
			for _, item := range review.ChangedFileOwners {
				mismatch := ""
				if item.OwnerMismatch {
					mismatch = " mismatch"
				}
				fmt.Fprintf(&b, "| `%s` | `%s` | `%s:%d %s` | `%s`%s |\n", item.Path, strings.Join(item.Owners, ", "), item.CodeownersFile, item.CodeownersLine, item.CodeownersPattern, valueOrNA(item.PackageOwner), mismatch)
			}
		}
		if len(review.ChangedFilesUnowned) > 0 {
			b.WriteString("\nChanged files without CODEOWNERS owners:\n")
			for _, file := range review.ChangedFilesUnowned {
				fmt.Fprintf(&b, "- `%s`\n", file)
			}
		}
	}
	b.WriteString("\n## Reviewer Guidance\n")
	guidance := reviewerGuidance(review)
	for _, item := range guidance {
		fmt.Fprintf(&b, "- %s\n", item)
	}
	b.WriteString("\n## Method\n")
	fmt.Fprintf(&b, "- Compare mode requested: %s\n", review.CompareModeRequested)
	fmt.Fprintf(&b, "- Compare mode used: %s\n", review.CompareModeUsed)
	fmt.Fprintf(&b, "- Base scan path type: %s\n", review.BaseScanPathType)
	fmt.Fprintf(&b, "- Head scan path type: %s\n", review.HeadScanPathType)
	fmt.Fprintf(&b, "- Base ref: `%s`\n", review.Base)
	fmt.Fprintf(&b, "- Head ref: `%s`\n", review.Head)
	fmt.Fprintf(&b, "- Config hash: `%s`\n", review.ConfigHash)
	if len(review.ConfigRulePacks) > 0 {
		b.WriteString("- Rule packs:\n")
		for _, pack := range review.ConfigRulePacks {
			fmt.Fprintf(&b, "  - `%s` `%s`\n", pack.Path, pack.ContentHash)
		}
	}
	if review.FallbackReason != "" {
		fmt.Fprintf(&b, "- Fallback reason: %s\n", review.FallbackReason)
	}
	fmt.Fprintf(&b, "- Match method: %s\n", review.MatchMethod)
	return b.String()
}

func PostReview(ctx context.Context, repo, prNumber, body string) error {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return fmt.Errorf("GITHUB_TOKEN is not set")
	}
	if repo == "" || prNumber == "" {
		return fmt.Errorf("GitHub repo and PR number are required")
	}
	client := &http.Client{Timeout: 15 * time.Second}
	baseURL := "https://api.github.com/repos/" + repo + "/issues/" + prNumber + "/comments"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
	if err != nil {
		return err
	}
	addGitHubHeaders(req, token)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("list comments failed: %s %s", resp.Status, strings.TrimSpace(string(data)))
	}
	var comments []struct {
		ID   int64  `json:"id"`
		Body string `json:"body"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&comments); err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]string{"body": body})
	for _, comment := range comments {
		if strings.Contains(comment.Body, CommentMarker) {
			patchURL := "https://api.github.com/repos/" + repo + "/issues/comments/" + strconv.FormatInt(comment.ID, 10)
			req, err := http.NewRequestWithContext(ctx, http.MethodPatch, patchURL, bytes.NewReader(payload))
			if err != nil {
				return err
			}
			addGitHubHeaders(req, token)
			req.Header.Set("Content-Type", "application/json")
			return checkGitHubResponse(client.Do(req))
		}
	}
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, baseURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	addGitHubHeaders(req, token)
	req.Header.Set("Content-Type", "application/json")
	return checkGitHubResponse(client.Do(req))
}

func HasFailingNewFinding(review *Review, threshold report.Severity) bool {
	for _, pkg := range review.Packages {
		for _, finding := range pkg.NewFindings {
			if severityRank(finding.Severity) >= severityRank(threshold) {
				return true
			}
		}
	}
	return false
}

func detectedBase(ctx context.Context, repoRoot string) string {
	if base := os.Getenv("GITHUB_BASE_REF"); base != "" {
		return "origin/" + base
	}
	if out := gitOutput(ctx, repoRoot, "symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD"); out != "" {
		return out
	}
	return "origin/main"
}

func detectedHead() string {
	if sha := os.Getenv("GITHUB_SHA"); sha != "" {
		return sha
	}
	return "HEAD"
}

func detectedPRNumber() string {
	if ref := os.Getenv("GITHUB_REF"); strings.HasPrefix(ref, "refs/pull/") {
		parts := strings.Split(ref, "/")
		if len(parts) >= 3 {
			return parts[2]
		}
	}
	return ""
}

func gitOutput(ctx context.Context, repoRoot string, args ...string) string {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = repoRoot
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func skipped(rel string) bool {
	for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
		switch part {
		case "vendor", "third_party", ".git", "node_modules":
			return true
		}
	}
	return false
}

func packageImportPaths(rep *report.Report) []string {
	out := make([]string, 0, len(rep.Packages))
	for _, pkg := range rep.Packages {
		out = append(out, pkg.ImportPath)
	}
	return out
}

func findingList(findings []report.Finding) string {
	if len(findings) == 0 {
		return "none"
	}
	ids := make([]string, 0, len(findings))
	for _, finding := range findings {
		ids = append(ids, finding.ID)
	}
	sort.Strings(ids)
	return strings.Join(ids, ", ")
}

func codeownersEvidenceSummary(evidence []report.Evidence) string {
	values := map[string]string{}
	for _, item := range evidence {
		switch item.Key {
		case "codeowners_matched_file", "codeowners_matched_line", "codeowners_matched_pattern", "codeowners_matched_owners", "codeowners_owners":
			values[item.Key] = item.Value
		}
	}
	file := values["codeowners_matched_file"]
	line := values["codeowners_matched_line"]
	pattern := values["codeowners_matched_pattern"]
	owners := values["codeowners_matched_owners"]
	if owners == "" {
		owners = values["codeowners_owners"]
	}
	if file == "" && pattern == "" && owners == "" {
		return ""
	}
	var parts []string
	if file != "" {
		if line != "" {
			parts = append(parts, file+":"+line)
		} else {
			parts = append(parts, file)
		}
	}
	if pattern != "" {
		parts = append(parts, "pattern `"+pattern+"`")
	}
	if owners != "" {
		parts = append(parts, "owners `"+owners+"`")
	}
	return strings.Join(parts, ", ")
}

func reviewerGuidance(review *Review) []string {
	seen := make(map[string]bool)
	var out []string
	if owners := reviewFileOwners(review); len(owners) > 0 {
		item := "Request review from CODEOWNERS owner(s): " + strings.Join(owners, ", ")
		seen[item] = true
		out = append(out, item)
	}
	for _, pkg := range review.Packages {
		for _, finding := range pkg.NewFindings {
			var item string
			switch finding.ID {
			case "FL-OWN-001", "FL-OWN-002", "FL-OWN-003", "FL-OWN-004":
				item = "Require owner review for " + pkg.Package.ImportPath
			case "FL-COV-001", "FL-COV-002", "FL-CHURN-001", "FL-TST-001", "FL-TST-002":
				item = "Add or update tests for " + pkg.Package.ImportPath
			case "FL-BND-001", "FL-DEP-001":
				item = "Check dependency boundary changes in " + pkg.Package.ImportPath
			}
			if item != "" && !seen[item] {
				seen[item] = true
				out = append(out, item)
			}
		}
	}
	if len(out) == 0 {
		return []string{"Review changed packages for ownership, coverage, and dependency boundary impact."}
	}
	sort.Strings(out)
	return out
}

func reviewFileOwners(review *Review) []string {
	seen := map[string]bool{}
	var owners []string
	for _, item := range review.ChangedFileOwners {
		for _, owner := range item.Owners {
			if !seen[owner] {
				seen[owner] = true
				owners = append(owners, owner)
			}
		}
	}
	sort.Strings(owners)
	return owners
}

func valueOrNA(value string) string {
	if value == "" {
		return "n/a"
	}
	return value
}

func formatDelta(v *float64) string {
	if v == nil {
		return "n/a"
	}
	return fmt.Sprintf("%+.2f", *v)
}

func checkGitHubResponse(resp *http.Response, err error) error {
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("GitHub API failed: %s %s", resp.Status, strings.TrimSpace(string(data)))
	}
	return nil
}

func addGitHubHeaders(req *http.Request, token string) {
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "faultline")
}

func severityRank(s report.Severity) int {
	switch s {
	case report.SeverityCritical:
		return 4
	case report.SeverityHigh:
		return 3
	case report.SeverityMedium:
		return 2
	case report.SeverityLow, report.SeverityInfo:
		return 1
	default:
		return 0
	}
}

func normalizeCompareMode(value string) (CompareMode, error) {
	switch CompareMode(strings.ToLower(strings.TrimSpace(value))) {
	case "", CompareModeAuto:
		return CompareModeAuto, nil
	case CompareModeHistory:
		return CompareModeHistory, nil
	case CompareModeWorktree:
		return CompareModeWorktree, nil
	default:
		return "", fmt.Errorf("invalid compare mode %q: expected auto, history, or worktree", value)
	}
}
