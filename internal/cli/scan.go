package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/faultline-go/faultline/internal/analyzer"
	fgit "github.com/faultline-go/faultline/internal/git"
	fmodule "github.com/faultline-go/faultline/internal/module"
	"github.com/faultline-go/faultline/internal/policy"
	"github.com/faultline-go/faultline/internal/report"
	"github.com/faultline-go/faultline/internal/sarif"
	"github.com/faultline-go/faultline/internal/storage"
	"github.com/spf13/cobra"
)

type scanOptions struct {
	format                 string
	out                    string
	coverage               string
	config                 string
	tags                   string
	failOn                 string
	includeGenerated       bool
	excludes               []string
	noHistory              bool
	strictConfig           bool
	allowConfigOutsideRepo bool
	govulncheck            string
	modules                []string
	allModules             bool
	ignoreModules          []string
	verbose                bool
}

type ExitError struct {
	Code int
	Err  error
}

func (e ExitError) Error() string { return e.Err.Error() }
func (e ExitError) Unwrap() error { return e.Err }

func newScanCommand() *cobra.Command {
	var opts scanOptions

	cmd := &cobra.Command{
		Use:   "scan [patterns...]",
		Short: "Scan Go packages and write a risk report",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				args = []string{"./..."}
			}
			return runScan(cmd, opts, args)
		},
	}
	cmd.Flags().StringVar(&opts.format, "format", "html", "report format: html, json, or sarif")
	cmd.Flags().StringVar(&opts.out, "out", "faultline-report.html", "output report path")
	cmd.Flags().StringVar(&opts.coverage, "coverage", "", "optional Go coverage profile")
	cmd.Flags().StringVar(&opts.config, "config", "", "optional faultline.yaml path")
	cmd.Flags().StringVar(&opts.tags, "tags", "", "comma-separated Go build tags")
	cmd.Flags().StringVar(&opts.failOn, "fail-on", "none", "exit non-zero on findings at threshold: none, high, or critical")
	cmd.Flags().BoolVar(&opts.includeGenerated, "include-generated", false, "include generated code LOC in complexity scoring")
	cmd.Flags().StringArrayVar(&opts.excludes, "exclude", nil, "exclude package directories matching a repo-relative glob; repeatable")
	cmd.Flags().BoolVar(&opts.noHistory, "no-history", false, "disable local scan history persistence and trend comparison")
	cmd.Flags().BoolVar(&opts.strictConfig, "strict-config", false, "fail on config validation warnings or errors")
	cmd.Flags().BoolVar(&opts.allowConfigOutsideRepo, "allow-config-outside-repo", false, "allow rule pack paths outside the repository root")
	cmd.Flags().StringVar(&opts.govulncheck, "govulncheck", "off", "optional govulncheck mode: off, auto, or path to govulncheck binary")
	cmd.Flags().StringArrayVar(&opts.modules, "module", nil, "scan only a module path or module root; repeatable")
	cmd.Flags().BoolVar(&opts.allModules, "all-modules", false, "scan all discovered modules when running from inside one module")
	cmd.Flags().StringArrayVar(&opts.ignoreModules, "ignore-module", nil, "ignore a module path or module root; repeatable")
	cmd.Flags().BoolVar(&opts.verbose, "verbose", false, "print scan progress")
	return cmd
}

func runScan(cmd *cobra.Command, opts scanOptions, patterns []string) error {
	format := strings.ToLower(strings.TrimSpace(opts.format))
	if format != "html" && format != "json" && format != "sarif" {
		return ExitError{Code: 2, Err: fmt.Errorf("unsupported format %q: expected html, json, or sarif", opts.format)}
	}
	failOn, err := parseFailOn(opts.failOn)
	if err != nil {
		return ExitError{Code: 2, Err: err}
	}

	rep, err := buildScanReport(cmd, opts, patterns)
	if err != nil {
		return ExitError{Code: 2, Err: err}
	}

	if opts.out == "" {
		return ExitError{Code: 2, Err: fmt.Errorf("--out is required")}
	}
	if err := os.MkdirAll(filepath.Dir(opts.out), 0755); err != nil && filepath.Dir(opts.out) != "." {
		return ExitError{Code: 2, Err: fmt.Errorf("create output directory: %w", err)}
	}

	switch format {
	case "json":
		if err := report.WriteJSONFile(opts.out, rep); err != nil {
			return ExitError{Code: 2, Err: err}
		}
	case "html":
		if err := report.WriteHTMLFile(opts.out, rep); err != nil {
			return ExitError{Code: 2, Err: err}
		}
	case "sarif":
		if err := sarif.WriteFile(opts.out, rep); err != nil {
			return ExitError{Code: 2, Err: err}
		}
	}
	if opts.verbose {
		fmt.Fprintf(cmd.ErrOrStderr(), "wrote %s report to %s\n", format, opts.out)
	}
	if failOn != "" && report.HasFindingAtOrAbove(rep.Packages, report.Severity(failOn), rep.DependencyFindings) {
		return ExitError{Code: 1, Err: fmt.Errorf("scan completed with findings at or above %s", strings.ToLower(failOn))}
	}
	return nil
}

func buildScanReport(cmd *cobra.Command, opts scanOptions, patterns []string) (*report.Report, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("get working directory: %w", err)
	}
	repoPath := cwd
	if gitRoot, err := fgit.RepoRoot(cmd.Context(), cwd); err == nil && gitRoot != "" {
		repoPath = gitRoot
	}
	scanRoot := repoPath
	if cwd != repoPath && !opts.allModules && len(opts.modules) == 0 {
		scanRoot = cwd
	}

	cfg := policy.DefaultConfig()
	configPath := opts.config
	var configWarnings []report.Warning
	var validation policy.ValidationReport
	if configPath != "" {
		loaded, resolvedValidation, err := policy.ResolveConfigWithValidation(configPath, policy.ResolveOptions{
			RepoRoot:               repoPath,
			AllowConfigOutsideRepo: opts.allowConfigOutsideRepo,
		})
		if err != nil {
			return nil, err
		}
		validation = resolvedValidation
		configWarnings = validationReportWarnings(validation)
		if opts.strictConfig && validation.HasWarnings() {
			return nil, fmt.Errorf("strict config validation failed with %d warning(s)", validation.WarningCount)
		}
		cfg = *loaded
	}

	buildTags := splitTags(opts.tags)
	modules, goWorkPath, moduleWarnings := resolveModules(scanRoot, cwd, opts)
	scanner := analyzer.Scanner{
		RepoPath:         scanRoot,
		Config:           cfg,
		ConfigPath:       configPath,
		CoveragePath:     opts.coverage,
		BuildTags:        buildTags,
		IncludeGenerated: opts.includeGenerated,
		ExcludeGlobs:     append([]string{}, opts.excludes...),
		Govulncheck:      opts.govulncheck,
		Modules:          modules,
		GoWorkPath:       goWorkPath,
		VerboseWriter:    verboseWriter(cmd, opts.verbose),
	}
	rep, err := scanner.Scan(cmd.Context(), patterns)
	if err != nil {
		return nil, err
	}
	if opts.strictConfig && hasWarningSource(rep.Warnings, "CODEOWNERS") {
		return nil, fmt.Errorf("strict config validation failed on CODEOWNERS diagnostics")
	}
	rep.Warnings = appendUniqueWarnings(rep.Warnings, configWarnings...)
	rep.Warnings = appendUniqueWarnings(rep.Warnings, moduleWarnings...)
	rep.Summary = report.ComputeSummaryWithDependencies(rep.Packages, rep.Warnings, rep.DependencyFindings)
	rep.Summary.DependencyCount = len(rep.Dependencies)
	if validation.ConfigHash != "" {
		rep.Meta.ConfigHash = validation.ConfigHash
		rep.Meta.RulePacks = reportRulePacks(validation.RulePacks)
	} else {
		rep.Meta.ConfigHash = storage.ConfigHash(configPath, cfg)
	}
	identity := storage.ComputeRepoIdentity(cmd.Context(), scanRoot, packageImportPaths(rep))
	rep.Meta.RepoFingerprint = identity.Fingerprint
	rep.Meta.RepoDisplayName = identity.DisplayName

	if !opts.noHistory {
		store, err := storage.Open(storage.DefaultPath(cwd))
		if err != nil {
			rep.Warnings = append(rep.Warnings, report.Warning{Source: "history", Message: fmt.Sprintf("local history unavailable: %v", err)})
			rep.Summary = report.ComputeSummaryWithDependencies(rep.Packages, rep.Warnings, rep.DependencyFindings)
			rep.Summary.DependencyCount = len(rep.Dependencies)
		} else {
			previous, method, err := store.PreviousPackageScores(cmd.Context(), identity)
			if err != nil {
				rep.Warnings = append(rep.Warnings, report.Warning{Source: "history", Message: fmt.Sprintf("trend comparison unavailable: %v", err)})
			} else {
				rep.Meta.HistoryMatchMethod = string(method)
				storage.ApplyTrends(rep, previous)
			}
			scanID, err := store.SaveReport(cmd.Context(), rep)
			if err != nil {
				rep.Warnings = append(rep.Warnings, report.Warning{Source: "history", Message: fmt.Sprintf("scan history was not persisted: %v", err)})
			} else {
				rep.Meta.ScanID = scanID
			}
			if err := store.Close(); err != nil {
				rep.Warnings = append(rep.Warnings, report.Warning{Source: "history", Message: fmt.Sprintf("close history database: %v", err)})
			}
			rep.Summary = report.ComputeSummaryWithDependencies(rep.Packages, rep.Warnings, rep.DependencyFindings)
			rep.Summary.DependencyCount = len(rep.Dependencies)
		}
	}
	sortReportWarnings(rep.Warnings)
	rep.Summary = report.ComputeSummaryWithDependencies(rep.Packages, rep.Warnings, rep.DependencyFindings)
	rep.Summary.DependencyCount = len(rep.Dependencies)
	return rep, nil
}

func packageImportPaths(rep *report.Report) []string {
	paths := make([]string, 0, len(rep.Packages))
	for _, pkg := range rep.Packages {
		if pkg.ModulePath != "" {
			paths = append(paths, pkg.ModulePath+"|"+pkg.ImportPath)
		} else {
			paths = append(paths, pkg.ImportPath)
		}
	}
	return paths
}

func resolveModules(repoPath, cwd string, opts scanOptions) ([]report.ModuleInfo, string, []report.Warning) {
	discovery, err := fmodule.Discover(repoPath)
	if err != nil {
		return nil, "", []report.Warning{{Source: "module", Message: err.Error()}}
	}
	modules, selectionWarnings := fmodule.Select(discovery, fmodule.SelectionOptions{
		CWD:           cwd,
		AllModules:    opts.allModules,
		Modules:       append([]string{}, opts.modules...),
		IgnoreModules: append([]string{}, opts.ignoreModules...),
	})
	warnings := append([]report.Warning{}, discovery.Warnings...)
	warnings = append(warnings, selectionWarnings...)
	if len(modules) == 0 {
		return nil, discovery.GoWork, warnings
	}
	selected := 0
	for _, mod := range modules {
		if mod.Selected {
			selected++
		}
	}
	if selected == 0 {
		warnings = append(warnings, report.Warning{Source: "module", Message: "no discovered modules selected; falling back to current directory package loading"})
	}
	return modules, discovery.GoWork, warnings
}

func parseFailOn(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "none":
		return "", nil
	case "high":
		return string(report.SeverityHigh), nil
	case "critical":
		return string(report.SeverityCritical), nil
	default:
		return "", fmt.Errorf("unsupported --fail-on %q: expected none, high, or critical", value)
	}
}

func splitTags(tags string) []string {
	if strings.TrimSpace(tags) == "" {
		return nil
	}
	parts := strings.Split(tags, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func verboseWriter(cmd *cobra.Command, verbose bool) analyzer.VerboseWriter {
	if !verbose {
		return nil
	}
	return cmd.ErrOrStderr()
}

func validationReportWarnings(validation policy.ValidationReport) []report.Warning {
	out := make([]report.Warning, 0, len(validation.Issues))
	for _, issue := range validation.Issues {
		out = append(out, report.Warning{
			Source:  "config",
			Message: formatValidationIssue(issue),
		})
	}
	return out
}

func hasWarningSource(warnings []report.Warning, source string) bool {
	for _, warning := range warnings {
		if warning.Source == source {
			return true
		}
	}
	return false
}

func formatValidationIssue(issue policy.ValidationIssue) string {
	location := issue.Path
	if issue.Line > 0 {
		location = fmt.Sprintf("%s:%d:%d", location, issue.Line, issue.Column)
	}
	if location == "" {
		return fmt.Sprintf("%s: %s", issue.Level, issue.Message)
	}
	return fmt.Sprintf("%s: %s: %s", issue.Level, location, issue.Message)
}

func appendUniqueWarnings(warnings []report.Warning, additions ...report.Warning) []report.Warning {
	seen := make(map[string]bool, len(warnings)+len(additions))
	for _, warning := range warnings {
		seen[warning.Source+"\x00"+warning.Message] = true
	}
	for _, warning := range additions {
		key := warning.Source + "\x00" + warning.Message
		if seen[key] {
			continue
		}
		warnings = append(warnings, warning)
		seen[key] = true
	}
	return warnings
}

func sortReportWarnings(warnings []report.Warning) {
	sort.SliceStable(warnings, func(i, j int) bool {
		if warnings[i].Source != warnings[j].Source {
			return warnings[i].Source < warnings[j].Source
		}
		return warnings[i].Message < warnings[j].Message
	})
}

func reportRulePacks(items []policy.RulePackAudit) []report.ConfigRulePack {
	out := make([]report.ConfigRulePack, 0, len(items))
	for _, item := range items {
		out = append(out, report.ConfigRulePack{Path: item.Path, ContentHash: item.ContentHash, Imported: item.Imported})
	}
	return out
}
