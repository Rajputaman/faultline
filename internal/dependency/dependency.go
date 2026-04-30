// Package dependency analyzes local Go module dependency metadata.
package dependency

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/faultline-go/faultline/internal/report"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
)

// PackageImports is the reduced package graph input needed for dependency
// usage analysis. Imports should already exclude standard-library imports.
type PackageImports struct {
	ImportPath string
	Imports    []string
}

type Options struct {
	RepoPath        string
	RepoRoot        string
	Module          report.ModuleInfo
	AllModules      []report.ModuleInfo
	Packages        []PackageImports
	Govulncheck     string
	GovulncheckArgs []string
}

type Result struct {
	Dependencies []report.DependencyRisk
	Findings     []report.Finding
	Warnings     []report.Warning
	Govulncheck  *report.ExternalToolResult
}

// Analyze reads go.mod/go.sum and computes structural dependency risk without
// contacting module proxies or vulnerability databases.
func Analyze(ctx context.Context, opts Options) Result {
	repoPath := opts.RepoPath
	if repoPath == "" {
		repoPath = "."
	}
	repoRoot := opts.RepoRoot
	if repoRoot == "" {
		repoRoot = repoPath
	}
	goModPath := filepath.Join(repoPath, "go.mod")
	data, err := os.ReadFile(goModPath)
	if errors.Is(err, os.ErrNotExist) {
		return Result{Warnings: []report.Warning{{Source: "dependency", Message: "go.mod not found; dependency inventory unavailable"}}}
	}
	if err != nil {
		return Result{Warnings: []report.Warning{{Source: "dependency", Message: fmt.Sprintf("read go.mod: %v", err)}}}
	}
	modFile, err := modfile.Parse(goModPath, data, nil)
	if err != nil {
		return Result{Warnings: []report.Warning{{Source: "dependency", Message: fmt.Sprintf("parse go.mod: %v", err)}}}
	}

	sumEntries := parseGoSum(filepath.Join(repoPath, "go.sum"))
	moduleInfo := opts.Module
	if moduleInfo.ModuleRoot == "" {
		moduleInfo.ModuleRoot = safeRel(repoRoot, repoPath)
	}
	if moduleInfo.ModulePath == "" && modFile.Module != nil {
		moduleInfo.ModulePath = modFile.Module.Mod.Path
	}
	if moduleInfo.GoModPath == "" {
		moduleInfo.GoModPath = safeRel(repoRoot, goModPath)
	}
	deps, findings := buildInventory(repoRoot, moduleInfo, opts.AllModules, modFile, sumEntries, opts.Packages)
	result := Result{
		Dependencies: deps,
		Findings:     findings,
	}
	if gov := runGovulncheck(ctx, repoPath, opts.Govulncheck, opts.GovulncheckArgs); gov != nil {
		result.Govulncheck = gov.Result
		result.Warnings = append(result.Warnings, gov.Warnings...)
	}
	return result
}

func buildInventory(repoRoot string, sourceModule report.ModuleInfo, allModules []report.ModuleInfo, modFile *modfile.File, sumEntries map[string]map[string]bool, pkgs []PackageImports) ([]report.DependencyRisk, []report.Finding) {
	requireByPath := make(map[string]*modfile.Require, len(modFile.Require))
	depsByPath := make(map[string]*report.DependencyRisk, len(modFile.Require)+len(modFile.Replace))
	for _, req := range modFile.Require {
		requireByPath[req.Mod.Path] = req
		line := lineNumber(req.Syntax)
		dep := report.DependencyRisk{
			SourceModulePath: sourceModule.ModulePath,
			SourceModuleRoot: sourceModule.ModuleRoot,
			ModulePath:       req.Mod.Path,
			Version:          req.Mod.Version,
			Indirect:         req.Indirect,
			GoSumPresent:     hasGoSum(sumEntries, req.Mod),
			Evidence: []report.Evidence{
				{Key: "go_mod_line", Value: strconv.Itoa(line), Source: "go.mod"},
				{Key: "required_version", Value: req.Mod.Version, Source: "go.mod"},
			},
		}
		depsByPath[req.Mod.Path] = &dep
	}
	for _, repl := range modFile.Replace {
		dep := depsByPath[repl.Old.Path]
		if dep == nil {
			dep = &report.DependencyRisk{
				SourceModulePath: sourceModule.ModulePath,
				SourceModuleRoot: sourceModule.ModuleRoot,
				ModulePath:       repl.Old.Path,
				Version:          repl.Old.Version,
				Evidence: []report.Evidence{
					{Key: "go_mod_line", Value: strconv.Itoa(lineNumber(repl.Syntax)), Source: "go.mod"},
				},
			}
			depsByPath[repl.Old.Path] = dep
		}
		dep.Replace = &report.DependencyReplace{
			OldPath:    repl.Old.Path,
			OldVersion: repl.Old.Version,
			NewPath:    repl.New.Path,
			NewVersion: repl.New.Version,
		}
		dep.LocalReplace = isLocalReplace(repl.New)
		if dep.LocalReplace {
			if target, ok := crossModuleReplace(repoRoot, sourceModule, allModules, repl.New.Path); ok {
				dep.CrossModuleReplace = true
				dep.ReplaceModulePath = target.ModulePath
				dep.ReplaceModuleRoot = target.ModuleRoot
			}
		}
		dep.Evidence = append(dep.Evidence,
			report.Evidence{Key: "replace_new_path", Value: repl.New.Path, Source: "go.mod"},
			report.Evidence{Key: "replace_new_version", Value: repl.New.Version, Source: "go.mod"},
			report.Evidence{Key: "go_mod_line", Value: strconv.Itoa(lineNumber(repl.Syntax)), Source: "go.mod"},
		)
	}

	deps := make([]report.DependencyRisk, 0, len(depsByPath))
	for _, dep := range depsByPath {
		deps = append(deps, *dep)
	}
	sort.SliceStable(deps, func(i, j int) bool {
		return deps[i].ModulePath < deps[j].ModulePath
	})
	usage := dependencyUsage(deps, pkgs)
	var findings []report.Finding
	for i := range deps {
		u := usage[deps[i].ModulePath]
		deps[i].Used = len(u.packages) > 0
		deps[i].ImportCount = u.importCount
		deps[i].ImportingPackages = sortedKeys(u.packages)
		deps[i].ImportingPackageCount = len(deps[i].ImportingPackages)
		deps[i].Findings = dependencyFindings(deps[i], requireByPath[deps[i].ModulePath] != nil, len(pkgs))
		deps[i].Evidence = append(deps[i].Evidence,
			report.Evidence{Key: "import_count", Value: strconv.Itoa(deps[i].ImportCount), Source: "import_graph"},
			report.Evidence{Key: "importing_package_count", Value: strconv.Itoa(deps[i].ImportingPackageCount), Source: "import_graph"},
		)
		sortFindings(deps[i].Findings)
		findings = append(findings, deps[i].Findings...)
	}
	sortFindings(findings)
	return deps, findings
}

type usageInfo struct {
	importCount int
	packages    map[string]bool
}

func dependencyUsage(deps []report.DependencyRisk, pkgs []PackageImports) map[string]usageInfo {
	out := make(map[string]usageInfo, len(deps))
	for _, dep := range deps {
		out[dep.ModulePath] = usageInfo{packages: map[string]bool{}}
	}
	modules := make([]string, 0, len(deps))
	for _, dep := range deps {
		modules = append(modules, dep.ModulePath)
	}
	sort.SliceStable(modules, func(i, j int) bool {
		return len(modules[i]) > len(modules[j])
	})
	for _, pkg := range pkgs {
		seenInPkg := map[string]bool{}
		for _, imp := range pkg.Imports {
			mod := moduleForImport(modules, imp)
			if mod == "" {
				continue
			}
			info := out[mod]
			info.importCount++
			if !seenInPkg[mod] {
				info.packages[pkg.ImportPath] = true
				seenInPkg[mod] = true
			}
			out[mod] = info
		}
	}
	return out
}

func moduleForImport(modules []string, imp string) string {
	for _, mod := range modules {
		if imp == mod || strings.HasPrefix(imp, mod+"/") {
			return mod
		}
	}
	return ""
}

func dependencyFindings(dep report.DependencyRisk, declared bool, packageCount int) []report.Finding {
	var findings []report.Finding
	if dep.Replace != nil {
		if dep.LocalReplace {
			findings = append(findings, finding(dep, "FL-DEP-002", report.SeverityHigh, "Local replace directive present",
				fmt.Sprintf("Module %s is replaced with local path %s.", dep.ModulePath, dep.Replace.NewPath),
				"Avoid committing local replace directives for release or CI builds; use a versioned module dependency or document the temporary waiver.",
				0.95,
				report.Evidence{Key: "replace_type", Value: "local", Source: "go.mod"}))
		}
		if dep.Replace.NewPath != "" && dep.Replace.NewVersion != "" && dep.Replace.NewPath != dep.Replace.OldPath {
			findings = append(findings, finding(dep, "FL-DEP-003", report.SeverityHigh, "Module replaced to different path",
				fmt.Sprintf("Module %s is replaced with different module path %s.", dep.ModulePath, dep.Replace.NewPath),
				"Verify this module path substitution is intentional and reviewed; prefer explicit governance when replacing module identity.",
				0.9,
				report.Evidence{Key: "replace_type", Value: "module_path_change", Source: "go.mod"}))
		}
		if dep.CrossModuleReplace {
			findings = append(findings, finding(dep, "FL-DEP-007", report.SeverityMedium, "Cross-module local replace inside repository",
				fmt.Sprintf("Module %s replaces %s with repository module %s.", dep.SourceModulePath, dep.ModulePath, dep.ReplaceModulePath),
				"Prefer go.work workspace usage for local multi-module development, or document why this committed replace is required.",
				0.9,
				report.Evidence{Key: "replace_type", Value: "cross_module_local", Source: "go.mod"},
				report.Evidence{Key: "replace_module_path", Value: dep.ReplaceModulePath, Source: "module"},
				report.Evidence{Key: "replace_module_root", Value: dep.ReplaceModuleRoot, Source: "module"}))
		}
	}
	if declared && !dep.Indirect && !dep.Used {
		findings = append(findings, finding(dep, "FL-DEP-004", report.SeverityLow, "Declared dependency appears unused",
			fmt.Sprintf("Direct dependency %s was not matched to imports in loaded packages.", dep.ModulePath),
			"Run go mod tidy locally after reviewing whether this dependency is used behind build tags or generated code.",
			0.55,
			report.Evidence{Key: "detection", Value: "best_effort_import_prefix_match", Source: "dependency"}))
	}
	if broadBlastRadius(dep, packageCount) {
		findings = append(findings, finding(dep, "FL-DEP-005", report.SeverityMedium, "Dependency has broad blast radius",
			fmt.Sprintf("Dependency %s is imported by %d loaded packages.", dep.ModulePath, dep.ImportingPackageCount),
			"Review update and rollback plans for this dependency; broad usage raises the coordination cost of upgrades.",
			0.75,
			report.Evidence{Key: "package_count", Value: strconv.Itoa(packageCount), Source: "import_graph"}))
	}
	if isPseudoVersion(dep.Version) || (dep.Replace != nil && isPseudoVersion(dep.Replace.NewVersion)) {
		findings = append(findings, finding(dep, "FL-DEP-006", report.SeverityLow, "Dependency uses pseudo-version",
			fmt.Sprintf("Dependency %s uses pseudo-version metadata.", dep.ModulePath),
			"Prefer tagged module versions when practical so provenance and upgrade intent are easier to review.",
			0.9,
			report.Evidence{Key: "version_kind", Value: "pseudo_version", Source: "go.mod"}))
	}
	return findings
}

func finding(dep report.DependencyRisk, id string, severity report.Severity, title, description, recommendation string, confidence float64, extra ...report.Evidence) report.Finding {
	evidence := []report.Evidence{
		{Key: "source_module_path", Value: dep.SourceModulePath, Source: "module"},
		{Key: "source_module_root", Value: dep.SourceModuleRoot, Source: "module"},
		{Key: "module_path", Value: dep.ModulePath, Source: "go.mod"},
		{Key: "version", Value: dep.Version, Source: "go.mod"},
	}
	if dep.Replace != nil {
		evidence = append(evidence,
			report.Evidence{Key: "replace_old_path", Value: dep.Replace.OldPath, Source: "go.mod"},
			report.Evidence{Key: "replace_old_version", Value: dep.Replace.OldVersion, Source: "go.mod"},
			report.Evidence{Key: "replace_new_path", Value: dep.Replace.NewPath, Source: "go.mod"},
			report.Evidence{Key: "replace_new_version", Value: dep.Replace.NewVersion, Source: "go.mod"},
		)
	}
	evidence = append(evidence,
		report.Evidence{Key: "go_mod_line", Value: firstEvidence(dep.Evidence, "go_mod_line"), Source: "go.mod"},
		report.Evidence{Key: "import_count", Value: strconv.Itoa(dep.ImportCount), Source: "import_graph"},
		report.Evidence{Key: "importing_package_count", Value: strconv.Itoa(dep.ImportingPackageCount), Source: "import_graph"},
	)
	evidence = append(evidence, extra...)
	return report.Finding{
		ID:             id,
		Category:       report.CategoryDependency,
		Severity:       severity,
		Title:          title,
		Description:    description,
		Evidence:       evidence,
		Recommendation: recommendation,
		Confidence:     confidence,
	}
}

func crossModuleReplace(repoRoot string, source report.ModuleInfo, modules []report.ModuleInfo, replacePath string) (report.ModuleInfo, bool) {
	if replacePath == "" || len(modules) == 0 {
		return report.ModuleInfo{}, false
	}
	sourceRoot := filepath.Join(repoRoot, filepath.FromSlash(source.ModuleRoot))
	target := filepath.Clean(filepath.Join(sourceRoot, filepath.FromSlash(replacePath)))
	for _, mod := range modules {
		if mod.ModuleRoot == "" || mod.ModuleRoot == source.ModuleRoot {
			continue
		}
		root := filepath.Join(repoRoot, filepath.FromSlash(mod.ModuleRoot))
		if samePath(root, target) {
			return mod, true
		}
	}
	return report.ModuleInfo{}, false
}

func parseGoSum(path string) map[string]map[string]bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	out := map[string]map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		modPath := fields[0]
		version := strings.TrimSuffix(fields[1], "/go.mod")
		if out[modPath] == nil {
			out[modPath] = map[string]bool{}
		}
		out[modPath][version] = true
	}
	return out
}

func hasGoSum(sumEntries map[string]map[string]bool, mod module.Version) bool {
	if mod.Path == "" || mod.Version == "" {
		return false
	}
	return sumEntries[mod.Path][mod.Version]
}

func isLocalReplace(mod module.Version) bool {
	if mod.Version != "" || mod.Path == "" {
		return false
	}
	p := filepath.FromSlash(mod.Path)
	return filepath.IsAbs(p) || strings.HasPrefix(mod.Path, ".") || strings.HasPrefix(mod.Path, "/")
}

func isPseudoVersion(version string) bool {
	if version == "" {
		return false
	}
	parts := strings.Split(version, "-")
	if len(parts) < 3 {
		return false
	}
	date := parts[len(parts)-2]
	hash := parts[len(parts)-1]
	if len(date) != 14 || len(hash) < 12 {
		return false
	}
	for _, r := range date {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	for _, r := range hash[:12] {
		if !unicode.IsDigit(r) && (r < 'a' || r > 'f') {
			return false
		}
	}
	return strings.HasPrefix(version, "v")
}

func broadBlastRadius(dep report.DependencyRisk, packageCount int) bool {
	if dep.ImportingPackageCount >= 5 {
		return true
	}
	if packageCount >= 3 && dep.ImportingPackageCount >= 3 {
		return float64(dep.ImportingPackageCount)/float64(packageCount) >= 0.4
	}
	return false
}

type govulncheckRun struct {
	Result   *report.ExternalToolResult
	Warnings []report.Warning
}

func runGovulncheck(ctx context.Context, repoPath, mode string, args []string) *govulncheckRun {
	mode = strings.TrimSpace(mode)
	if mode == "" || strings.EqualFold(mode, "off") {
		return nil
	}
	toolPath := mode
	if strings.EqualFold(mode, "auto") {
		found, err := exec.LookPath("govulncheck")
		if err != nil {
			return &govulncheckRun{
				Result:   &report.ExternalToolResult{Name: "govulncheck", Mode: mode, Ran: false, Error: "govulncheck not found on PATH"},
				Warnings: []report.Warning{{Source: "govulncheck", Message: "govulncheck auto mode requested but binary was not found"}},
			}
		}
		toolPath = found
	}
	if len(args) == 0 {
		args = []string{"./..."}
	}
	cmdArgs := append([]string{"-json"}, args...)
	cmd := exec.CommandContext(ctx, toolPath, cmdArgs...)
	cmd.Dir = repoPath
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	res := &report.ExternalToolResult{Name: "govulncheck", Mode: mode, ToolPath: toolPath, Ran: true, Output: stdout.String()}
	if err != nil {
		res.Error = strings.TrimSpace(stderr.String())
		if res.Error == "" {
			res.Error = err.Error()
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			res.ExitCode = exitErr.ExitCode()
		}
		return &govulncheckRun{
			Result:   res,
			Warnings: []report.Warning{{Source: "govulncheck", Message: fmt.Sprintf("govulncheck returned non-zero status: %s", res.Error)}},
		}
	}
	return &govulncheckRun{Result: res}
}

func lineNumber(line *modfile.Line) int {
	if line == nil {
		return 0
	}
	return line.Start.Line
}

func firstEvidence(items []report.Evidence, key string) string {
	for _, item := range items {
		if item.Key == key && item.Value != "" {
			return item.Value
		}
	}
	return ""
}

func sortedKeys(in map[string]bool) []string {
	out := make([]string, 0, len(in))
	for key := range in {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func samePath(a, b string) bool {
	absA, errA := filepath.Abs(a)
	absB, errB := filepath.Abs(b)
	if errA != nil || errB != nil {
		return filepath.Clean(a) == filepath.Clean(b)
	}
	return filepath.Clean(absA) == filepath.Clean(absB)
}

func safeRel(base, target string) string {
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return filepath.ToSlash(target)
	}
	if rel == "." {
		return "."
	}
	return filepath.ToSlash(rel)
}

func sortFindings(findings []report.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].ID != findings[j].ID {
			return findings[i].ID < findings[j].ID
		}
		return findings[i].Description < findings[j].Description
	})
}
