// Package module discovers Go modules and workspaces inside a repository.
package module

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/faultline-go/faultline/internal/report"
	"golang.org/x/mod/modfile"
)

type Discovery struct {
	RepoRoot string
	GoWork   string
	Modules  []report.ModuleInfo
	Warnings []report.Warning
}

type SelectionOptions struct {
	CWD           string
	AllModules    bool
	Modules       []string
	IgnoreModules []string
}

// Discover finds go.mod files under repoRoot, excluding common generated and
// vendored trees. go.work is detected only at the repository root for now.
func Discover(repoRoot string) (Discovery, error) {
	repoAbs, err := filepath.Abs(repoRoot)
	if err != nil {
		return Discovery{}, fmt.Errorf("resolve repo root: %w", err)
	}
	discovery := Discovery{RepoRoot: repoAbs}
	workspaceUses := map[string]bool{}
	goWork := filepath.Join(repoAbs, "go.work")
	if data, err := os.ReadFile(goWork); err == nil {
		discovery.GoWork = safeRel(repoAbs, goWork)
		work, parseErr := modfile.ParseWork(goWork, data, nil)
		if parseErr != nil {
			discovery.Warnings = append(discovery.Warnings, report.Warning{Source: "module", Message: fmt.Sprintf("parse go.work: %v", parseErr)})
		} else {
			for _, use := range work.Use {
				root := filepath.Clean(filepath.Join(repoAbs, filepath.FromSlash(use.Path)))
				workspaceUses[root] = true
			}
		}
	} else if err != nil && !os.IsNotExist(err) {
		discovery.Warnings = append(discovery.Warnings, report.Warning{Source: "module", Message: fmt.Sprintf("read go.work: %v", err)})
	}

	err = filepath.WalkDir(repoAbs, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			discovery.Warnings = append(discovery.Warnings, report.Warning{Source: "module", Message: fmt.Sprintf("walk %s: %v", safeRel(repoAbs, path), err)})
			return nil
		}
		if entry.IsDir() {
			if path != repoAbs && skipDir(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Name() != "go.mod" {
			return nil
		}
		info, warn := readModule(repoAbs, path, workspaceUses)
		if warn != nil {
			discovery.Warnings = append(discovery.Warnings, *warn)
		}
		if info.ModuleRoot != "" {
			discovery.Modules = append(discovery.Modules, info)
		}
		return nil
	})
	if err != nil {
		return discovery, fmt.Errorf("discover modules: %w", err)
	}
	sort.SliceStable(discovery.Modules, func(i, j int) bool {
		return discovery.Modules[i].ModuleRoot < discovery.Modules[j].ModuleRoot
	})
	return discovery, nil
}

func readModule(repoRoot, goModPath string, workspaceUses map[string]bool) (report.ModuleInfo, *report.Warning) {
	data, err := os.ReadFile(goModPath)
	if err != nil {
		return report.ModuleInfo{}, &report.Warning{Source: "module", Message: fmt.Sprintf("read %s: %v", safeRel(repoRoot, goModPath), err)}
	}
	mod, err := modfile.Parse(goModPath, data, nil)
	if err != nil {
		return report.ModuleInfo{}, &report.Warning{Source: "module", Message: fmt.Sprintf("parse %s: %v", safeRel(repoRoot, goModPath), err)}
	}
	root := filepath.Dir(goModPath)
	modulePath := ""
	if mod.Module != nil {
		modulePath = mod.Module.Mod.Path
	}
	info := report.ModuleInfo{
		ModulePath:       modulePath,
		ModuleRoot:       safeRel(repoRoot, root),
		GoModPath:        safeRel(repoRoot, goModPath),
		IncludedByGoWork: workspaceUses[filepath.Clean(root)],
	}
	return info, nil
}

// Select marks discovered modules as selected for scan.
func Select(discovery Discovery, opts SelectionOptions) ([]report.ModuleInfo, []report.Warning) {
	modules := cloneModules(discovery.Modules)
	var warnings []report.Warning
	ignore := make(map[int]bool)
	for _, pattern := range opts.IgnoreModules {
		matches := matchingModules(discovery.RepoRoot, modules, pattern)
		if len(matches) == 0 {
			warnings = append(warnings, report.Warning{Source: "module", Message: fmt.Sprintf("ignored module %q did not match any discovered module", pattern)})
		}
		for _, idx := range matches {
			ignore[idx] = true
		}
	}

	selected := map[int]bool{}
	if len(opts.Modules) > 0 {
		for _, pattern := range opts.Modules {
			matches := matchingModules(discovery.RepoRoot, modules, pattern)
			if len(matches) == 0 {
				warnings = append(warnings, report.Warning{Source: "module", Message: fmt.Sprintf("module selector %q did not match any discovered module", pattern)})
			}
			for _, idx := range matches {
				selected[idx] = true
			}
		}
	} else if opts.AllModules || cwdIsRepoRoot(discovery.RepoRoot, opts.CWD) {
		for i := range modules {
			selected[i] = true
		}
	} else if idx, ok := containingModule(discovery.RepoRoot, modules, opts.CWD); ok {
		selected[idx] = true
	} else {
		for i := range modules {
			selected[i] = true
		}
	}

	for i := range modules {
		modules[i].Selected = selected[i] && !ignore[i]
	}
	return modules, warnings
}

func matchingModules(repoRoot string, modules []report.ModuleInfo, selector string) []int {
	selector = strings.TrimSpace(filepath.ToSlash(selector))
	if selector == "" {
		return nil
	}
	if filepath.IsAbs(selector) {
		if rel, err := filepath.Rel(repoRoot, filepath.FromSlash(selector)); err == nil {
			selector = filepath.ToSlash(rel)
		}
	}
	var out []int
	for i, module := range modules {
		if selector == module.ModulePath || selector == module.ModuleRoot || selector == module.GoModPath {
			out = append(out, i)
			continue
		}
		if strings.HasSuffix(module.ModuleRoot, "/"+selector) || strings.HasSuffix(module.ModulePath, "/"+selector) {
			out = append(out, i)
		}
	}
	return out
}

func containingModule(repoRoot string, modules []report.ModuleInfo, cwd string) (int, bool) {
	cwdAbs, err := filepath.Abs(cwd)
	if err != nil {
		return 0, false
	}
	best := -1
	bestLen := -1
	for i, module := range modules {
		root := filepath.Join(repoRoot, filepath.FromSlash(module.ModuleRoot))
		if pathWithin(root, cwdAbs) && len(root) > bestLen {
			best = i
			bestLen = len(root)
		}
	}
	return best, best >= 0
}

func cwdIsRepoRoot(repoRoot, cwd string) bool {
	cwdAbs, err := filepath.Abs(cwd)
	if err != nil {
		return false
	}
	return filepath.Clean(repoRoot) == filepath.Clean(cwdAbs)
}

func cloneModules(modules []report.ModuleInfo) []report.ModuleInfo {
	out := append([]report.ModuleInfo{}, modules...)
	return out
}

func Selected(modules []report.ModuleInfo) []report.ModuleInfo {
	out := make([]report.ModuleInfo, 0, len(modules))
	for _, module := range modules {
		if module.Selected {
			out = append(out, module)
		}
	}
	return out
}

func ByDir(modules []report.ModuleInfo, repoRoot, dir string) report.ModuleInfo {
	best := report.ModuleInfo{}
	bestLen := -1
	for _, module := range modules {
		root := filepath.Join(repoRoot, filepath.FromSlash(module.ModuleRoot))
		if pathWithin(root, dir) && len(root) > bestLen {
			best = module
			bestLen = len(root)
		}
	}
	return best
}

func skipDir(name string) bool {
	switch name {
	case "vendor", "third_party", "node_modules", ".git":
		return true
	default:
		return false
	}
}

func pathWithin(root, child string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(child))
	if err != nil {
		return false
	}
	return rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "..")
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
