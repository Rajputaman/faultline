package analyzer

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

// LoadedPackage is the analyzer's reduced view of a Go package.
type LoadedPackage struct {
	ID              string
	ImportPath      string
	Dir             string
	ModulePath      string
	ModuleRoot      string
	Imports         []string
	InternalImports []string
	Errors          []string
}

// LoadIssue preserves package loader errors for the report.
type LoadIssue struct {
	PackageID  string
	ImportPath string
	Error      string
}

// LoadPackages loads Go packages without executing repository scripts.
func LoadPackages(ctx context.Context, repoPath string, patterns, buildTags []string) ([]LoadedPackage, []LoadIssue, error) {
	return LoadPackagesInDir(ctx, repoPath, repoPath, "", "", patterns, buildTags)
}

func LoadPackagesInDir(ctx context.Context, repoRoot, dir, modulePath, moduleRoot string, patterns, buildTags []string) ([]LoadedPackage, []LoadIssue, error) {
	args := []string{}
	if len(buildTags) > 0 {
		args = append(args, "-tags="+strings.Join(buildTags, ","))
	}
	cfg := &packages.Config{
		Context: ctx,
		Dir:     dir,
		Mode: packages.NeedName |
			packages.NeedFiles |
			packages.NeedCompiledGoFiles |
			packages.NeedImports |
			packages.NeedModule |
			packages.NeedTypesSizes,
		BuildFlags: args,
	}
	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		return nil, nil, fmt.Errorf("load packages: %w", err)
	}

	var issues []LoadIssue
	out := make([]LoadedPackage, 0, len(pkgs))
	for _, pkg := range pkgs {
		pkgDir := packageDir(pkg)
		if pkgDir == "" || shouldSkipDir(repoRoot, pkgDir) {
			continue
		}

		lp := LoadedPackage{
			ID:         stablePackageID(pkg, modulePath),
			ImportPath: pkg.PkgPath,
			Dir:        pkgDir,
			ModulePath: modulePath,
			ModuleRoot: moduleRoot,
		}
		for _, e := range pkg.Errors {
			msg := e.Error()
			lp.Errors = append(lp.Errors, msg)
			issues = append(issues, LoadIssue{PackageID: lp.ID, ImportPath: lp.ImportPath, Error: msg})
		}
		for path := range pkg.Imports {
			if !isStandardLibraryImport(path) {
				lp.Imports = append(lp.Imports, path)
			}
		}
		sort.Strings(lp.Imports)
		out = append(out, lp)
	}
	markInternalImports(out)
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].ImportPath < out[j].ImportPath
	})
	return out, issues, nil
}

func markInternalImports(pkgs []LoadedPackage) {
	known := make(map[string]struct{}, len(pkgs))
	for _, pkg := range pkgs {
		known[pkg.ImportPath] = struct{}{}
	}
	for i := range pkgs {
		for _, imp := range pkgs[i].Imports {
			if _, ok := known[imp]; ok {
				pkgs[i].InternalImports = append(pkgs[i].InternalImports, imp)
			}
		}
		sort.Strings(pkgs[i].InternalImports)
	}
}

func isStandardLibraryImport(path string) bool {
	if path == "" {
		return false
	}
	first, _, _ := strings.Cut(path, "/")
	return !strings.Contains(first, ".")
}

func packageDir(pkg *packages.Package) string {
	files := append([]string{}, pkg.GoFiles...)
	files = append(files, pkg.CompiledGoFiles...)
	if len(files) == 0 {
		return ""
	}
	return filepath.Dir(files[0])
}

func stablePackageID(pkg *packages.Package, modulePath string) string {
	if pkg.PkgPath != "" {
		if modulePath != "" {
			return modulePath + "|" + pkg.PkgPath
		}
		return pkg.PkgPath
	}
	if pkg.ID != "" {
		return pkg.ID
	}
	return pkg.Name
}

func shouldSkipDir(repoPath, dir string) bool {
	rel := safeRel(repoPath, dir)
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return true
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	for _, p := range parts {
		switch p {
		case "vendor", "third_party", ".git", "node_modules":
			return true
		}
	}
	return false
}

func safeRel(base, target string) string {
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return target
	}
	if rel == "." {
		return "."
	}
	return filepath.ToSlash(rel)
}
