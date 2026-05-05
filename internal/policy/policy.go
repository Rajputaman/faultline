package policy

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/faultline-go/faultline/internal/report"
)

// PackageFacts is the policy layer's reduced view of one package.
type PackageFacts struct {
	ImportPath            string
	Dir                   string
	DirectInternalImports []string
}

// BoundaryRules returns a defensive copy of configured boundary rules.
func (c Config) BoundaryRules() []BoundaryRule {
	return append([]BoundaryRule{}, c.Boundaries...)
}

func (c Config) Summary() report.ConfigSummary {
	scoring := NormalizeScoringConfig(c.Scoring)
	return report.ConfigSummary{
		OwnershipRequireCodeowners:                   c.Ownership.RequireCodeowners,
		OwnershipMaxAuthorCount90d:                   c.Ownership.MaxAuthorCount90d,
		CoverageMinPackageCoverage:                   c.Coverage.MinPackageCoverage,
		TestRatioThreshold:                           c.TestRatioThreshold,
		ScoringChurnMaxLines30d:                      scoring.ChurnMaxLines30d,
		ScoringComplexityMaxLOC:                      scoring.ComplexityMaxLOC,
		ScoringComplexityMaxImports:                  scoring.ComplexityMaxImports,
		ScoringComplexityMaxFiles:                    scoring.ComplexityMaxFiles,
		ScoringDependencyCentralityMaxReverseImports: scoring.DependencyCentralityMaxReverseImportCount,
		BoundaryRuleCount:                            len(c.Boundaries),
		SuppressionCount:                             len(c.Suppressions),
	}
}

// EvaluateBoundaries returns BOUNDARY findings keyed by importing package.
func EvaluateBoundaries(cfg Config, pkgs []PackageFacts) (map[string][]report.Finding, []report.Warning) {
	findings := make(map[string][]report.Finding)
	var warnings []report.Warning

	pkgDirByImport := make(map[string]string, len(pkgs))
	for _, pkg := range pkgs {
		pkgDirByImport[pkg.ImportPath] = filepath.ToSlash(pkg.Dir)
	}

	for i, rule := range cfg.Boundaries {
		context := fmt.Sprintf("boundaries[%d]", i)
		ruleWarnings := validateBoundaryRule(rule, context)
		warnings = append(warnings, ruleWarnings...)
		if len(ruleWarnings) > 0 {
			continue
		}

		for _, pkg := range pkgs {
			if !matchesPattern(rule.From, pkg.ImportPath, pkg.Dir) {
				continue
			}
			for _, imp := range pkg.DirectInternalImports {
				importDir := pkgDirByImport[imp]
				if !matchesAny(rule.Deny, imp, importDir) {
					continue
				}
				if matchesAny(rule.Except, pkg.ImportPath, pkg.Dir) || matchesAny(rule.Except, imp, importDir) {
					continue
				}
				findings[pkg.ImportPath] = append(findings[pkg.ImportPath], boundaryFinding(rule, pkg, imp, importDir))
			}
		}
	}

	return findings, warnings
}

func boundaryFinding(rule BoundaryRule, pkg PackageFacts, deniedImport, deniedDir string) report.Finding {
	return report.Finding{
		ID:          "FL-BND-001",
		Category:    report.CategoryBoundary,
		Severity:    report.SeverityHigh,
		Title:       "Architecture boundary violation",
		Description: fmt.Sprintf("Package %s imports %s, which is denied by boundary rule %q.", pkg.ImportPath, deniedImport, rule.Name),
		Evidence: []report.Evidence{
			{Key: "boundary_rule", Value: rule.Name, Source: "policy"},
			{Key: "from", Value: rule.From, Source: "policy"},
			{Key: "deny", Value: strings.Join(rule.Deny, ","), Source: "policy"},
			{Key: "importing_package", Value: pkg.ImportPath, Source: "import_graph"},
			{Key: "importing_dir", Value: pkg.Dir, Source: "import_graph"},
			{Key: "matched_import", Value: deniedImport, Source: "import_graph"},
			{Key: "matched_import_dir", Value: deniedDir, Source: "import_graph"},
		},
		Recommendation: "Invert the dependency direction or introduce an interface in an allowed lower-level package so policy boundaries remain explicit.",
		Confidence:     0.9,
	}
}

func validateBoundaryRule(rule BoundaryRule, context string) []report.Warning {
	var warnings []report.Warning
	if strings.TrimSpace(rule.Name) == "" {
		warnings = append(warnings, report.Warning{Message: context + ": boundary rule missing name", Source: "policy"})
	}
	if strings.TrimSpace(rule.From) == "" {
		warnings = append(warnings, report.Warning{Message: context + ": boundary rule missing from pattern", Source: "policy"})
	} else if err := validateGlobish(rule.From); err != nil {
		warnings = append(warnings, report.Warning{Message: fmt.Sprintf("%s: invalid from pattern %q: %v", context, rule.From, err), Source: "policy"})
	}
	if len(rule.Deny) == 0 {
		warnings = append(warnings, report.Warning{Message: context + ": boundary rule missing deny patterns", Source: "policy"})
	}
	for j, pattern := range rule.Deny {
		if strings.TrimSpace(pattern) == "" {
			warnings = append(warnings, report.Warning{Message: fmt.Sprintf("%s.deny[%d]: empty deny pattern", context, j), Source: "policy"})
			continue
		}
		if err := validateGlobish(pattern); err != nil {
			warnings = append(warnings, report.Warning{Message: fmt.Sprintf("%s.deny[%d]: invalid pattern %q: %v", context, j, pattern, err), Source: "policy"})
		}
	}
	for j, pattern := range rule.Except {
		if strings.TrimSpace(pattern) == "" {
			warnings = append(warnings, report.Warning{Message: fmt.Sprintf("%s.except[%d]: empty except pattern", context, j), Source: "policy"})
			continue
		}
		if err := validateGlobish(pattern); err != nil {
			warnings = append(warnings, report.Warning{Message: fmt.Sprintf("%s.except[%d]: invalid pattern %q: %v", context, j, pattern, err), Source: "policy"})
		}
	}
	return warnings
}

// ApplySuppressions marks matching, non-expired suppressions on findings and
// returns top-level audit entries plus config warnings.
func ApplySuppressions(cfg Config, pkgs []report.PackageRisk, now time.Time) ([]report.PackageRisk, []report.SuppressedFinding, []report.Warning) {
	out := clonePackages(pkgs)
	var audit []report.SuppressedFinding
	var warnings []report.Warning

	for i := range cfg.Suppressions {
		warnings = append(warnings, validateSuppression(cfg.Suppressions[i], cfg.SuppressionPolicy, i, now)...)
	}

	for i := range out {
		for j := range out[i].Findings {
			supp, ok := matchSuppression(cfg.Suppressions, cfg.SuppressionPolicy, out[i], out[i].Findings[j], now)
			if !ok {
				continue
			}
			info := report.SuppressionInfo{
				Reason:   supp.Reason,
				Owner:    supp.Owner,
				Expires:  supp.Expires,
				Package:  supp.Package,
				Category: supp.Category,
				Created:  supp.Created,
			}
			out[i].Findings[j].Suppressed = true
			out[i].Findings[j].Suppression = &info
			audit = append(audit, report.SuppressedFinding{
				PackageImportPath: out[i].ImportPath,
				FindingID:         out[i].Findings[j].ID,
				Category:          out[i].Findings[j].Category,
				Severity:          out[i].Findings[j].Severity,
				Suppression:       info,
			})
		}
	}
	return out, audit, warnings
}

func clonePackages(pkgs []report.PackageRisk) []report.PackageRisk {
	out := append([]report.PackageRisk{}, pkgs...)
	for i := range out {
		out[i].Findings = append([]report.Finding{}, pkgs[i].Findings...)
		out[i].Evidence = append([]report.Evidence{}, pkgs[i].Evidence...)
		out[i].LoadErrors = append([]string{}, pkgs[i].LoadErrors...)
		out[i].DirectInternalImports = append([]string{}, pkgs[i].DirectInternalImports...)
	}
	return out
}

func matchSuppression(suppressions []Suppression, policy SuppressionPolicy, pkg report.PackageRisk, finding report.Finding, now time.Time) (Suppression, bool) {
	for _, suppression := range suppressions {
		if !suppressionUsable(suppression, policy, now) {
			continue
		}
		if suppression.ID != finding.ID {
			continue
		}
		if suppression.Category != "" && !strings.EqualFold(suppression.Category, string(finding.Category)) {
			continue
		}
		if !matchesPattern(suppression.Package, pkg.ImportPath, pkg.Dir) {
			continue
		}
		return suppression, true
	}
	return Suppression{}, false
}

func suppressionUsable(s Suppression, policy SuppressionPolicy, now time.Time) bool {
	if strings.TrimSpace(s.ID) == "" || strings.TrimSpace(s.Package) == "" {
		return false
	}
	if policy.RequireReason && strings.TrimSpace(s.Reason) == "" {
		return false
	}
	if policy.RequireOwner && strings.TrimSpace(s.Owner) == "" {
		return false
	}
	if policy.RequireExpires && strings.TrimSpace(s.Expires) == "" {
		return false
	}
	if strings.TrimSpace(s.Expires) == "" {
		return true
	}
	expires := s.ExpiresTime()
	return !expires.IsZero() && !expires.Before(dateOnly(now))
}

func validateSuppression(s Suppression, policy SuppressionPolicy, index int, now time.Time) []report.Warning {
	context := fmt.Sprintf("suppressions[%d]", index)
	issues := validateSuppressionIssues(s, policy, context, now)
	warnings := make([]report.Warning, 0, len(issues))
	for _, issue := range issues {
		warnings = append(warnings, report.Warning{Message: fmt.Sprintf("%s: %s", issue.Path, issue.Message), Source: "policy"})
	}
	return warnings
}

func validCategory(category string) bool {
	switch report.Category(strings.ToUpper(category)) {
	case report.CategoryOwnership, report.CategoryChurn, report.CategoryCoverage, report.CategoryComplexity, report.CategoryBoundary, report.CategoryDependency, report.CategoryTest:
		return true
	default:
		return false
	}
}

func dateOnly(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

func matchesAny(patterns []string, importPath, dir string) bool {
	for _, pattern := range patterns {
		if matchesPattern(pattern, importPath, dir) {
			return true
		}
	}
	return false
}

func matchesPattern(pattern, importPath, dir string) bool {
	pattern = strings.TrimSpace(filepath.ToSlash(pattern))
	if pattern == "" {
		return false
	}
	importPath = filepath.ToSlash(importPath)
	dir = filepath.ToSlash(dir)
	return globishMatch(pattern, importPath) || globishMatch(pattern, dir)
}

func validateGlobish(pattern string) error {
	_, err := path.Match(strings.ReplaceAll(filepath.ToSlash(pattern), "**", "*"), "")
	if err != nil {
		return err
	}
	return nil
}

func globishMatch(pattern, value string) bool {
	if pattern == value {
		return true
	}
	if ok, err := path.Match(pattern, value); err == nil && ok {
		return true
	}
	if strings.HasPrefix(pattern, "*/") {
		return globishMatch(strings.TrimPrefix(pattern, "*/"), value)
	}
	parts := strings.Split(value, "/")
	for i := 1; i < len(parts); i++ {
		suffix := strings.Join(parts[i:], "/")
		if ok, err := path.Match(pattern, suffix); err == nil && ok {
			return true
		}
	}
	if strings.Contains(pattern, "**") {
		patternParts := strings.Split(pattern, "**")
		pos := 0
		for _, part := range patternParts {
			if part == "" {
				continue
			}
			idx := strings.Index(value[pos:], part)
			if idx < 0 {
				return false
			}
			pos += idx + len(part)
		}
		if !strings.HasPrefix(pattern, "**") && !strings.HasPrefix(value, patternParts[0]) {
			return false
		}
		last := patternParts[len(patternParts)-1]
		if !strings.HasSuffix(pattern, "**") && last != "" && !strings.HasSuffix(value, last) {
			return false
		}
		return true
	}
	return false
}
