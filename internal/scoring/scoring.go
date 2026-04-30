package scoring

import (
	"math"

	"github.com/faultline-go/faultline/internal/policy"
	"github.com/faultline-go/faultline/internal/report"
)

const Version = "faultline-risk-v0.2"

// Options controls scoring thresholds. The model is intentionally simple and
// deterministic; thresholds should be tuned with real project data before being
// treated as release gates.
type Options struct {
	Config           policy.Config
	CoverageSupplied bool
	CoverageUsable   bool
	GitAvailable     bool
	CodeownersUsed   bool
}

// Result is the output of scoring a package.
type Result struct {
	RiskScore       float64
	ComplexityScore float64
	Breakdown       report.ScoreBreakdown
	Evidence        []report.Evidence
	Findings        []report.Finding
}

// ScorePackage computes an explainable risk score in the range [0,100].
func ScorePackage(pkg report.PackageRisk, opts Options) Result {
	cfg := opts.Config
	if cfg.Version == 0 {
		cfg = policy.DefaultConfig()
	}

	breakdown := report.ScoreBreakdown{
		ChurnScore:                clamp(float64(pkg.Churn30d)/1000.0*100.0, 0, 100),
		CoverageGapScore:          coverageGapScore(pkg.CoveragePct, cfg),
		ComplexityScore:           complexity(pkg),
		OwnershipEntropyScore:     clamp(pkg.OwnershipEntropy*100.0, 0, 100),
		DependencyCentralityScore: clamp(float64(pkg.ReverseImportCount)/10.0*100.0, 0, 100),
	}

	risk := breakdown.ChurnScore*0.25 +
		breakdown.CoverageGapScore*0.20 +
		breakdown.ComplexityScore*0.20 +
		breakdown.OwnershipEntropyScore*0.20 +
		breakdown.DependencyCentralityScore*0.15

	ev := []report.Evidence{
		evidenceFloat("churn_score", breakdown.ChurnScore, "scoring"),
		evidenceFloat("coverage_gap_score", breakdown.CoverageGapScore, "scoring"),
		evidenceFloat("complexity_score", breakdown.ComplexityScore, "scoring"),
		evidenceFloat("ownership_entropy_score", breakdown.OwnershipEntropyScore, "scoring"),
		evidenceFloat("dependency_centrality_score", breakdown.DependencyCentralityScore, "scoring"),
		evidenceFloat("risk_score", risk, "scoring"),
		evidence("scoring_version", Version, "scoring"),
	}

	findings := make([]report.Finding, 0, 7)
	if pkg.Churn30d >= 500 {
		findings = append(findings, report.Finding{
			ID:          "FL-CHURN-001",
			Category:    report.CategoryChurn,
			Severity:    report.SeverityHigh,
			Title:       "High churn in last 30 days",
			Description: "This package has a high number of added and deleted lines in the last 30 days.",
			Evidence: []report.Evidence{
				evidence("churn_30d", pkg.Churn30d, "git"),
				evidence("threshold", 500, "scoring"),
			},
			Recommendation: "Review recent changes, stabilize interfaces, and prioritize tests around active code paths.",
			Confidence:     0.8,
		})
	}
	if opts.CoverageSupplied && opts.CoverageUsable && pkg.CoveragePct != nil && *pkg.CoveragePct < cfg.Coverage.MinPackageCoverage {
		findings = append(findings, report.Finding{
			ID:          "FL-COV-001",
			Category:    report.CategoryCoverage,
			Severity:    report.SeverityMedium,
			Title:       "Package coverage is below threshold",
			Description: "Coverage is known for this package and is below the configured minimum.",
			Evidence: []report.Evidence{
				evidenceFloat("coverage_pct", *pkg.CoveragePct, "coverage"),
				evidenceFloat("min_package_coverage", cfg.Coverage.MinPackageCoverage, "policy"),
			},
			Recommendation: "Add tests for changed and high-risk code before relying on this package as stable.",
			Confidence:     0.85,
		})
	}
	if !opts.CoverageSupplied || !opts.CoverageUsable || (opts.CoverageUsable && pkg.CoveragePct == nil) {
		source := "cli"
		description := "No coverage profile was supplied, so coverage was treated as unknown."
		if opts.CoverageSupplied && opts.CoverageUsable {
			source = "coverage"
			description = "A coverage profile was supplied, but this package was not present in it."
		} else if opts.CoverageSupplied {
			source = "coverage"
			description = "Coverage data could not be used, so package coverage was treated as unknown."
		}
		findings = append(findings, report.Finding{
			ID:             "FL-COV-002",
			Category:       report.CategoryCoverage,
			Severity:       report.SeverityLow,
			Title:          "Coverage data is missing",
			Description:    description,
			Evidence:       []report.Evidence{evidence("coverage", "unknown", source)},
			Recommendation: "Run go test with -coverprofile for all scanned packages and pass --coverage.",
			Confidence:     1.0,
		})
	}
	if pkg.DominantOwner == nil && cfg.Ownership.RequireCodeowners {
		findings = append(findings, report.Finding{
			ID:             "FL-OWN-001",
			Category:       report.CategoryOwnership,
			Severity:       report.SeverityLow,
			Title:          "No owner found",
			Description:    "No module owner, CODEOWNERS owner, or dominant git author owner resolved for this package.",
			Evidence:       []report.Evidence{evidence("owner", "unknown", "ownership")},
			Recommendation: "Add an owners.modules entry, a CODEOWNERS rule, or an ownership alias that maps the dominant maintainer to a team.",
			Confidence:     0.7,
		})
	}
	if pkg.AuthorCount90d > cfg.Ownership.MaxAuthorCount90d {
		findings = append(findings, report.Finding{
			ID:          "FL-OWN-002",
			Category:    report.CategoryOwnership,
			Severity:    report.SeverityMedium,
			Title:       "High author count in last 90 days",
			Description: "Several distinct authors changed this package in the last 90 days.",
			Evidence: []report.Evidence{
				evidence("author_count_90d", pkg.AuthorCount90d, "git"),
				evidence("max_author_count_90d", cfg.Ownership.MaxAuthorCount90d, "policy"),
			},
			Recommendation: "Confirm ownership, review handoff paths, and make package stewardship explicit.",
			Confidence:     0.75,
		})
	}
	if pkg.ReverseImportCount >= 5 {
		findings = append(findings, report.Finding{
			ID:             "FL-DEP-001",
			Category:       report.CategoryComplexity,
			Severity:       report.SeverityMedium,
			Title:          "High reverse import count",
			Description:    "Many loaded packages import this package, increasing change blast radius.",
			Evidence:       []report.Evidence{evidence("reverse_import_count", pkg.ReverseImportCount, "import_graph")},
			Recommendation: "Keep APIs stable, add focused tests, and consider splitting responsibilities if the package keeps growing.",
			Confidence:     0.75,
		})
	}
	if pkg.FileCount > 0 && float64(pkg.GeneratedFileCount)/float64(pkg.FileCount) >= 0.5 {
		findings = append(findings, report.Finding{
			ID:          "FL-GEN-001",
			Category:    report.CategoryComplexity,
			Severity:    report.SeverityLow,
			Title:       "Generated-code-heavy package",
			Description: "Generated files dominate this package, so structural metrics may be less actionable.",
			Evidence: []report.Evidence{
				evidence("generated_file_count", pkg.GeneratedFileCount, "filesystem"),
				evidence("file_count", pkg.FileCount, "filesystem"),
			},
			Recommendation: "Interpret package metrics cautiously and prefer generator-level ownership and testing checks.",
			Confidence:     0.8,
		})
	}

	return Result{
		RiskScore:       round2(clamp(risk, 0, 100)),
		ComplexityScore: round2(breakdown.ComplexityScore),
		Breakdown:       roundBreakdown(breakdown),
		Evidence:        ev,
		Findings:        findings,
	}
}

func coverageGapScore(coveragePct *float64, cfg policy.Config) float64 {
	if coveragePct == nil {
		return 50
	}
	minCoverage := cfg.Coverage.MinPackageCoverage
	if minCoverage <= 0 {
		return 0
	}
	return clamp((minCoverage-*coveragePct)/minCoverage*100.0, 0, 100)
}

func complexity(pkg report.PackageRisk) float64 {
	locComponent := clamp(float64(pkg.LOC)/1000.0*100.0, 0, 100)
	importComponent := clamp(float64(pkg.ImportCount)/20.0*100.0, 0, 100)
	fileComponent := clamp(float64(pkg.FileCount-pkg.GeneratedFileCount)/30.0*100.0, 0, 100)
	return locComponent*0.45 + importComponent*0.35 + fileComponent*0.20
}

func roundBreakdown(b report.ScoreBreakdown) report.ScoreBreakdown {
	return report.ScoreBreakdown{
		ChurnScore:                round2(b.ChurnScore),
		CoverageGapScore:          round2(b.CoverageGapScore),
		ComplexityScore:           round2(b.ComplexityScore),
		OwnershipEntropyScore:     round2(b.OwnershipEntropyScore),
		DependencyCentralityScore: round2(b.DependencyCentralityScore),
	}
}

func clamp(v, min, max float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return min
	}
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}
