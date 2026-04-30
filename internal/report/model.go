package report

import "time"

// Category classifies the nature of a finding.
type Category string

const (
	CategoryOwnership  Category = "OWNERSHIP"
	CategoryChurn      Category = "CHURN"
	CategoryCoverage   Category = "COVERAGE"
	CategoryComplexity Category = "COMPLEXITY"
	CategoryBoundary   Category = "BOUNDARY"
	CategoryDependency Category = "DEPENDENCY"
)

// Severity indicates how urgent a finding is.
type Severity string

const (
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// Evidence is a named data point that supports a finding or score.
type Evidence struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Source string `json:"source"`
}

// OwnerCandidate records a possible package owner and where that signal came from.
type OwnerCandidate struct {
	Owner      string  `json:"owner"`
	Source     string  `json:"source"`
	Confidence float64 `json:"confidence"`
	Detail     string  `json:"detail,omitempty"`
}

// Warning is a non-fatal issue encountered during a scan.
type Warning struct {
	Message string `json:"message"`
	Source  string `json:"source"`
}

// ScoreBreakdown contains normalized 0-100 component scores.
type ScoreBreakdown struct {
	ChurnScore                float64 `json:"churn_score"`
	CoverageGapScore          float64 `json:"coverage_gap_score"`
	ComplexityScore           float64 `json:"complexity_score"`
	OwnershipEntropyScore     float64 `json:"ownership_entropy_score"`
	DependencyCentralityScore float64 `json:"dependency_centrality_score"`
}

// Finding is a specific risk signal detected in a package.
type Finding struct {
	ID             string           `json:"id"`
	Category       Category         `json:"category"`
	Severity       Severity         `json:"severity"`
	Title          string           `json:"title"`
	Description    string           `json:"description"`
	Evidence       []Evidence       `json:"evidence,omitempty"`
	Recommendation string           `json:"recommendation"`
	Confidence     float64          `json:"confidence"`
	Suppressed     bool             `json:"suppressed,omitempty"`
	Suppression    *SuppressionInfo `json:"suppression,omitempty"`
}

// SuppressionInfo records the waiver metadata applied to a finding.
type SuppressionInfo struct {
	Reason   string `json:"reason"`
	Owner    string `json:"owner"`
	Expires  string `json:"expires"`
	Package  string `json:"package"`
	Category string `json:"category,omitempty"`
	Created  string `json:"created,omitempty"`
}

// SuppressedFinding is a top-level audit entry for suppressed findings.
type SuppressedFinding struct {
	PackageImportPath string          `json:"package_import_path"`
	FindingID         string          `json:"finding_id"`
	Category          Category        `json:"category"`
	Severity          Severity        `json:"severity"`
	Suppression       SuppressionInfo `json:"suppression"`
}

// PackageRisk is the complete risk profile for a single Go package.
type PackageRisk struct {
	PackageID             string           `json:"package_id"`
	ImportPath            string           `json:"import_path"`
	Dir                   string           `json:"dir"`
	ModulePath            string           `json:"module_path,omitempty"`
	ModuleRoot            string           `json:"module_root,omitempty"`
	LOC                   int              `json:"loc"`
	TestLOC               int              `json:"test_loc"`
	GeneratedLOC          int              `json:"generated_loc"`
	FileCount             int              `json:"file_count"`
	GeneratedFileCount    int              `json:"generated_file_count"`
	ImportCount           int              `json:"import_count"`
	ReverseImportCount    int              `json:"reverse_import_count"`
	DirectInternalImports []string         `json:"direct_internal_imports,omitempty"`
	CoveragePct           *float64         `json:"coverage_pct,omitempty"`
	Churn30d              int              `json:"churn_30d"`
	Churn90d              int              `json:"churn_90d"`
	AuthorCount90d        int              `json:"author_count_90d"`
	DominantOwner         *string          `json:"dominant_owner,omitempty"`
	OwnerSource           string           `json:"owner_source,omitempty"`
	CandidateOwners       []OwnerCandidate `json:"candidate_owners,omitempty"`
	OwnershipConfidence   float64          `json:"ownership_confidence,omitempty"`
	OwnershipEntropy      float64          `json:"ownership_entropy"`
	ComplexityScore       float64          `json:"complexity_score"`
	RiskScore             float64          `json:"risk_score"`
	PreviousRiskScore     *float64         `json:"previous_risk_score,omitempty"`
	RiskDelta             *float64         `json:"risk_delta,omitempty"`
	Trend                 string           `json:"trend,omitempty"`
	ScoreBreakdown        ScoreBreakdown   `json:"score_breakdown"`
	Findings              []Finding        `json:"findings,omitempty"`
	Evidence              []Evidence       `json:"evidence,omitempty"`
	LoadErrors            []string         `json:"load_errors,omitempty"`
}

// DependencyRisk records local Go module dependency metadata and structural
// dependency risk signals. It is intentionally not a vulnerability record.
type DependencyRisk struct {
	SourceModulePath      string             `json:"source_module_path,omitempty"`
	SourceModuleRoot      string             `json:"source_module_root,omitempty"`
	ModulePath            string             `json:"module_path"`
	Version               string             `json:"version,omitempty"`
	Indirect              bool               `json:"indirect"`
	GoSumPresent          bool               `json:"go_sum_present"`
	Replace               *DependencyReplace `json:"replace,omitempty"`
	LocalReplace          bool               `json:"local_replace,omitempty"`
	CrossModuleReplace    bool               `json:"cross_module_replace,omitempty"`
	ReplaceModulePath     string             `json:"replace_module_path,omitempty"`
	ReplaceModuleRoot     string             `json:"replace_module_root,omitempty"`
	Used                  bool               `json:"used"`
	ImportCount           int                `json:"import_count"`
	ImportingPackageCount int                `json:"importing_package_count"`
	ImportingPackages     []string           `json:"importing_packages,omitempty"`
	Findings              []Finding          `json:"findings,omitempty"`
	Evidence              []Evidence         `json:"evidence,omitempty"`
}

// DependencyReplace describes a go.mod replace directive.
type DependencyReplace struct {
	OldPath    string `json:"old_path"`
	OldVersion string `json:"old_version,omitempty"`
	NewPath    string `json:"new_path"`
	NewVersion string `json:"new_version,omitempty"`
}

// ExternalToolResult records optional output from tools Faultline did not run by
// default. It exists so reports can distinguish structural analysis from
// external vulnerability tooling.
type ExternalToolResult struct {
	Name     string `json:"name"`
	Mode     string `json:"mode"`
	ToolPath string `json:"tool_path,omitempty"`
	Ran      bool   `json:"ran"`
	ExitCode int    `json:"exit_code,omitempty"`
	Output   string `json:"json_output,omitempty"`
	Error    string `json:"error,omitempty"`
}

// ModuleInfo describes a discovered Go module in the repository.
type ModuleInfo struct {
	ModulePath       string `json:"module_path"`
	ModuleRoot       string `json:"module_root"`
	GoModPath        string `json:"go_mod_path"`
	IncludedByGoWork bool   `json:"included_by_go_work"`
	Selected         bool   `json:"selected"`
}

// ScanMeta holds metadata about the scan run itself.
type ScanMeta struct {
	Version            string           `json:"version"`
	Commit             string           `json:"commit"`
	ScanTime           time.Time        `json:"scan_time"`
	RepoPath           string           `json:"repo_path"`
	RepoDisplayName    string           `json:"repo_display_name,omitempty"`
	RepoFingerprint    string           `json:"repo_fingerprint,omitempty"`
	HistoryMatchMethod string           `json:"history_match_method,omitempty"`
	Patterns           []string         `json:"patterns"`
	BuildTags          []string         `json:"build_tags,omitempty"`
	ConfigPath         string           `json:"config_path,omitempty"`
	ConfigHash         string           `json:"config_hash,omitempty"`
	RulePacks          []ConfigRulePack `json:"rule_packs,omitempty"`
	GoWorkPath         string           `json:"go_work_path,omitempty"`
	ScanID             int64            `json:"scan_id,omitempty"`
}

type ConfigRulePack struct {
	Path        string `json:"path"`
	ContentHash string `json:"content_hash,omitempty"`
	Imported    bool   `json:"imported"`
}

// ConfigSummary records the policy inputs that affected scoring.
type ConfigSummary struct {
	OwnershipRequireCodeowners bool    `json:"ownership_require_codeowners"`
	OwnershipMaxAuthorCount90d int     `json:"ownership_max_author_count_90d"`
	CoverageMinPackageCoverage float64 `json:"coverage_min_package_coverage"`
	BoundaryRuleCount          int     `json:"boundary_rule_count"`
	SuppressionCount           int     `json:"suppression_count"`
}

// Report is the top-level output of a faultline scan.
type Report struct {
	Meta               ScanMeta            `json:"meta"`
	Warnings           []Warning           `json:"warnings,omitempty"`
	ScoringVersion     string              `json:"scoring_version"`
	ConfigSummary      ConfigSummary       `json:"config_summary"`
	SuppressedFindings []SuppressedFinding `json:"suppressed_findings,omitempty"`
	Modules            []ModuleInfo        `json:"modules,omitempty"`
	Dependencies       []DependencyRisk    `json:"dependencies,omitempty"`
	DependencyFindings []Finding           `json:"dependency_findings,omitempty"`
	Govulncheck        *ExternalToolResult `json:"govulncheck,omitempty"`
	Packages           []PackageRisk       `json:"packages"`
	Summary            Summary             `json:"summary"`
}

// Summary holds aggregate statistics for the report.
type Summary struct {
	TotalPackages          int     `json:"total_packages"`
	HighRiskCount          int     `json:"high_risk_count"`
	WarningCount           int     `json:"warning_count"`
	SuppressedCount        int     `json:"suppressed_count"`
	TotalFindings          int     `json:"total_findings"`
	CriticalCount          int     `json:"critical_count"`
	HighCount              int     `json:"high_count"`
	MediumCount            int     `json:"medium_count"`
	LowCount               int     `json:"low_count"`
	GeneratedFilePct       float64 `json:"generated_file_pct"`
	DependencyCount        int     `json:"dependency_count,omitempty"`
	DependencyFindingCount int     `json:"dependency_finding_count,omitempty"`
}

// ComputeSummary fills in aggregate counts from the packages list.
func ComputeSummary(pkgs []PackageRisk, warnings []Warning) Summary {
	return ComputeSummaryWithDependencies(pkgs, warnings, nil)
}

// ComputeSummaryWithDependencies fills in aggregate counts from packages and
// top-level dependency findings.
func ComputeSummaryWithDependencies(pkgs []PackageRisk, warnings []Warning, dependencyFindings []Finding) Summary {
	s := Summary{TotalPackages: len(pkgs), WarningCount: len(warnings)}
	totalFiles := 0
	generatedFiles := 0
	for _, p := range pkgs {
		totalFiles += p.FileCount
		generatedFiles += p.GeneratedFileCount
		if p.RiskScore >= 70 {
			s.HighRiskCount++
		}
		for _, f := range p.Findings {
			s.TotalFindings++
			if f.Suppressed {
				s.SuppressedCount++
				continue
			}
			switch f.Severity {
			case SeverityCritical:
				s.CriticalCount++
			case SeverityHigh:
				s.HighCount++
			case SeverityMedium:
				s.MediumCount++
			case SeverityLow:
				s.LowCount++
			}
		}
	}
	for _, f := range dependencyFindings {
		s.TotalFindings++
		s.DependencyFindingCount++
		if f.Suppressed {
			s.SuppressedCount++
			continue
		}
		switch f.Severity {
		case SeverityCritical:
			s.CriticalCount++
		case SeverityHigh:
			s.HighCount++
		case SeverityMedium:
			s.MediumCount++
		case SeverityLow:
			s.LowCount++
		}
	}
	if totalFiles > 0 {
		s.GeneratedFilePct = float64(generatedFiles) / float64(totalFiles) * 100
	}
	return s
}

// HasFindingAtOrAbove reports whether any finding reaches the requested threshold.
func HasFindingAtOrAbove(pkgs []PackageRisk, threshold Severity, extraFindings ...[]Finding) bool {
	for _, p := range pkgs {
		for _, f := range p.Findings {
			if f.Suppressed {
				continue
			}
			if severityRank(f.Severity) >= severityRank(threshold) {
				return true
			}
		}
	}
	for _, findings := range extraFindings {
		for _, f := range findings {
			if f.Suppressed {
				continue
			}
			if severityRank(f.Severity) >= severityRank(threshold) {
				return true
			}
		}
	}
	return false
}

func severityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}
