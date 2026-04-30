// Package baseline implements local governance baselines for Faultline scans.
package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/faultline-go/faultline/internal/report"
)

const SchemaVersion = 1

// Baseline is the auditable snapshot checked into or archived by a team.
// It stores metrics and finding identities, not source code.
type Baseline struct {
	SchemaVersion     int                        `json:"schema_version"`
	CreatedAt         time.Time                  `json:"created_at"`
	FaultlineVersion  string                     `json:"faultline_version"`
	RepoFingerprint   string                     `json:"repo_fingerprint,omitempty"`
	ConfigHash        string                     `json:"config_hash,omitempty"`
	PackageRisks      []PackageRisk              `json:"package_risks"`
	FindingIdentities []FindingIdentity          `json:"finding_identities"`
	Suppressions      []report.SuppressedFinding `json:"suppressions,omitempty"`
	Summary           report.Summary             `json:"summary"`
	ConfigSummary     report.ConfigSummary       `json:"config_summary"`
	Warnings          []report.Warning           `json:"warnings,omitempty"`
}

// PackageRisk is the subset of package risk data needed for ratcheting.
type PackageRisk struct {
	ImportPath     string                `json:"import_path"`
	Dir            string                `json:"dir,omitempty"`
	RiskScore      float64               `json:"risk_score"`
	ScoreBreakdown report.ScoreBreakdown `json:"score_breakdown"`
	CoveragePct    *float64              `json:"coverage_pct,omitempty"`
	Findings       []FindingIdentity     `json:"findings,omitempty"`
}

// FindingIdentity is a stable, source-free identity for a finding.
type FindingIdentity struct {
	Key               string                  `json:"key"`
	ID                string                  `json:"id"`
	PackageImportPath string                  `json:"package_import_path"`
	Category          report.Category         `json:"category"`
	Severity          report.Severity         `json:"severity"`
	Title             string                  `json:"title"`
	Location          string                  `json:"location,omitempty"`
	Evidence          []report.Evidence       `json:"evidence,omitempty"`
	Suppressed        bool                    `json:"suppressed,omitempty"`
	Suppression       *report.SuppressionInfo `json:"suppression,omitempty"`
}

type PackageDelta struct {
	ImportPath        string  `json:"import_path"`
	PreviousRiskScore float64 `json:"previous_risk_score"`
	CurrentRiskScore  float64 `json:"current_risk_score"`
	RiskDelta         float64 `json:"risk_delta"`
}

type CheckSummary struct {
	NewFindings        int     `json:"new_findings"`
	ResolvedFindings   int     `json:"resolved_findings"`
	SuppressedFindings int     `json:"suppressed_findings"`
	WorsenedPackages   int     `json:"worsened_packages"`
	ImprovedPackages   int     `json:"improved_packages"`
	FailOnNew          string  `json:"fail_on_new"`
	FailOnRiskDelta    float64 `json:"fail_on_risk_delta"`
	Failed             bool    `json:"failed"`
}

type CheckResult struct {
	SchemaVersion       int               `json:"schema_version"`
	CheckedAt           time.Time         `json:"checked_at"`
	BaselineCreatedAt   time.Time         `json:"baseline_created_at"`
	BaselineVersion     string            `json:"baseline_faultline_version"`
	CurrentVersion      string            `json:"current_faultline_version"`
	BaselineFingerprint string            `json:"baseline_repo_fingerprint,omitempty"`
	CurrentFingerprint  string            `json:"current_repo_fingerprint,omitempty"`
	ConfigHash          string            `json:"config_hash,omitempty"`
	CurrentConfigHash   string            `json:"current_config_hash,omitempty"`
	Warnings            []report.Warning  `json:"warnings,omitempty"`
	NewFindings         []FindingIdentity `json:"new_findings,omitempty"`
	ResolvedFindings    []FindingIdentity `json:"resolved_findings,omitempty"`
	SuppressedFindings  []FindingIdentity `json:"suppressed_findings,omitempty"`
	WorsenedPackages    []PackageDelta    `json:"worsened_packages,omitempty"`
	ImprovedPackages    []PackageDelta    `json:"improved_packages,omitempty"`
	Summary             CheckSummary      `json:"summary"`
}

type CheckOptions struct {
	FailOnNew       report.Severity
	FailOnRiskDelta float64
}

// Create builds a deterministic baseline from a scan report.
func Create(rep *report.Report) Baseline {
	b := Baseline{
		SchemaVersion:     SchemaVersion,
		CreatedAt:         rep.Meta.ScanTime.UTC(),
		FaultlineVersion:  rep.Meta.Version,
		RepoFingerprint:   rep.Meta.RepoFingerprint,
		ConfigHash:        rep.Meta.ConfigHash,
		Suppressions:      append([]report.SuppressedFinding{}, rep.SuppressedFindings...),
		Summary:           rep.Summary,
		ConfigSummary:     rep.ConfigSummary,
		Warnings:          append([]report.Warning{}, rep.Warnings...),
		PackageRisks:      make([]PackageRisk, 0, len(rep.Packages)),
		FindingIdentities: nil,
	}
	for _, pkg := range sortedPackages(rep.Packages) {
		var coverage *float64
		if pkg.CoveragePct != nil {
			value := *pkg.CoveragePct
			coverage = &value
		}
		pb := PackageRisk{
			ImportPath:     pkg.ImportPath,
			Dir:            pkg.Dir,
			RiskScore:      round2(pkg.RiskScore),
			ScoreBreakdown: pkg.ScoreBreakdown,
			CoveragePct:    coverage,
		}
		for _, finding := range sortedFindings(pkg.Findings) {
			identity := Identity(pkg, finding)
			pb.Findings = append(pb.Findings, identity)
			b.FindingIdentities = append(b.FindingIdentities, identity)
		}
		b.PackageRisks = append(b.PackageRisks, pb)
	}
	sortFindingIdentities(b.FindingIdentities)
	sort.SliceStable(b.Suppressions, func(i, j int) bool {
		if b.Suppressions[i].PackageImportPath != b.Suppressions[j].PackageImportPath {
			return b.Suppressions[i].PackageImportPath < b.Suppressions[j].PackageImportPath
		}
		return b.Suppressions[i].FindingID < b.Suppressions[j].FindingID
	})
	sortWarnings(b.Warnings)
	return b
}

// Compare checks the current scan against a stored baseline.
func Compare(base Baseline, current *report.Report, opts CheckOptions) CheckResult {
	result := CheckResult{
		SchemaVersion:       SchemaVersion,
		CheckedAt:           current.Meta.ScanTime.UTC(),
		BaselineCreatedAt:   base.CreatedAt.UTC(),
		BaselineVersion:     base.FaultlineVersion,
		CurrentVersion:      current.Meta.Version,
		BaselineFingerprint: base.RepoFingerprint,
		CurrentFingerprint:  current.Meta.RepoFingerprint,
		ConfigHash:          base.ConfigHash,
		CurrentConfigHash:   current.Meta.ConfigHash,
		Warnings:            append([]report.Warning{}, current.Warnings...),
	}
	if base.RepoFingerprint != "" && current.Meta.RepoFingerprint != "" && base.RepoFingerprint != current.Meta.RepoFingerprint {
		result.Warnings = append(result.Warnings, report.Warning{
			Source:  "baseline",
			Message: "baseline repo fingerprint does not match current repo fingerprint",
		})
	}
	if base.ConfigHash != "" && current.Meta.ConfigHash != "" && base.ConfigHash != current.Meta.ConfigHash {
		result.Warnings = append(result.Warnings, report.Warning{
			Source:  "baseline",
			Message: "baseline config hash does not match current config hash",
		})
	}

	baseFindings := make(map[string]FindingIdentity)
	baseUnsuppressed := make(map[string]FindingIdentity)
	for _, finding := range base.FindingIdentities {
		baseFindings[finding.Key] = finding
		if !finding.Suppressed {
			baseUnsuppressed[finding.Key] = finding
		}
	}

	currentAll := make(map[string]FindingIdentity)
	for _, pkg := range current.Packages {
		for _, finding := range pkg.Findings {
			identity := Identity(pkg, finding)
			currentAll[identity.Key] = identity
			if finding.Suppressed {
				result.SuppressedFindings = append(result.SuppressedFindings, identity)
				continue
			}
			if _, ok := baseFindings[identity.Key]; !ok {
				result.NewFindings = append(result.NewFindings, identity)
			}
		}
	}
	for key, finding := range baseUnsuppressed {
		if _, ok := currentAll[key]; !ok {
			result.ResolvedFindings = append(result.ResolvedFindings, finding)
		}
	}

	basePackages := make(map[string]PackageRisk, len(base.PackageRisks))
	for _, pkg := range base.PackageRisks {
		basePackages[pkg.ImportPath] = pkg
	}
	for _, pkg := range current.Packages {
		prev, ok := basePackages[pkg.ImportPath]
		if !ok {
			continue
		}
		delta := round2(pkg.RiskScore - prev.RiskScore)
		if delta > 0 {
			result.WorsenedPackages = append(result.WorsenedPackages, PackageDelta{
				ImportPath:        pkg.ImportPath,
				PreviousRiskScore: prev.RiskScore,
				CurrentRiskScore:  round2(pkg.RiskScore),
				RiskDelta:         delta,
			})
		} else if delta < 0 {
			result.ImprovedPackages = append(result.ImprovedPackages, PackageDelta{
				ImportPath:        pkg.ImportPath,
				PreviousRiskScore: prev.RiskScore,
				CurrentRiskScore:  round2(pkg.RiskScore),
				RiskDelta:         delta,
			})
		}
	}

	sortFindingIdentities(result.NewFindings)
	sortFindingIdentities(result.ResolvedFindings)
	sortFindingIdentities(result.SuppressedFindings)
	sortPackageDeltas(result.WorsenedPackages, true)
	sortPackageDeltas(result.ImprovedPackages, false)
	sortWarnings(result.Warnings)

	failOnNew := string(opts.FailOnNew)
	if failOnNew == "" {
		failOnNew = "none"
	}
	result.Summary = CheckSummary{
		NewFindings:        len(result.NewFindings),
		ResolvedFindings:   len(result.ResolvedFindings),
		SuppressedFindings: len(result.SuppressedFindings),
		WorsenedPackages:   len(result.WorsenedPackages),
		ImprovedPackages:   len(result.ImprovedPackages),
		FailOnNew:          failOnNew,
		FailOnRiskDelta:    opts.FailOnRiskDelta,
	}
	result.Summary.Failed = HasViolations(result, opts)
	return result
}

func HasViolations(result CheckResult, opts CheckOptions) bool {
	if opts.FailOnNew != "" {
		for _, finding := range result.NewFindings {
			if severityRank(finding.Severity) >= severityRank(opts.FailOnNew) {
				return true
			}
		}
	}
	if opts.FailOnRiskDelta >= 0 {
		for _, pkg := range result.WorsenedPackages {
			if pkg.RiskDelta > opts.FailOnRiskDelta {
				return true
			}
		}
	}
	return false
}

// Identity returns a stable finding key from package, finding category, relevant
// evidence values, and the package-level location available in the report.
func Identity(pkg report.PackageRisk, finding report.Finding) FindingIdentity {
	evidence := stableEvidence(finding.Evidence)
	location := locationFor(pkg, finding)
	parts := []string{
		finding.ID,
		pkg.ImportPath,
		string(finding.Category),
		location,
	}
	for _, ev := range evidence {
		parts = append(parts, ev.Key, ev.Value)
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	identity := FindingIdentity{
		Key:               hex.EncodeToString(sum[:]),
		ID:                finding.ID,
		PackageImportPath: pkg.ImportPath,
		Category:          finding.Category,
		Severity:          finding.Severity,
		Title:             finding.Title,
		Location:          location,
		Evidence:          evidence,
		Suppressed:        finding.Suppressed,
		Suppression:       finding.Suppression,
	}
	return identity
}

func MarshalBaseline(b Baseline) ([]byte, error) {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal baseline: %w", err)
	}
	return append(data, '\n'), nil
}

func MarshalCheckJSON(result CheckResult) ([]byte, error) {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal baseline check result: %w", err)
	}
	return append(data, '\n'), nil
}

func stableEvidence(items []report.Evidence) []report.Evidence {
	out := make([]report.Evidence, 0, len(items))
	for _, item := range items {
		if strings.TrimSpace(item.Key) == "" {
			continue
		}
		out = append(out, item)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Key != out[j].Key {
			return out[i].Key < out[j].Key
		}
		if out[i].Value != out[j].Value {
			return out[i].Value < out[j].Value
		}
		return out[i].Source < out[j].Source
	})
	return out
}

func locationFor(pkg report.PackageRisk, finding report.Finding) string {
	if finding.ID == "FL-BND-001" {
		if matched := evidenceValue(finding.Evidence, "matched_import"); matched != "" {
			return pkg.Dir + " imports " + matched
		}
	}
	return pkg.Dir
}

func evidenceValue(items []report.Evidence, key string) string {
	for _, item := range items {
		if item.Key == key {
			return item.Value
		}
	}
	return ""
}

func sortedPackages(pkgs []report.PackageRisk) []report.PackageRisk {
	out := append([]report.PackageRisk{}, pkgs...)
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].ImportPath < out[j].ImportPath
	})
	return out
}

func sortedFindings(findings []report.Finding) []report.Finding {
	out := append([]report.Finding{}, findings...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].ID != out[j].ID {
			return out[i].ID < out[j].ID
		}
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].Title < out[j].Title
	})
	return out
}

func sortFindingIdentities(findings []FindingIdentity) {
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].PackageImportPath != findings[j].PackageImportPath {
			return findings[i].PackageImportPath < findings[j].PackageImportPath
		}
		if findings[i].ID != findings[j].ID {
			return findings[i].ID < findings[j].ID
		}
		return findings[i].Key < findings[j].Key
	})
}

func sortPackageDeltas(pkgs []PackageDelta, descending bool) {
	sort.SliceStable(pkgs, func(i, j int) bool {
		if pkgs[i].RiskDelta == pkgs[j].RiskDelta {
			return pkgs[i].ImportPath < pkgs[j].ImportPath
		}
		if descending {
			return pkgs[i].RiskDelta > pkgs[j].RiskDelta
		}
		return pkgs[i].RiskDelta < pkgs[j].RiskDelta
	})
}

func sortWarnings(warnings []report.Warning) {
	sort.SliceStable(warnings, func(i, j int) bool {
		if warnings[i].Source != warnings[j].Source {
			return warnings[i].Source < warnings[j].Source
		}
		return warnings[i].Message < warnings[j].Message
	})
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

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}
