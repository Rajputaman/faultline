// Package export defines the public metadata-only contract that downstream
// systems can consume without linking to Faultline's internal scanner packages.
package export

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/faultline-go/faultline/internal/report"
)

const (
	// SnapshotSchemaVersion identifies the metadata snapshot schema emitted by
	// this package. It is versioned separately from the full scan report JSON so
	// commercial integrations can evolve without depending on internal structs.
	SnapshotSchemaVersion = "faultline.snapshot.v1"
)

// Snapshot is the stable, metadata-only export shape intended for paid
// integrations, portfolio rollups, and future upload bundles. It intentionally
// omits package directories, source file contents, and raw code snippets.
type Snapshot struct {
	SchemaVersion string                `json:"schema_version"`
	CreatedAt     time.Time             `json:"created_at"`
	Source        SourceMetadata        `json:"source"`
	Config        ConfigMetadata        `json:"config"`
	Summary       Summary               `json:"summary"`
	Packages      []PackageSnapshot     `json:"packages"`
	Findings      []FindingSnapshot     `json:"findings,omitempty"`
	Suppressions  []SuppressionSnapshot `json:"suppressions,omitempty"`
	Dependencies  []DependencySnapshot  `json:"dependencies,omitempty"`
	Incidents     []IncidentSnapshot    `json:"incidents,omitempty"`
	Warnings      []WarningSnapshot     `json:"warnings,omitempty"`
}

// SourceMetadata describes the scan source without including source code.
type SourceMetadata struct {
	FaultlineVersion string    `json:"faultline_version"`
	FaultlineCommit  string    `json:"faultline_commit,omitempty"`
	ScoringVersion   string    `json:"scoring_version"`
	ScanTime         time.Time `json:"scan_time"`
	ScanID           int64     `json:"scan_id,omitempty"`
	RepoFingerprint  string    `json:"repo_fingerprint,omitempty"`
	RepoDisplayName  string    `json:"repo_display_name,omitempty"`
}

// ConfigMetadata captures the policy identity that affected the scan.
type ConfigMetadata struct {
	ConfigHash         string         `json:"config_hash,omitempty"`
	BoundaryRuleCount  int            `json:"boundary_rule_count"`
	SuppressionCount   int            `json:"suppression_count"`
	RulePacks          []RulePack     `json:"rule_packs,omitempty"`
	HistoryMatchMethod string         `json:"history_match_method,omitempty"`
	GoWorkPathPresent  bool           `json:"go_work_path_present"`
	BuildTags          []string       `json:"build_tags,omitempty"`
	Patterns           []string       `json:"patterns,omitempty"`
	Modules            []ModuleRecord `json:"modules,omitempty"`
}

// RulePack is an audit record for a resolved local rule pack.
type RulePack struct {
	Path        string `json:"path"`
	ContentHash string `json:"content_hash,omitempty"`
	Imported    bool   `json:"imported"`
}

// ModuleRecord records module identity without storing files.
type ModuleRecord struct {
	ModulePath       string `json:"module_path"`
	ModuleRoot       string `json:"module_root,omitempty"`
	IncludedByGoWork bool   `json:"included_by_go_work"`
	Selected         bool   `json:"selected"`
}

// Summary contains portfolio-safe aggregate counts.
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

// PackageSnapshot is the package-level risk record used by upload bundles.
type PackageSnapshot struct {
	PackageID          string          `json:"package_id"`
	ImportPath         string          `json:"import_path"`
	ModulePath         string          `json:"module_path,omitempty"`
	ModuleRoot         string          `json:"module_root,omitempty"`
	RiskScore          float64         `json:"risk_score"`
	PreviousRiskScore  *float64        `json:"previous_risk_score,omitempty"`
	RiskDelta          *float64        `json:"risk_delta,omitempty"`
	Trend              string          `json:"trend,omitempty"`
	ScoreBreakdown     ScoreBreakdown  `json:"score_breakdown"`
	CoveragePct        *float64        `json:"coverage_pct,omitempty"`
	Churn30d           int             `json:"churn_30d"`
	Churn90d           int             `json:"churn_90d"`
	AuthorCount90d     int             `json:"author_count_90d"`
	Owner              string          `json:"owner,omitempty"`
	OwnerSource        string          `json:"owner_source,omitempty"`
	ReverseImportCount int             `json:"reverse_import_count"`
	FindingIdentities  []string        `json:"finding_identities,omitempty"`
	IncidentIDs        []string        `json:"incident_ids,omitempty"`
	IncidentCount      int             `json:"incident_count,omitempty"`
	Evidence           []EvidencePoint `json:"evidence,omitempty"`
}

// ScoreBreakdown contains normalized 0-100 component scores.
type ScoreBreakdown struct {
	ChurnScore                float64 `json:"churn_score"`
	CoverageGapScore          float64 `json:"coverage_gap_score"`
	ComplexityScore           float64 `json:"complexity_score"`
	OwnershipEntropyScore     float64 `json:"ownership_entropy_score"`
	DependencyCentralityScore float64 `json:"dependency_centrality_score"`
}

// FindingSnapshot is a stable finding record for cross-repo governance.
type FindingSnapshot struct {
	Identity          string           `json:"identity"`
	ID                string           `json:"id"`
	Category          string           `json:"category"`
	Severity          string           `json:"severity"`
	PackageImportPath string           `json:"package_import_path,omitempty"`
	ModulePath        string           `json:"module_path,omitempty"`
	Title             string           `json:"title"`
	Suppressed        bool             `json:"suppressed"`
	Suppression       *SuppressionInfo `json:"suppression,omitempty"`
	Evidence          []EvidencePoint  `json:"evidence,omitempty"`
}

// SuppressionSnapshot preserves waiver metadata without deleting risk records.
type SuppressionSnapshot struct {
	FindingIdentity   string          `json:"finding_identity"`
	FindingID         string          `json:"finding_id"`
	PackageImportPath string          `json:"package_import_path"`
	Category          string          `json:"category,omitempty"`
	Severity          string          `json:"severity,omitempty"`
	Suppression       SuppressionInfo `json:"suppression"`
}

// SuppressionInfo is the exported suppression metadata.
type SuppressionInfo struct {
	Reason  string `json:"reason"`
	Owner   string `json:"owner"`
	Expires string `json:"expires"`
	Package string `json:"package"`
	Created string `json:"created,omitempty"`
}

// DependencySnapshot records structural module dependency risk metadata.
type DependencySnapshot struct {
	SourceModulePath   string   `json:"source_module_path,omitempty"`
	SourceModuleRoot   string   `json:"source_module_root,omitempty"`
	ModulePath         string   `json:"module_path"`
	Version            string   `json:"version,omitempty"`
	Indirect           bool     `json:"indirect"`
	LocalReplace       bool     `json:"local_replace,omitempty"`
	CrossModuleReplace bool     `json:"cross_module_replace,omitempty"`
	PseudoVersion      bool     `json:"pseudo_version,omitempty"`
	FindingIdentities  []string `json:"finding_identities,omitempty"`
}

// IncidentSnapshot records an operational incident included in the snapshot.
type IncidentSnapshot struct {
	ID               string     `json:"id"`
	Title            string     `json:"title"`
	Severity         string     `json:"severity"`
	StartedAt        time.Time  `json:"started_at"`
	ResolvedAt       *time.Time `json:"resolved_at,omitempty"`
	AffectedPackages []string   `json:"affected_packages"`
	URL              string     `json:"url,omitempty"`
}

// EvidencePoint is a sanitized evidence item. Evidence values should remain
// metadata-only and must not contain source code snippets.
type EvidencePoint struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Source string `json:"source"`
}

// WarningSnapshot records non-fatal scanner warnings.
type WarningSnapshot struct {
	Source  string `json:"source"`
	Message string `json:"message"`
}

// FromReportJSON converts a normal Faultline scan JSON report into a
// metadata-only snapshot. This is the preferred boundary for commercial
// ingestion because it works with released OSS binaries and does not require
// source-code upload.
func FromReportJSON(data []byte) (*Snapshot, error) {
	var rep report.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("parse faultline report JSON: %w", err)
	}
	return fromReport(&rep), nil
}

// MarshalJSON returns deterministic, pretty JSON for a snapshot.
func MarshalJSON(snapshot *Snapshot) ([]byte, error) {
	if snapshot == nil {
		return nil, fmt.Errorf("snapshot is nil")
	}
	normalize(snapshot)
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal faultline snapshot: %w", err)
	}
	return append(data, '\n'), nil
}

func fromReport(rep *report.Report) *Snapshot {
	snapshot := &Snapshot{
		SchemaVersion: SnapshotSchemaVersion,
		CreatedAt:     rep.Meta.ScanTime,
		Source: SourceMetadata{
			FaultlineVersion: rep.Meta.Version,
			FaultlineCommit:  rep.Meta.Commit,
			ScoringVersion:   rep.ScoringVersion,
			ScanTime:         rep.Meta.ScanTime,
			ScanID:           rep.Meta.ScanID,
			RepoFingerprint:  rep.Meta.RepoFingerprint,
			RepoDisplayName:  rep.Meta.RepoDisplayName,
		},
		Config: ConfigMetadata{
			ConfigHash:         rep.Meta.ConfigHash,
			BoundaryRuleCount:  rep.ConfigSummary.BoundaryRuleCount,
			SuppressionCount:   rep.ConfigSummary.SuppressionCount,
			HistoryMatchMethod: rep.Meta.HistoryMatchMethod,
			GoWorkPathPresent:  rep.Meta.GoWorkPath != "",
			BuildTags:          append([]string{}, rep.Meta.BuildTags...),
			Patterns:           append([]string{}, rep.Meta.Patterns...),
		},
		Summary: Summary{
			TotalPackages:          rep.Summary.TotalPackages,
			HighRiskCount:          rep.Summary.HighRiskCount,
			WarningCount:           rep.Summary.WarningCount,
			SuppressedCount:        rep.Summary.SuppressedCount,
			TotalFindings:          rep.Summary.TotalFindings,
			CriticalCount:          rep.Summary.CriticalCount,
			HighCount:              rep.Summary.HighCount,
			MediumCount:            rep.Summary.MediumCount,
			LowCount:               rep.Summary.LowCount,
			GeneratedFilePct:       rep.Summary.GeneratedFilePct,
			DependencyCount:        rep.Summary.DependencyCount,
			DependencyFindingCount: rep.Summary.DependencyFindingCount,
		},
	}
	for _, pack := range rep.Meta.RulePacks {
		snapshot.Config.RulePacks = append(snapshot.Config.RulePacks, RulePack(pack))
	}
	for _, module := range rep.Modules {
		snapshot.Config.Modules = append(snapshot.Config.Modules, ModuleRecord{
			ModulePath:       module.ModulePath,
			ModuleRoot:       module.ModuleRoot,
			IncludedByGoWork: module.IncludedByGoWork,
			Selected:         module.Selected,
		})
	}
	for _, warning := range rep.Warnings {
		snapshot.Warnings = append(snapshot.Warnings, WarningSnapshot{Source: warning.Source, Message: warning.Message})
	}
	for _, inc := range rep.Incidents {
		snapshot.Incidents = append(snapshot.Incidents, IncidentSnapshot{
			ID:               inc.ID,
			Title:            inc.Title,
			Severity:         inc.Severity,
			StartedAt:        inc.StartedAt,
			ResolvedAt:       inc.ResolvedAt,
			AffectedPackages: append([]string{}, inc.AffectedPackages...),
			URL:              inc.URL,
		})
	}
	for _, pkg := range rep.Packages {
		owner := ""
		if pkg.DominantOwner != nil {
			owner = *pkg.DominantOwner
		}
		record := PackageSnapshot{
			PackageID:          pkg.PackageID,
			ImportPath:         pkg.ImportPath,
			ModulePath:         pkg.ModulePath,
			ModuleRoot:         pkg.ModuleRoot,
			RiskScore:          pkg.RiskScore,
			PreviousRiskScore:  pkg.PreviousRiskScore,
			RiskDelta:          pkg.RiskDelta,
			Trend:              pkg.Trend,
			ScoreBreakdown:     scoreBreakdown(pkg.ScoreBreakdown),
			CoveragePct:        pkg.CoveragePct,
			Churn30d:           pkg.Churn30d,
			Churn90d:           pkg.Churn90d,
			AuthorCount90d:     pkg.AuthorCount90d,
			Owner:              owner,
			OwnerSource:        pkg.OwnerSource,
			ReverseImportCount: pkg.ReverseImportCount,
			IncidentIDs:        append([]string{}, pkg.IncidentIDs...),
			IncidentCount:      pkg.IncidentCount,
			Evidence:           evidencePoints(pkg.Evidence),
		}
		for _, finding := range pkg.Findings {
			identity := findingIdentity(pkg.ImportPath, pkg.ModulePath, finding)
			record.FindingIdentities = append(record.FindingIdentities, identity)
			snapshot.Findings = append(snapshot.Findings, findingSnapshot(identity, pkg.ImportPath, pkg.ModulePath, finding))
			if finding.Suppressed && finding.Suppression != nil {
				snapshot.Suppressions = append(snapshot.Suppressions, SuppressionSnapshot{
					FindingIdentity:   identity,
					FindingID:         finding.ID,
					PackageImportPath: pkg.ImportPath,
					Category:          string(finding.Category),
					Severity:          string(finding.Severity),
					Suppression:       suppressionInfo(*finding.Suppression),
				})
			}
		}
		sort.Strings(record.FindingIdentities)
		snapshot.Packages = append(snapshot.Packages, record)
	}
	for _, finding := range rep.DependencyFindings {
		modulePath := evidenceValue(finding.Evidence, "module_path")
		identity := findingIdentity("", modulePath, finding)
		snapshot.Findings = append(snapshot.Findings, findingSnapshot(identity, "", modulePath, finding))
	}
	dependencyFindings := dependencyFindingIndex(rep.DependencyFindings)
	for _, dep := range rep.Dependencies {
		record := DependencySnapshot{
			SourceModulePath:   dep.SourceModulePath,
			SourceModuleRoot:   dep.SourceModuleRoot,
			ModulePath:         dep.ModulePath,
			Version:            dep.Version,
			Indirect:           dep.Indirect,
			LocalReplace:       dep.LocalReplace,
			CrossModuleReplace: dep.CrossModuleReplace,
			PseudoVersion:      isPseudoVersion(dep.Version),
		}
		for _, finding := range dep.Findings {
			identity := findingIdentity("", dep.ModulePath, finding)
			record.FindingIdentities = append(record.FindingIdentities, identity)
			snapshot.Findings = append(snapshot.Findings, findingSnapshot(identity, "", dep.ModulePath, finding))
		}
		record.FindingIdentities = append(record.FindingIdentities, dependencyFindings[dep.ModulePath]...)
		sort.Strings(record.FindingIdentities)
		snapshot.Dependencies = append(snapshot.Dependencies, record)
	}
	normalize(snapshot)
	return snapshot
}

func findingSnapshot(identity, pkgImportPath, modulePath string, finding report.Finding) FindingSnapshot {
	item := FindingSnapshot{
		Identity:          identity,
		ID:                finding.ID,
		Category:          string(finding.Category),
		Severity:          string(finding.Severity),
		PackageImportPath: pkgImportPath,
		ModulePath:        modulePath,
		Title:             finding.Title,
		Suppressed:        finding.Suppressed,
		Evidence:          evidencePoints(finding.Evidence),
	}
	if finding.Suppression != nil {
		info := suppressionInfo(*finding.Suppression)
		item.Suppression = &info
	}
	return item
}

func suppressionInfo(info report.SuppressionInfo) SuppressionInfo {
	return SuppressionInfo{
		Reason:  info.Reason,
		Owner:   info.Owner,
		Expires: info.Expires,
		Package: info.Package,
		Created: info.Created,
	}
}

func scoreBreakdown(score report.ScoreBreakdown) ScoreBreakdown {
	return ScoreBreakdown{
		ChurnScore:                score.ChurnScore,
		CoverageGapScore:          score.CoverageGapScore,
		ComplexityScore:           score.ComplexityScore,
		OwnershipEntropyScore:     score.OwnershipEntropyScore,
		DependencyCentralityScore: score.DependencyCentralityScore,
	}
}

func evidencePoints(items []report.Evidence) []EvidencePoint {
	out := make([]EvidencePoint, 0, len(items))
	for _, item := range items {
		out = append(out, EvidencePoint{Key: item.Key, Value: item.Value, Source: item.Source})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		if out[i].Key != out[j].Key {
			return out[i].Key < out[j].Key
		}
		return out[i].Value < out[j].Value
	})
	return out
}

func dependencyFindingIndex(findings []report.Finding) map[string][]string {
	out := map[string][]string{}
	for _, finding := range findings {
		modulePath := evidenceValue(finding.Evidence, "module_path")
		if modulePath == "" {
			continue
		}
		out[modulePath] = append(out[modulePath], findingIdentity("", modulePath, finding))
	}
	return out
}

func evidenceValue(items []report.Evidence, key string) string {
	for _, item := range items {
		if item.Key == key {
			return item.Value
		}
	}
	return ""
}

func findingIdentity(pkgImportPath, modulePath string, finding report.Finding) string {
	keys := []string{
		"id=" + finding.ID,
		"package=" + pkgImportPath,
		"module=" + modulePath,
		"category=" + string(finding.Category),
	}
	for _, item := range evidencePoints(finding.Evidence) {
		switch item.Key {
		case "matched_import", "importing_file", "module_path", "source_module_root", "boundary_rule", "replacement", "dependency":
			keys = append(keys, item.Key+"="+item.Value)
		}
	}
	sort.Strings(keys)
	sum := sha256.Sum256([]byte(strings.Join(keys, "\x00")))
	return hex.EncodeToString(sum[:16])
}

func isPseudoVersion(version string) bool {
	parts := strings.Split(version, "-")
	return len(parts) >= 3 && len(parts[len(parts)-2]) == 14
}

func normalize(snapshot *Snapshot) {
	sort.Strings(snapshot.Config.BuildTags)
	sort.Strings(snapshot.Config.Patterns)
	sort.SliceStable(snapshot.Config.RulePacks, func(i, j int) bool {
		return snapshot.Config.RulePacks[i].Path < snapshot.Config.RulePacks[j].Path
	})
	sort.SliceStable(snapshot.Config.Modules, func(i, j int) bool {
		if snapshot.Config.Modules[i].ModuleRoot != snapshot.Config.Modules[j].ModuleRoot {
			return snapshot.Config.Modules[i].ModuleRoot < snapshot.Config.Modules[j].ModuleRoot
		}
		return snapshot.Config.Modules[i].ModulePath < snapshot.Config.Modules[j].ModulePath
	})
	sort.SliceStable(snapshot.Packages, func(i, j int) bool {
		if snapshot.Packages[i].ModulePath != snapshot.Packages[j].ModulePath {
			return snapshot.Packages[i].ModulePath < snapshot.Packages[j].ModulePath
		}
		return snapshot.Packages[i].ImportPath < snapshot.Packages[j].ImportPath
	})
	sort.SliceStable(snapshot.Findings, func(i, j int) bool {
		if snapshot.Findings[i].PackageImportPath != snapshot.Findings[j].PackageImportPath {
			return snapshot.Findings[i].PackageImportPath < snapshot.Findings[j].PackageImportPath
		}
		if snapshot.Findings[i].ID != snapshot.Findings[j].ID {
			return snapshot.Findings[i].ID < snapshot.Findings[j].ID
		}
		return snapshot.Findings[i].Identity < snapshot.Findings[j].Identity
	})
	sort.SliceStable(snapshot.Suppressions, func(i, j int) bool {
		return snapshot.Suppressions[i].FindingIdentity < snapshot.Suppressions[j].FindingIdentity
	})
	sort.SliceStable(snapshot.Dependencies, func(i, j int) bool {
		if snapshot.Dependencies[i].SourceModuleRoot != snapshot.Dependencies[j].SourceModuleRoot {
			return snapshot.Dependencies[i].SourceModuleRoot < snapshot.Dependencies[j].SourceModuleRoot
		}
		return snapshot.Dependencies[i].ModulePath < snapshot.Dependencies[j].ModulePath
	})
	for i := range snapshot.Packages {
		sort.Strings(snapshot.Packages[i].IncidentIDs)
	}
	for i := range snapshot.Incidents {
		sort.Strings(snapshot.Incidents[i].AffectedPackages)
	}
	sort.SliceStable(snapshot.Incidents, func(i, j int) bool {
		if !snapshot.Incidents[i].StartedAt.Equal(snapshot.Incidents[j].StartedAt) {
			return snapshot.Incidents[i].StartedAt.Before(snapshot.Incidents[j].StartedAt)
		}
		return snapshot.Incidents[i].ID < snapshot.Incidents[j].ID
	})
	sort.SliceStable(snapshot.Warnings, func(i, j int) bool {
		if snapshot.Warnings[i].Source != snapshot.Warnings[j].Source {
			return snapshot.Warnings[i].Source < snapshot.Warnings[j].Source
		}
		return snapshot.Warnings[i].Message < snapshot.Warnings[j].Message
	})
}
