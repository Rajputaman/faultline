package sarif

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/faultline-go/faultline/internal/report"
)

const Version = "2.1.0"

type Document struct {
	Schema  string `json:"$schema,omitempty"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

type Run struct {
	Tool       Tool              `json:"tool"`
	Results    []Result          `json:"results,omitempty"`
	Properties map[string]string `json:"properties,omitempty"`
}

type Tool struct {
	Driver Driver `json:"driver"`
}

type Driver struct {
	Name           string          `json:"name"`
	Version        string          `json:"version,omitempty"`
	InformationURI string          `json:"informationUri,omitempty"`
	Rules          []ReportingRule `json:"rules"`
}

type ReportingRule struct {
	ID                   string                 `json:"id"`
	Name                 string                 `json:"name,omitempty"`
	ShortDescription     Message                `json:"shortDescription"`
	FullDescription      Message                `json:"fullDescription"`
	Help                 Message                `json:"help"`
	DefaultConfiguration ReportingConfiguration `json:"defaultConfiguration"`
}

type ReportingConfiguration struct {
	Level string `json:"level"`
}

type Result struct {
	RuleID     string     `json:"ruleId"`
	Level      string     `json:"level"`
	Message    Message    `json:"message"`
	Locations  []Location `json:"locations,omitempty"`
	Properties Properties `json:"properties,omitempty"`
}

type Message struct {
	Text     string `json:"text,omitempty"`
	Markdown string `json:"markdown,omitempty"`
}

type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           *Region          `json:"region,omitempty"`
}

type ArtifactLocation struct {
	URI string `json:"uri"`
}

type Region struct {
	StartLine int `json:"startLine,omitempty"`
}

type Properties struct {
	PackageImportPath string   `json:"packageImportPath,omitempty"`
	PackageDirectory  string   `json:"packageDirectory,omitempty"`
	ModulePath        string   `json:"modulePath,omitempty"`
	FileOwners        []string `json:"fileOwners,omitempty"`
	CodeownersFile    string   `json:"codeownersFile,omitempty"`
	CodeownersLine    string   `json:"codeownersLine,omitempty"`
	CodeownersPattern string   `json:"codeownersPattern,omitempty"`
	Evidence          []string `json:"evidence,omitempty"`
}

type ruleMetadata struct {
	id       string
	name     string
	short    string
	full     string
	help     string
	severity report.Severity
}

var rules = []ruleMetadata{
	{id: "FL-BND-001", name: "Architecture boundary violation", short: "Architecture boundary violation", full: "A package imports another package denied by configured architecture policy.", help: "Change the dependency direction, move the dependency behind an allowed interface, or update the boundary policy if the dependency is intentional.", severity: report.SeverityHigh},
	{id: "FL-CHURN-001", name: "High churn", short: "High churn in the last 30 days", full: "A package has high added and deleted line churn in recent git history.", help: "Review recent changes, stabilize interfaces, and add tests around active code paths.", severity: report.SeverityHigh},
	{id: "FL-COV-001", name: "Low coverage", short: "Package coverage is below threshold", full: "Coverage is known for this package and is below the configured minimum.", help: "Add tests for changed and high-risk code before relying on this package as stable.", severity: report.SeverityMedium},
	{id: "FL-COV-002", name: "Missing coverage", short: "Coverage data is missing", full: "Coverage was not supplied or did not contain this package.", help: "Run go test with -coverprofile for all scanned packages and pass --coverage.", severity: report.SeverityLow},
	{id: "FL-TST-001", name: "No test files", short: "No test files", full: "Package has no _test.go files. No automated test coverage exists.", help: "Add at least one _test.go file with Test* functions covering the package's exported surface. Prioritize packages with high risk scores or dependency centrality.", severity: report.SeverityMedium},
	{id: "FL-TST-002", name: "Low test-to-code ratio", short: "Low test-to-code ratio", full: "Package test code is thin relative to production code (TestLOC/LOC below threshold).", help: "Increase test coverage. The test-to-code ratio threshold is configurable via test_ratio_threshold in faultline.yaml.", severity: report.SeverityLow},
	{id: "FL-OWN-001", name: "No owner found", short: "No owner found", full: "No module owner, CODEOWNERS owner, or dominant git author owner resolved for this package.", help: "Add an owners.modules entry, CODEOWNERS rule, or ownership alias for the package.", severity: report.SeverityLow},
	{id: "FL-OWN-002", name: "High author count", short: "High author count in the last 90 days", full: "Several distinct authors changed this package in the last 90 days.", help: "Confirm ownership, review handoff paths, and make package stewardship explicit.", severity: report.SeverityMedium},
	{id: "FL-OWN-003", name: "Ownership source mismatch", short: "CODEOWNERS differs from dominant git author", full: "The CODEOWNERS owner differs from the dominant recent git author or configured ownership alias.", help: "Confirm current stewardship and update CODEOWNERS or ownership aliases if responsibility moved.", severity: report.SeverityMedium},
	{id: "FL-OWN-004", name: "Missing module owner", short: "Module owner missing in multi-module repository", full: "A package belongs to a module without an explicit owners.modules entry in a multi-module repository.", help: "Add an owners.modules entry for the module so package ownership remains stable across monorepo refactors.", severity: report.SeverityLow},
	{id: "FL-DEP-001", name: "High reverse imports", short: "High reverse import count", full: "Many loaded packages import this package, increasing change blast radius.", help: "Keep APIs stable, add focused tests, and consider splitting responsibilities if the package keeps growing.", severity: report.SeverityMedium},
	{id: "FL-DEP-002", name: "Local replace directive", short: "Local replace directive present", full: "go.mod contains a replace directive pointing to a local filesystem path.", help: "Avoid committing local replace directives for release or CI builds; use a versioned module dependency or document the temporary waiver.", severity: report.SeverityHigh},
	{id: "FL-DEP-003", name: "Module path replacement", short: "Module replaced to different module path", full: "go.mod replaces one module path with a different module path.", help: "Verify module identity substitution is intentional and reviewed.", severity: report.SeverityHigh},
	{id: "FL-DEP-004", name: "Unused dependency", short: "Declared dependency appears unused", full: "A direct required module was not matched to imports in loaded packages.", help: "Run go mod tidy locally after reviewing build tags and generated code.", severity: report.SeverityLow},
	{id: "FL-DEP-005", name: "Broad dependency blast radius", short: "Dependency has broad blast radius", full: "A dependency is imported by many loaded packages, increasing upgrade coordination risk.", help: "Review update and rollback plans for broadly used dependencies.", severity: report.SeverityMedium},
	{id: "FL-DEP-006", name: "Pseudo-version dependency", short: "Dependency uses pseudo-version", full: "A dependency uses Go pseudo-version metadata instead of a tagged module version.", help: "Prefer tagged module versions when practical.", severity: report.SeverityLow},
	{id: "FL-DEP-007", name: "Cross-module local replace", short: "Cross-module local replace inside repository", full: "A module uses a local replace directive pointing to another module in the same repository.", help: "Prefer go.work workspace usage for local multi-module development, or document why the committed replace is required.", severity: report.SeverityMedium},
	{id: "FL-GEN-001", name: "Generated-code-heavy package", short: "Generated-code-heavy package", full: "Generated files dominate this package, so structural metrics may be less actionable.", help: "Interpret package metrics cautiously and prefer generator-level ownership and testing checks.", severity: report.SeverityLow},
	{id: "FL-INC-001", name: "Package involved in recent incident", short: "Package involved in recent incident", full: "This package was listed as affected in one or more operational incidents within the lookback window.", help: "Review incident history for this package. High risk score combined with recent incident involvement is the highest priority governance signal.", severity: report.SeverityHigh},
}

// Convert returns deterministic SARIF 2.1.0 JSON. Suppressed findings are
// omitted because GitHub code scanning treats uploaded results as active alerts.
func Convert(rep *report.Report) ([]byte, error) {
	return ConvertWithOptions(rep, Options{})
}

type Options struct {
	Properties map[string]string
}

func ConvertWithOptions(rep *report.Report, opts Options) ([]byte, error) {
	doc := BuildWithOptions(rep, opts)
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal SARIF: %w", err)
	}
	return append(data, '\n'), nil
}

func Build(rep *report.Report) Document {
	return BuildWithOptions(rep, Options{})
}

func BuildWithOptions(rep *report.Report, opts Options) Document {
	properties := stableProperties(opts.Properties)
	if rep.Meta.ConfigHash != "" {
		if properties == nil {
			properties = map[string]string{}
		}
		properties["faultline.config_hash"] = rep.Meta.ConfigHash
	}
	if len(rep.Warnings) > 0 {
		if properties == nil {
			properties = map[string]string{}
		}
		warnings := make([]string, 0, len(rep.Warnings))
		for _, warning := range rep.Warnings {
			warnings = append(warnings, warning.Source+": "+warning.Message)
		}
		sort.Strings(warnings)
		properties["faultline.warning_count"] = fmt.Sprintf("%d", len(rep.Warnings))
		properties["faultline.warnings"] = strings.Join(warnings, "\n")
	}
	if len(rep.Meta.RulePacks) > 0 {
		if properties == nil {
			properties = map[string]string{}
		}
		packs := make([]string, 0, len(rep.Meta.RulePacks))
		for _, pack := range rep.Meta.RulePacks {
			packs = append(packs, pack.Path+"="+pack.ContentHash)
		}
		sort.Strings(packs)
		properties["faultline.rule_packs"] = strings.Join(packs, "\n")
	}
	return Document{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: Version,
		Runs: []Run{
			{
				Tool: Tool{
					Driver: Driver{
						Name:           "Faultline",
						Version:        rep.Meta.Version,
						InformationURI: "https://github.com/faultline-go/faultline",
						Rules:          reportingRules(),
					},
				},
				Results:    results(rep),
				Properties: properties,
			},
		},
	}
}

func WriteFile(path string, rep *report.Report) error {
	return WriteFileWithOptions(path, rep, Options{})
}

func WriteFileWithOptions(path string, rep *report.Report, opts Options) error {
	data, err := ConvertWithOptions(rep, opts)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write SARIF report %s: %w", path, err)
	}
	return nil
}

func stableProperties(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		if strings.TrimSpace(k) == "" || v == "" {
			continue
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func reportingRules() []ReportingRule {
	ordered := append([]ruleMetadata{}, rules...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].id < ordered[j].id
	})
	out := make([]ReportingRule, 0, len(ordered))
	for _, rule := range ordered {
		out = append(out, ReportingRule{
			ID:               rule.id,
			Name:             rule.name,
			ShortDescription: Message{Text: rule.short},
			FullDescription:  Message{Text: rule.full},
			Help:             Message{Text: rule.help, Markdown: rule.help},
			DefaultConfiguration: ReportingConfiguration{
				Level: Level(rule.severity),
			},
		})
	}
	return out
}

func results(rep *report.Report) []Result {
	var out []Result
	for _, pkg := range rep.Packages {
		for _, finding := range pkg.Findings {
			if finding.Suppressed {
				continue
			}
			result := Result{
				RuleID:  finding.ID,
				Level:   Level(finding.Severity),
				Message: Message{Text: resultMessage(pkg, finding)},
				Properties: Properties{
					PackageImportPath: pkg.ImportPath,
					PackageDirectory:  pkg.Dir,
					Evidence:          evidenceSummary(finding.Evidence),
				},
			}
			addOwnerProperties(&result.Properties, finding.Evidence)
			if loc, ok := location(rep.Meta.RepoPath, pkg, finding); ok {
				result.Locations = []Location{loc}
			}
			out = append(out, result)
		}
	}
	for _, finding := range rep.DependencyFindings {
		if finding.Suppressed {
			continue
		}
		modulePath := evidenceValue(finding.Evidence, "module_path")
		result := Result{
			RuleID:  finding.ID,
			Level:   Level(finding.Severity),
			Message: Message{Text: dependencyResultMessage(modulePath, finding)},
			Properties: Properties{
				ModulePath: modulePath,
				Evidence:   evidenceSummary(finding.Evidence),
			},
		}
		if loc, ok := dependencyLocation(finding); ok {
			result.Locations = []Location{loc}
		}
		out = append(out, result)
	}
	sort.SliceStable(out, func(i, j int) bool {
		left := resultSortKey(out[i])
		right := resultSortKey(out[j])
		if left != right {
			return left < right
		}
		if out[i].RuleID != out[j].RuleID {
			return out[i].RuleID < out[j].RuleID
		}
		return out[i].Message.Text < out[j].Message.Text
	})
	return out
}

func resultSortKey(result Result) string {
	if result.Properties.PackageImportPath != "" {
		return result.Properties.PackageImportPath
	}
	return result.Properties.ModulePath
}

func addOwnerProperties(props *Properties, evidence []report.Evidence) {
	if owners := evidenceValue(evidence, "file_owner"); owners != "" && owners != "unknown" {
		props.FileOwners = splitCSV(owners)
	}
	props.CodeownersFile = evidenceValue(evidence, "file_codeowners_file")
	props.CodeownersLine = evidenceValue(evidence, "file_codeowners_line")
	props.CodeownersPattern = evidenceValue(evidence, "file_codeowners_pattern")
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	sort.Strings(out)
	return out
}

// Level maps Faultline severities to SARIF result levels.
func Level(severity report.Severity) string {
	switch severity {
	case report.SeverityCritical, report.SeverityHigh:
		return "error"
	case report.SeverityMedium:
		return "warning"
	case report.SeverityLow, report.SeverityInfo:
		return "note"
	default:
		return "note"
	}
}

func resultMessage(pkg report.PackageRisk, finding report.Finding) string {
	evidence := evidenceSummary(finding.Evidence)
	text := fmt.Sprintf("%s: %s Package: %s.", finding.Title, finding.Description, pkg.ImportPath)
	if len(evidence) > 0 {
		text += " Evidence: " + strings.Join(evidence, "; ") + "."
	}
	return text
}

func dependencyResultMessage(modulePath string, finding report.Finding) string {
	text := fmt.Sprintf("%s: %s Module: %s.", finding.Title, finding.Description, modulePath)
	if evidence := evidenceSummary(finding.Evidence); len(evidence) > 0 {
		text += " Evidence: " + strings.Join(evidence, "; ") + "."
	}
	return text
}

func evidenceSummary(items []report.Evidence) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, fmt.Sprintf("%s=%s (%s)", item.Key, item.Value, item.Source))
	}
	sort.Strings(out)
	return out
}

func location(repoRoot string, pkg report.PackageRisk, finding report.Finding) (Location, bool) {
	pkgDir := filepath.Join(repoRoot, filepath.FromSlash(pkg.Dir))
	if finding.ID == "FL-BND-001" {
		if rel := evidenceValue(finding.Evidence, "importing_file"); rel != "" {
			line := 0
			if value := evidenceValue(finding.Evidence, "importing_line"); value != "" {
				if parsed, err := strconv.Atoi(value); err == nil {
					line = parsed
				}
			}
			return makeLocation(rel, line), true
		}
		if deniedImport := evidenceValue(finding.Evidence, "matched_import"); deniedImport != "" {
			if rel, line, ok := findImportLocation(repoRoot, pkgDir, deniedImport); ok {
				return makeLocation(rel, line), true
			}
		}
	}
	if rel, ok := firstPackageFile(repoRoot, pkgDir); ok {
		return makeLocation(rel, 1), true
	}
	if pkg.Dir != "" && pkg.Dir != "." {
		return makeLocation(filepath.ToSlash(pkg.Dir), 0), true
	}
	return Location{}, false
}

func dependencyLocation(finding report.Finding) (Location, bool) {
	line := 0
	if value := evidenceValue(finding.Evidence, "go_mod_line"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			line = parsed
		}
	}
	return makeLocation("go.mod", line), true
}

func makeLocation(rel string, line int) Location {
	loc := Location{
		PhysicalLocation: PhysicalLocation{
			ArtifactLocation: ArtifactLocation{URI: filepath.ToSlash(rel)},
		},
	}
	if line > 0 {
		loc.PhysicalLocation.Region = &Region{StartLine: line}
	}
	return loc
}

func evidenceValue(items []report.Evidence, key string) string {
	for _, item := range items {
		if item.Key == key {
			return item.Value
		}
	}
	return ""
}

func findImportLocation(repoRoot, pkgDir, deniedImport string) (string, int, bool) {
	files, err := goFiles(pkgDir)
	if err != nil {
		return "", 0, false
	}
	needle := []byte(strconvQuote(deniedImport))
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(bytes.NewReader(data))
		line := 1
		for scanner.Scan() {
			if bytes.Contains(scanner.Bytes(), needle) {
				rel, err := filepath.Rel(repoRoot, file)
				if err != nil {
					return filepath.ToSlash(file), line, true
				}
				return filepath.ToSlash(rel), line, true
			}
			line++
		}
	}
	return "", 0, false
}

func firstPackageFile(repoRoot, pkgDir string) (string, bool) {
	files, err := goFiles(pkgDir)
	if err != nil {
		return "", false
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		if isGeneratedFile(filepath.Base(file), data) {
			continue
		}
		rel, err := filepath.Rel(repoRoot, file)
		if err != nil {
			return filepath.ToSlash(file), true
		}
		return filepath.ToSlash(rel), true
	}
	if len(files) > 0 {
		rel, err := filepath.Rel(repoRoot, files[0])
		if err != nil {
			return filepath.ToSlash(files[0]), true
		}
		return filepath.ToSlash(rel), true
	}
	return "", false
}

func goFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		files = append(files, filepath.Join(dir, entry.Name()))
	}
	sort.Strings(files)
	return files, nil
}

func isGeneratedFile(name string, data []byte) bool {
	base := filepath.Base(name)
	if strings.HasSuffix(base, ".pb.go") ||
		strings.HasSuffix(base, "_generated.go") ||
		strings.HasPrefix(base, "mock_") ||
		(strings.HasPrefix(base, "zz_generated") && strings.HasSuffix(base, ".go")) {
		return true
	}
	head := data
	if len(head) > 4096 {
		head = head[:4096]
	}
	if idx := bytes.Index(head, []byte("package ")); idx >= 0 {
		head = head[:idx]
	}
	head = bytes.ToLower(head)
	return bytes.Contains(head, []byte("code generated")) ||
		bytes.Contains(head, []byte("do not edit"))
}

func strconvQuote(s string) string {
	data, _ := json.Marshal(s)
	return string(data)
}
