// Package policy loads and validates faultline configuration files.
package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const SupportedConfigVersion = 1

// Config is the top-level structure for faultline.yaml.
type Config struct {
	Version           int               `yaml:"version" json:"version"`
	RulePacks         []RulePackRef     `yaml:"rule_packs" json:"rule_packs,omitempty"`
	Ownership         OwnershipConfig   `yaml:"ownership" json:"ownership"`
	Owners            OwnersConfig      `yaml:"owners" json:"owners,omitempty"`
	Coverage          CoverageConfig    `yaml:"coverage" json:"coverage"`
	Scoring           ScoringConfig     `yaml:"scoring" json:"scoring"`
	Boundaries        []BoundaryRule    `yaml:"boundaries" json:"boundaries,omitempty"`
	SuppressionPolicy SuppressionPolicy `yaml:"suppression_policy" json:"suppression_policy,omitempty"`
	Suppressions      []Suppression     `yaml:"suppressions" json:"suppressions,omitempty"`
}

type RulePackRef struct {
	Path string `yaml:"path" json:"path"`
}

// OwnershipConfig controls ownership-related thresholds.
type OwnershipConfig struct {
	RequireCodeowners bool `yaml:"require_codeowners" json:"require_codeowners"`
	MaxAuthorCount90d int  `yaml:"max_author_count_90d" json:"max_author_count_90d"`
}

// OwnersConfig maps enterprise ownership identities to modules and aliases.
type OwnersConfig struct {
	Aliases map[string][]string          `yaml:"aliases" json:"aliases,omitempty"`
	Modules map[string]ModuleOwnerConfig `yaml:"modules" json:"modules,omitempty"`
}

// ModuleOwnerConfig declares an explicit owner for a module path.
type ModuleOwnerConfig struct {
	Owner string `yaml:"owner" json:"owner"`
}

// CoverageConfig controls coverage thresholds.
type CoverageConfig struct {
	MinPackageCoverage float64 `yaml:"min_package_coverage" json:"min_package_coverage"`
}

// ScoringConfig controls calibration constants for normalized component
// scores. Defaults preserve the initial Faultline risk model.
type ScoringConfig struct {
	ChurnMaxLines30d                          int `yaml:"churn_max_lines_30d" json:"churn_max_lines_30d"`
	ComplexityMaxLOC                          int `yaml:"complexity_max_loc" json:"complexity_max_loc"`
	ComplexityMaxImports                      int `yaml:"complexity_max_imports" json:"complexity_max_imports"`
	ComplexityMaxFiles                        int `yaml:"complexity_max_files" json:"complexity_max_files"`
	DependencyCentralityMaxReverseImportCount int `yaml:"dependency_centrality_max_reverse_imports" json:"dependency_centrality_max_reverse_imports"`
}

// BoundaryRule defines an import boundary that must not be crossed.
type BoundaryRule struct {
	Name   string   `yaml:"name" json:"name"`
	From   string   `yaml:"from" json:"from"`
	Deny   []string `yaml:"deny" json:"deny"`
	Except []string `yaml:"except" json:"except,omitempty"`
}

type SuppressionPolicy struct {
	RequireOwner   bool `yaml:"require_owner" json:"require_owner"`
	RequireReason  bool `yaml:"require_reason" json:"require_reason"`
	RequireExpires bool `yaml:"require_expiry" json:"require_expiry"`
	MaxDays        int  `yaml:"max_days" json:"max_days,omitempty"`
}

// Suppression silences a specific finding for a package.
type Suppression struct {
	ID       string `yaml:"id" json:"id"`
	Package  string `yaml:"package" json:"package"`
	Category string `yaml:"category" json:"category,omitempty"`
	Reason   string `yaml:"reason" json:"reason"`
	Expires  string `yaml:"expires" json:"expires"`
	Owner    string `yaml:"owner" json:"owner"`
	Created  string `yaml:"created" json:"created,omitempty"`
}

type ValidationLevel string

const (
	ValidationWarning ValidationLevel = "warning"
	ValidationError   ValidationLevel = "error"
)

type ValidationIssue struct {
	Level   ValidationLevel `json:"level"`
	Path    string          `json:"path"`
	Message string          `json:"message"`
	Line    int             `json:"line,omitempty"`
	Column  int             `json:"column,omitempty"`
}

type ValidationReport struct {
	Path               string            `json:"path,omitempty"`
	ConfigHash         string            `json:"config_hash"`
	ResolvedConfigHash string            `json:"resolved_config_hash,omitempty"`
	RulePacks          []RulePackAudit   `json:"rule_packs,omitempty"`
	Issues             []ValidationIssue `json:"issues,omitempty"`
	WarningCount       int               `json:"warning_count"`
	ErrorCount         int               `json:"error_count"`
}

func (r ValidationReport) HasWarnings() bool { return r.WarningCount > 0 }
func (r ValidationReport) HasErrors() bool   { return r.ErrorCount > 0 }

type RulePackAudit struct {
	Path        string `json:"path" yaml:"path"`
	ContentHash string `json:"content_hash,omitempty" yaml:"content_hash,omitempty"`
	Imported    bool   `json:"imported" yaml:"imported"`
}

type ResolveOptions struct {
	RepoRoot               string
	AllowConfigOutsideRepo bool
	Now                    time.Time
}

// ExpiresTime parses the Expires field. Returns zero time if blank or unparseable.
func (s Suppression) ExpiresTime() time.Time {
	if s.Expires == "" {
		return time.Time{}
	}
	t, err := time.Parse("2006-01-02", s.Expires)
	if err != nil {
		return time.Time{}
	}
	return t
}

// CreatedTime parses the Created field. Returns zero time if blank or unparseable.
func (s Suppression) CreatedTime() time.Time {
	if s.Created == "" {
		return time.Time{}
	}
	t, err := time.Parse("2006-01-02", s.Created)
	if err != nil {
		return time.Time{}
	}
	return t
}

// UnmarshalYAML accepts the current require_expiry key and the older
// require_expires spelling. The current key wins when both are present.
func (p *SuppressionPolicy) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.MappingNode {
		return value.Decode((*suppressionPolicyYAML)(p))
	}
	for i := 0; i+1 < len(value.Content); i += 2 {
		key := value.Content[i].Value
		node := value.Content[i+1]
		switch key {
		case "require_owner":
			if err := node.Decode(&p.RequireOwner); err != nil {
				return err
			}
		case "require_reason":
			if err := node.Decode(&p.RequireReason); err != nil {
				return err
			}
		case "require_expiry", "require_expires":
			if err := node.Decode(&p.RequireExpires); err != nil {
				return err
			}
		case "max_days":
			if err := node.Decode(&p.MaxDays); err != nil {
				return err
			}
		}
	}
	return nil
}

type suppressionPolicyYAML SuppressionPolicy

// DefaultConfig returns a Config with safe defaults.
func DefaultConfig() Config {
	return Config{
		Version: 1,
		Ownership: OwnershipConfig{
			RequireCodeowners: false,
			MaxAuthorCount90d: 6,
		},
		Coverage: CoverageConfig{
			MinPackageCoverage: 60,
		},
		Scoring: DefaultScoringConfig(),
		SuppressionPolicy: SuppressionPolicy{
			RequireOwner:   true,
			RequireReason:  true,
			RequireExpires: true,
		},
	}
}

func DefaultScoringConfig() ScoringConfig {
	return ScoringConfig{
		ChurnMaxLines30d:                          1000,
		ComplexityMaxLOC:                          1000,
		ComplexityMaxImports:                      20,
		ComplexityMaxFiles:                        30,
		DependencyCentralityMaxReverseImportCount: 10,
	}
}

func NormalizeScoringConfig(cfg ScoringConfig) ScoringConfig {
	defaults := DefaultScoringConfig()
	if cfg.ChurnMaxLines30d <= 0 {
		cfg.ChurnMaxLines30d = defaults.ChurnMaxLines30d
	}
	if cfg.ComplexityMaxLOC <= 0 {
		cfg.ComplexityMaxLOC = defaults.ComplexityMaxLOC
	}
	if cfg.ComplexityMaxImports <= 0 {
		cfg.ComplexityMaxImports = defaults.ComplexityMaxImports
	}
	if cfg.ComplexityMaxFiles <= 0 {
		cfg.ComplexityMaxFiles = defaults.ComplexityMaxFiles
	}
	if cfg.DependencyCentralityMaxReverseImportCount <= 0 {
		cfg.DependencyCentralityMaxReverseImportCount = defaults.DependencyCentralityMaxReverseImportCount
	}
	return cfg
}

// LoadConfig reads and parses a faultline YAML config file.
// The file content is treated as untrusted: only known fields are decoded.
func LoadConfig(path string) (*Config, error) {
	cfg, _, err := LoadConfigWithValidation(path)
	return cfg, err
}

func LoadConfigWithValidation(path string) (*Config, ValidationReport, error) {
	cwd, _ := os.Getwd()
	return ResolveConfigWithValidation(path, ResolveOptions{RepoRoot: cwd, Now: time.Now().UTC()})
}

func ResolveConfigWithValidation(path string, opts ResolveOptions) (*Config, ValidationReport, error) {
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	if opts.RepoRoot == "" {
		opts.RepoRoot, _ = os.Getwd()
	}
	base, root, rawHash, err := readConfigDocument(path, true)
	if err != nil {
		return nil, ValidationReport{Path: path}, err
	}
	issues := unknownConfigKeys(root, false)
	resolved := DefaultConfig()
	resolved.Version = base.Version

	var audits []RulePackAudit
	for i, ref := range base.RulePacks {
		audit, pack, packRoot, packIssues, err := loadRulePack(ref.Path, opts)
		audits = append(audits, audit)
		issues = append(issues, packIssues...)
		if err != nil {
			issues = append(issues, ValidationIssue{Level: ValidationError, Path: fmt.Sprintf("rule_packs[%d].path", i), Message: err.Error()})
			continue
		}
		if !audit.Imported {
			continue
		}
		mergeConfig(&resolved, pack, packRoot, fmt.Sprintf("rule_packs[%d]", i), &issues)
	}
	mergeConfig(&resolved, base, root, "config", &issues)
	resolved.RulePacks = append([]RulePackRef{}, base.RulePacks...)
	resolved.Suppressions = append([]Suppression{}, base.Suppressions...)

	finalHash := ResolvedConfigHash(resolved, audits)
	report := ValidateConfig(path, resolved, issues, finalHash, opts.Now)
	report.RulePacks = audits
	report.ResolvedConfigHash = finalHash
	if rawHash != "" && rawHash != finalHash {
		// ConfigHash represents the resolved enforcement artifact. The raw hash
		// remains available through rule-pack audit hashes.
		report.ConfigHash = finalHash
	}
	if report.HasErrors() {
		return &resolved, report, fmt.Errorf("config %s is invalid", path)
	}
	return &resolved, report, nil
}

func readConfigDocument(path string, allowSuppressions bool) (Config, yaml.Node, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, yaml.Node{}, "", fmt.Errorf("read config %s: %w", path, err)
	}

	var root yaml.Node
	if err := yaml.NewDecoder(newLimitedReader(data, 1<<20)).Decode(&root); err != nil {
		return Config{}, yaml.Node{}, hashBytes(data), fmt.Errorf("parse config %s: %w", path, err)
	}
	cfg := DefaultConfig()
	if !allowSuppressions {
		cfg.Suppressions = nil
	}
	dec := yaml.NewDecoder(newLimitedReader(data, 1<<20)) // 1 MiB limit
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, yaml.Node{}, hashBytes(data), fmt.Errorf("parse config %s: %w", path, err)
	}
	return cfg, root, hashBytes(data), nil
}

func newLimitedReader(data []byte, max int) *bytes.Reader {
	if len(data) > max {
		data = data[:max]
	}
	return bytes.NewReader(data)
}

func ValidateConfig(path string, cfg Config, unknown []ValidationIssue, configHash string, now time.Time) ValidationReport {
	report := ValidationReport{Path: path, ConfigHash: configHash}
	report.Issues = append(report.Issues, unknown...)
	if cfg.Version != SupportedConfigVersion {
		report.Issues = append(report.Issues, ValidationIssue{
			Level:   ValidationError,
			Path:    "version",
			Message: fmt.Sprintf("unsupported version %d; supported version is %d", cfg.Version, SupportedConfigVersion),
		})
	}
	if cfg.Ownership.MaxAuthorCount90d < 0 {
		report.Issues = append(report.Issues, ValidationIssue{Level: ValidationWarning, Path: "ownership.max_author_count_90d", Message: "must be zero or greater"})
	}
	if cfg.Ownership.MaxAuthorCount90d > 1000 {
		report.Issues = append(report.Issues, ValidationIssue{Level: ValidationWarning, Path: "ownership.max_author_count_90d", Message: "unusually high threshold; verify this is intentional"})
	}
	for alias, members := range cfg.Owners.Aliases {
		alias = strings.TrimSpace(alias)
		if alias == "" {
			report.Issues = append(report.Issues, ValidationIssue{Level: ValidationWarning, Path: "owners.aliases", Message: "alias owner key must not be empty"})
		}
		if len(members) == 0 {
			report.Issues = append(report.Issues, ValidationIssue{Level: ValidationWarning, Path: fmt.Sprintf("owners.aliases.%s", alias), Message: "alias must include at least one identity"})
		}
		for i, member := range members {
			if strings.TrimSpace(member) == "" {
				report.Issues = append(report.Issues, ValidationIssue{Level: ValidationWarning, Path: fmt.Sprintf("owners.aliases.%s[%d]", alias, i), Message: "alias identity must not be empty"})
			}
		}
	}
	for modulePath, owner := range cfg.Owners.Modules {
		if strings.TrimSpace(modulePath) == "" {
			report.Issues = append(report.Issues, ValidationIssue{Level: ValidationWarning, Path: "owners.modules", Message: "module owner key must not be empty"})
		}
		if strings.TrimSpace(owner.Owner) == "" {
			report.Issues = append(report.Issues, ValidationIssue{Level: ValidationWarning, Path: fmt.Sprintf("owners.modules.%s.owner", modulePath), Message: "module owner must not be empty"})
		}
	}
	if cfg.Coverage.MinPackageCoverage < 0 || cfg.Coverage.MinPackageCoverage > 100 {
		report.Issues = append(report.Issues, ValidationIssue{Level: ValidationWarning, Path: "coverage.min_package_coverage", Message: "must be between 0 and 100"})
	}
	report.Issues = append(report.Issues, validateScoringConfigIssues(cfg.Scoring)...)
	if cfg.SuppressionPolicy.MaxDays < 0 {
		report.Issues = append(report.Issues, ValidationIssue{Level: ValidationWarning, Path: "suppression_policy.max_days", Message: "must be zero or greater"})
	}
	for i, ref := range cfg.RulePacks {
		if strings.TrimSpace(ref.Path) == "" {
			report.Issues = append(report.Issues, ValidationIssue{Level: ValidationWarning, Path: fmt.Sprintf("rule_packs[%d].path", i), Message: "rule pack path is required"})
		}
	}
	for i, rule := range cfg.Boundaries {
		report.Issues = append(report.Issues, validateBoundaryRuleIssues(rule, fmt.Sprintf("boundaries[%d]", i))...)
	}
	for i, suppression := range cfg.Suppressions {
		report.Issues = append(report.Issues, validateSuppressionIssues(suppression, cfg.SuppressionPolicy, fmt.Sprintf("suppressions[%d]", i), now)...)
	}
	sort.SliceStable(report.Issues, func(i, j int) bool {
		if report.Issues[i].Level != report.Issues[j].Level {
			return report.Issues[i].Level < report.Issues[j].Level
		}
		if report.Issues[i].Path != report.Issues[j].Path {
			return report.Issues[i].Path < report.Issues[j].Path
		}
		return report.Issues[i].Message < report.Issues[j].Message
	})
	for _, issue := range report.Issues {
		if issue.Level == ValidationError {
			report.ErrorCount++
		} else {
			report.WarningCount++
		}
	}
	return report
}

func ConfigHash(cfg Config) string {
	data, _ := yaml.Marshal(cfg)
	return hashBytes(data)
}

func ResolvedConfigHash(cfg Config, packs []RulePackAudit) string {
	material := struct {
		Config    Config          `json:"config"`
		RulePacks []RulePackAudit `json:"rule_packs,omitempty"`
	}{
		Config:    cfg,
		RulePacks: packs,
	}
	data, _ := json.Marshal(material)
	return hashBytes(data)
}

func loadRulePack(path string, opts ResolveOptions) (RulePackAudit, Config, yaml.Node, []ValidationIssue, error) {
	audit := RulePackAudit{Path: filepath.ToSlash(path)}
	resolved, err := resolveRulePackPath(opts.RepoRoot, path, opts.AllowConfigOutsideRepo)
	if err != nil {
		return audit, Config{}, yaml.Node{}, nil, err
	}
	data, err := os.ReadFile(resolved)
	if os.IsNotExist(err) {
		return audit, Config{}, yaml.Node{}, []ValidationIssue{{Level: ValidationWarning, Path: "rule_packs.path", Message: fmt.Sprintf("rule pack %q does not exist", path)}}, nil
	}
	if err != nil {
		return audit, Config{}, yaml.Node{}, nil, fmt.Errorf("read rule pack %s: %w", path, err)
	}
	audit.ContentHash = hashBytes(data)
	audit.Imported = true
	var root yaml.Node
	if err := yaml.NewDecoder(newLimitedReader(data, 1<<20)).Decode(&root); err != nil {
		return audit, Config{}, yaml.Node{}, nil, fmt.Errorf("parse rule pack %s: %w", path, err)
	}
	cfg := DefaultConfig()
	cfg.Suppressions = nil
	if err := yaml.NewDecoder(newLimitedReader(data, 1<<20)).Decode(&cfg); err != nil {
		return audit, Config{}, yaml.Node{}, nil, fmt.Errorf("parse rule pack %s: %w", path, err)
	}
	issues := unknownConfigKeys(root, true)
	if len(nodeSequence(rootMappingValue(root, "suppressions"))) > 0 || rootMappingValue(root, "suppressions") != nil {
		issues = append(issues, ValidationIssue{Level: ValidationWarning, Path: "suppressions", Message: fmt.Sprintf("rule pack %q contains suppressions; suppressions must stay repo-local and were ignored", path)})
	}
	cfg.Suppressions = nil
	cfg.RulePacks = nil
	return audit, cfg, root, issues, nil
}

func resolveRulePackPath(repoRoot, rulePath string, allowOutside bool) (string, error) {
	if strings.TrimSpace(rulePath) == "" {
		return "", fmt.Errorf("rule pack path is required")
	}
	if strings.Contains(rulePath, "$") || strings.Contains(rulePath, "~") {
		return "", fmt.Errorf("rule pack path %q must be literal; environment and shell expansion are not supported", rulePath)
	}
	var candidate string
	if filepath.IsAbs(rulePath) {
		candidate = filepath.Clean(rulePath)
	} else {
		candidate = filepath.Join(repoRoot, filepath.FromSlash(rulePath))
	}
	if allowOutside {
		return candidate, nil
	}
	repoAbs, err := filepath.Abs(repoRoot)
	if err != nil {
		return "", fmt.Errorf("resolve repo root: %w", err)
	}
	candidateAbs, err := filepath.Abs(candidate)
	if err != nil {
		return "", fmt.Errorf("resolve rule pack path %q: %w", rulePath, err)
	}
	if !pathWithin(repoAbs, candidateAbs) {
		return "", fmt.Errorf("rule pack path %q escapes repo root", rulePath)
	}
	if eval, err := filepath.EvalSymlinks(candidateAbs); err == nil {
		repoEval, repoErr := filepath.EvalSymlinks(repoAbs)
		if repoErr == nil && !pathWithin(repoEval, eval) {
			return "", fmt.Errorf("rule pack path %q resolves outside repo root", rulePath)
		}
	}
	return candidateAbs, nil
}

func pathWithin(root, child string) bool {
	rel, err := filepath.Rel(root, child)
	if err != nil {
		return false
	}
	return rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "..")
}

func mergeConfig(dst *Config, src Config, root yaml.Node, context string, issues *[]ValidationIssue) {
	if nodeHasPath(root, "ownership.require_codeowners") {
		dst.Ownership.RequireCodeowners = src.Ownership.RequireCodeowners
	}
	if nodeHasPath(root, "ownership.max_author_count_90d") {
		dst.Ownership.MaxAuthorCount90d = src.Ownership.MaxAuthorCount90d
	}
	if nodeHasPath(root, "owners.aliases") {
		if dst.Owners.Aliases == nil {
			dst.Owners.Aliases = map[string][]string{}
		}
		for owner, identities := range src.Owners.Aliases {
			dst.Owners.Aliases[owner] = append([]string{}, identities...)
		}
	}
	if nodeHasPath(root, "owners.modules") {
		if dst.Owners.Modules == nil {
			dst.Owners.Modules = map[string]ModuleOwnerConfig{}
		}
		for modulePath, owner := range src.Owners.Modules {
			dst.Owners.Modules[modulePath] = owner
		}
	}
	if nodeHasPath(root, "coverage.min_package_coverage") {
		dst.Coverage.MinPackageCoverage = src.Coverage.MinPackageCoverage
	}
	if nodeHasPath(root, "scoring.churn_max_lines_30d") {
		dst.Scoring.ChurnMaxLines30d = src.Scoring.ChurnMaxLines30d
	}
	if nodeHasPath(root, "scoring.complexity_max_loc") {
		dst.Scoring.ComplexityMaxLOC = src.Scoring.ComplexityMaxLOC
	}
	if nodeHasPath(root, "scoring.complexity_max_imports") {
		dst.Scoring.ComplexityMaxImports = src.Scoring.ComplexityMaxImports
	}
	if nodeHasPath(root, "scoring.complexity_max_files") {
		dst.Scoring.ComplexityMaxFiles = src.Scoring.ComplexityMaxFiles
	}
	if nodeHasPath(root, "scoring.dependency_centrality_max_reverse_imports") {
		dst.Scoring.DependencyCentralityMaxReverseImportCount = src.Scoring.DependencyCentralityMaxReverseImportCount
	}
	if nodeHasPath(root, "suppression_policy.require_owner") {
		dst.SuppressionPolicy.RequireOwner = src.SuppressionPolicy.RequireOwner
	}
	if nodeHasPath(root, "suppression_policy.require_reason") {
		dst.SuppressionPolicy.RequireReason = src.SuppressionPolicy.RequireReason
	}
	if nodeHasPath(root, "suppression_policy.require_expiry") || nodeHasPath(root, "suppression_policy.require_expires") {
		dst.SuppressionPolicy.RequireExpires = src.SuppressionPolicy.RequireExpires
	}
	if nodeHasPath(root, "suppression_policy.max_days") {
		dst.SuppressionPolicy.MaxDays = src.SuppressionPolicy.MaxDays
	}
	for _, rule := range src.Boundaries {
		addBoundary(dst, rule, context, issues)
	}
}

func addBoundary(dst *Config, rule BoundaryRule, context string, issues *[]ValidationIssue) {
	for i, existing := range dst.Boundaries {
		if existing.Name == "" || rule.Name == "" || existing.Name != rule.Name {
			continue
		}
		if reflect.DeepEqual(existing, rule) {
			return
		}
		*issues = append(*issues, ValidationIssue{
			Level:   ValidationWarning,
			Path:    context + ".boundaries." + rule.Name,
			Message: fmt.Sprintf("duplicate boundary name %q overrides earlier non-identical rule", rule.Name),
		})
		dst.Boundaries[i] = rule
		return
	}
	dst.Boundaries = append(dst.Boundaries, rule)
}

func nodeHasPath(root yaml.Node, dotted string) bool {
	parts := strings.Split(dotted, ".")
	node := rootMappingNode(root)
	for _, part := range parts {
		if node == nil || node.Kind != yaml.MappingNode {
			return false
		}
		node = mappingValue(node, part)
		if node == nil {
			return false
		}
	}
	return true
}

func rootMappingNode(root yaml.Node) *yaml.Node {
	node := &root
	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		node = node.Content[0]
	}
	if node.Kind != yaml.MappingNode {
		return nil
	}
	return node
}

func rootMappingValue(root yaml.Node, key string) *yaml.Node {
	return mappingValue(rootMappingNode(root), key)
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func nodeSequence(node *yaml.Node) []*yaml.Node {
	if node == nil || node.Kind != yaml.SequenceNode {
		return nil
	}
	return node.Content
}

func unknownConfigKeys(root yaml.Node, rulePack bool) []ValidationIssue {
	doc := root
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		doc = *doc.Content[0]
	}
	if doc.Kind == 0 {
		return nil
	}
	if doc.Kind != yaml.MappingNode {
		return []ValidationIssue{{Level: ValidationError, Path: "$", Message: "config root must be a mapping", Line: doc.Line, Column: doc.Column}}
	}
	allowedTopLevel := map[string]bool{
		"version":            true,
		"rule_packs":         !rulePack,
		"ownership":          true,
		"owners":             true,
		"coverage":           true,
		"scoring":            true,
		"boundaries":         true,
		"suppression_policy": true,
		"suppressions":       true,
	}
	var issues []ValidationIssue
	for i := 0; i+1 < len(doc.Content); i += 2 {
		key := doc.Content[i]
		value := doc.Content[i+1]
		if !allowedTopLevel[key.Value] {
			issues = append(issues, unknownKeyIssue(key.Value, key.Line, key.Column))
			continue
		}
		switch key.Value {
		case "rule_packs":
			issues = append(issues, unknownSequenceMappingKeys(value, "rule_packs", map[string]bool{
				"path": true,
			})...)
		case "ownership":
			issues = append(issues, unknownMappingKeys(value, "ownership", map[string]bool{
				"require_codeowners":   true,
				"max_author_count_90d": true,
			})...)
		case "owners":
			issues = append(issues, unknownOwnersKeys(value)...)
		case "coverage":
			issues = append(issues, unknownMappingKeys(value, "coverage", map[string]bool{
				"min_package_coverage": true,
			})...)
		case "scoring":
			issues = append(issues, unknownMappingKeys(value, "scoring", map[string]bool{
				"churn_max_lines_30d":                       true,
				"complexity_max_loc":                        true,
				"complexity_max_imports":                    true,
				"complexity_max_files":                      true,
				"dependency_centrality_max_reverse_imports": true,
			})...)
		case "boundaries":
			issues = append(issues, unknownSequenceMappingKeys(value, "boundaries", map[string]bool{
				"name":   true,
				"from":   true,
				"deny":   true,
				"except": true,
			})...)
		case "suppression_policy":
			issues = append(issues, unknownMappingKeys(value, "suppression_policy", map[string]bool{
				"require_owner":   true,
				"require_reason":  true,
				"require_expiry":  true,
				"require_expires": true,
				"max_days":        true,
			})...)
		case "suppressions":
			issues = append(issues, unknownSequenceMappingKeys(value, "suppressions", map[string]bool{
				"id":       true,
				"package":  true,
				"category": true,
				"reason":   true,
				"expires":  true,
				"owner":    true,
				"created":  true,
			})...)
		}
	}
	return issues
}

func unknownMappingKeys(node *yaml.Node, path string, allowed map[string]bool) []ValidationIssue {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	var issues []ValidationIssue
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i]
		if allowed[key.Value] {
			continue
		}
		issues = append(issues, unknownKeyIssue(path+"."+key.Value, key.Line, key.Column))
	}
	return issues
}

func unknownSequenceMappingKeys(node *yaml.Node, path string, allowed map[string]bool) []ValidationIssue {
	if node == nil || node.Kind != yaml.SequenceNode {
		return nil
	}
	var issues []ValidationIssue
	for i, item := range node.Content {
		itemPath := fmt.Sprintf("%s[%d]", path, i)
		issues = append(issues, unknownMappingKeys(item, itemPath, allowed)...)
	}
	return issues
}

func unknownOwnersKeys(node *yaml.Node) []ValidationIssue {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	var issues []ValidationIssue
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i]
		value := node.Content[i+1]
		switch key.Value {
		case "aliases":
			if value.Kind != yaml.MappingNode {
				continue
			}
			for j := 0; j+1 < len(value.Content); j += 2 {
				if value.Content[j+1].Kind != yaml.SequenceNode {
					issues = append(issues, ValidationIssue{Level: ValidationWarning, Path: "owners.aliases." + value.Content[j].Value, Message: "alias value should be an array of identities", Line: value.Content[j].Line, Column: value.Content[j].Column})
				}
			}
		case "modules":
			if value.Kind != yaml.MappingNode {
				continue
			}
			for j := 0; j+1 < len(value.Content); j += 2 {
				moduleKey := value.Content[j]
				moduleValue := value.Content[j+1]
				issues = append(issues, unknownMappingKeys(moduleValue, "owners.modules."+moduleKey.Value, map[string]bool{
					"owner": true,
				})...)
			}
		default:
			issues = append(issues, unknownKeyIssue("owners."+key.Value, key.Line, key.Column))
		}
	}
	return issues
}

func unknownKeyIssue(path string, line, column int) ValidationIssue {
	return ValidationIssue{
		Level:   ValidationWarning,
		Path:    path,
		Message: "unknown key will be ignored",
		Line:    line,
		Column:  column,
	}
}

func validateBoundaryRuleIssues(rule BoundaryRule, context string) []ValidationIssue {
	var issues []ValidationIssue
	if strings.TrimSpace(rule.Name) == "" {
		issues = append(issues, ValidationIssue{Level: ValidationWarning, Path: context + ".name", Message: "boundary rule missing name"})
	}
	if strings.TrimSpace(rule.From) == "" {
		issues = append(issues, ValidationIssue{Level: ValidationWarning, Path: context + ".from", Message: "boundary rule missing from pattern"})
	} else if err := validateGlobish(rule.From); err != nil {
		issues = append(issues, ValidationIssue{Level: ValidationWarning, Path: context + ".from", Message: fmt.Sprintf("invalid pattern %q: %v", rule.From, err)})
	}
	if len(rule.Deny) == 0 {
		issues = append(issues, ValidationIssue{Level: ValidationWarning, Path: context + ".deny", Message: "boundary rule missing deny patterns"})
	}
	for j, pattern := range rule.Deny {
		path := fmt.Sprintf("%s.deny[%d]", context, j)
		if strings.TrimSpace(pattern) == "" {
			issues = append(issues, ValidationIssue{Level: ValidationWarning, Path: path, Message: "empty deny pattern"})
			continue
		}
		if err := validateGlobish(pattern); err != nil {
			issues = append(issues, ValidationIssue{Level: ValidationWarning, Path: path, Message: fmt.Sprintf("invalid pattern %q: %v", pattern, err)})
		}
	}
	for j, pattern := range rule.Except {
		path := fmt.Sprintf("%s.except[%d]", context, j)
		if strings.TrimSpace(pattern) == "" {
			issues = append(issues, ValidationIssue{Level: ValidationWarning, Path: path, Message: "empty except pattern"})
			continue
		}
		if err := validateGlobish(pattern); err != nil {
			issues = append(issues, ValidationIssue{Level: ValidationWarning, Path: path, Message: fmt.Sprintf("invalid pattern %q: %v", pattern, err)})
		}
	}
	return issues
}

func validateScoringConfigIssues(cfg ScoringConfig) []ValidationIssue {
	values := []struct {
		path  string
		value int
	}{
		{path: "scoring.churn_max_lines_30d", value: cfg.ChurnMaxLines30d},
		{path: "scoring.complexity_max_loc", value: cfg.ComplexityMaxLOC},
		{path: "scoring.complexity_max_imports", value: cfg.ComplexityMaxImports},
		{path: "scoring.complexity_max_files", value: cfg.ComplexityMaxFiles},
		{path: "scoring.dependency_centrality_max_reverse_imports", value: cfg.DependencyCentralityMaxReverseImportCount},
	}
	var issues []ValidationIssue
	for _, item := range values {
		if item.value <= 0 {
			issues = append(issues, ValidationIssue{Level: ValidationWarning, Path: item.path, Message: "must be greater than zero"})
		}
	}
	return issues
}

func validateSuppressionIssues(s Suppression, policy SuppressionPolicy, context string, now time.Time) []ValidationIssue {
	var issues []ValidationIssue
	required := []struct {
		name  string
		value string
	}{
		{name: "id", value: s.ID},
		{name: "package", value: s.Package},
	}
	if policy.RequireReason {
		required = append(required, struct {
			name  string
			value string
		}{name: "reason", value: s.Reason})
	}
	if policy.RequireOwner {
		required = append(required, struct {
			name  string
			value string
		}{name: "owner", value: s.Owner})
	}
	if policy.RequireExpires {
		required = append(required, struct {
			name  string
			value string
		}{name: "expires", value: s.Expires})
	}
	for _, value := range required {
		if strings.TrimSpace(value.value) == "" {
			issues = append(issues, ValidationIssue{Level: ValidationWarning, Path: context + "." + value.name, Message: suppressionRequiredMessage(value.name, policy)})
		}
	}
	var expires time.Time
	if s.Expires != "" {
		expires = s.ExpiresTime()
		if expires.IsZero() {
			issues = append(issues, ValidationIssue{Level: ValidationWarning, Path: context + ".expires", Message: fmt.Sprintf("invalid expiry date %q; expected YYYY-MM-DD", s.Expires)})
		} else if expires.Before(dateOnly(now)) {
			issues = append(issues, ValidationIssue{Level: ValidationWarning, Path: context + ".expires", Message: fmt.Sprintf("suppression expired on %s", s.Expires)})
		}
	}
	var created time.Time
	if s.Created != "" {
		created = s.CreatedTime()
		if created.IsZero() {
			issues = append(issues, ValidationIssue{Level: ValidationWarning, Path: context + ".created", Message: fmt.Sprintf("invalid created date %q; expected YYYY-MM-DD", s.Created)})
		}
	}
	if policy.MaxDays > 0 && !expires.IsZero() {
		effective := dateOnly(now)
		if !created.IsZero() {
			effective = created
		}
		limit := effective.AddDate(0, 0, policy.MaxDays)
		if expires.After(limit) {
			issues = append(issues, ValidationIssue{
				Level:   ValidationWarning,
				Path:    context + ".expires",
				Message: fmt.Sprintf("suppression expiry %s exceeds suppression_policy.max_days (%d) from %s", s.Expires, policy.MaxDays, effective.Format("2006-01-02")),
			})
		}
	}
	if s.Package != "" {
		if err := validateGlobish(s.Package); err != nil {
			issues = append(issues, ValidationIssue{Level: ValidationWarning, Path: context + ".package", Message: fmt.Sprintf("invalid package pattern %q: %v", s.Package, err)})
		}
	}
	if s.Category != "" && !validCategory(s.Category) {
		issues = append(issues, ValidationIssue{Level: ValidationWarning, Path: context + ".category", Message: fmt.Sprintf("unknown category %q", s.Category)})
	}
	return issues
}

// ValidateSuppressionIssues validates one suppression against the resolved
// suppression policy. The returned diagnostics are warnings so non-strict scans
// can still apply policy-violating waivers while keeping them auditable.
func ValidateSuppressionIssues(s Suppression, policy SuppressionPolicy, context string, now time.Time) []ValidationIssue {
	return validateSuppressionIssues(s, policy, context, now)
}

func suppressionRequiredMessage(field string, policy SuppressionPolicy) string {
	switch field {
	case "owner":
		return "suppression missing owner required by suppression_policy.require_owner"
	case "reason":
		return "suppression missing reason required by suppression_policy.require_reason"
	case "expires":
		return "suppression missing expires required by suppression_policy.require_expiry"
	default:
		return "required suppression field is missing"
	}
}

func hashBytes(data []byte) string {
	// Keep this local to the policy package to avoid coupling config validation to storage.
	sum := [32]byte{}
	if data != nil {
		sum = sha256Sum(data)
	}
	return fmt.Sprintf("%x", sum)
}

func sha256Sum(data []byte) [32]byte {
	// Wrapped so tests can exercise ConfigHash without depending on storage internals.
	return sha256.Sum256(data)
}
