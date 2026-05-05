package cli

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/faultline-go/faultline/internal/policy"
	"github.com/faultline-go/faultline/internal/report"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type configOptions struct {
	config                 string
	format                 string
	strict                 bool
	out                    string
	allowConfigOutsideRepo bool
}

type configExplanation struct {
	Path               string                   `json:"path"`
	ConfigHash         string                   `json:"config_hash"`
	Ownership          policy.OwnershipConfig   `json:"ownership"`
	Owners             policy.OwnersConfig      `json:"owners,omitempty"`
	Coverage           policy.CoverageConfig    `json:"coverage"`
	TestRatioThreshold float64                  `json:"test_ratio_threshold"`
	Scoring            policy.ScoringConfig     `json:"scoring"`
	SuppressionPolicy  policy.SuppressionPolicy `json:"suppression_policy"`
	Boundaries         []policy.BoundaryRule    `json:"boundaries,omitempty"`
	Suppressions       []suppressionStatus      `json:"suppressions,omitempty"`
	Warnings           []policy.ValidationIssue `json:"warnings,omitempty"`
	WarningCount       int                      `json:"warning_count"`
	RulePacks          []policy.RulePackAudit   `json:"rule_packs,omitempty"`
}

type configSchema struct {
	SupportedVersion int             `json:"supported_version"`
	Sections         []schemaSection `json:"sections"`
	Examples         []schemaExample `json:"examples"`
}

type schemaSection struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Required    bool          `json:"required"`
	Fields      []schemaField `json:"fields"`
}

type schemaField struct {
	Path        string   `json:"path"`
	Type        string   `json:"type"`
	Required    bool     `json:"required"`
	Default     string   `json:"default_behavior"`
	Validation  []string `json:"validation_rules,omitempty"`
	Description string   `json:"description"`
}

type schemaExample struct {
	Name string `json:"name"`
	YAML string `json:"yaml"`
}

type suppressionStatus struct {
	Index           int      `json:"index"`
	ID              string   `json:"id"`
	Package         string   `json:"package"`
	Category        string   `json:"category,omitempty"`
	Reason          string   `json:"reason"`
	Owner           string   `json:"owner"`
	Expires         string   `json:"expires"`
	Created         string   `json:"created,omitempty"`
	Status          string   `json:"status"`
	DaysUntil       *int     `json:"days_until_expiry,omitempty"`
	Warnings        []string `json:"warnings,omitempty"`
	PolicyViolating bool     `json:"policy_violating,omitempty"`
}

type configDocs struct {
	Path               string                   `json:"path"`
	ConfigHash         string                   `json:"config_hash"`
	GeneratedAt        time.Time                `json:"generated_at"`
	Ownership          policy.OwnershipConfig   `json:"ownership"`
	Owners             policy.OwnersConfig      `json:"owners,omitempty"`
	Coverage           policy.CoverageConfig    `json:"coverage"`
	TestRatioThreshold float64                  `json:"test_ratio_threshold"`
	Scoring            policy.ScoringConfig     `json:"scoring"`
	SuppressionPolicy  policy.SuppressionPolicy `json:"suppression_policy"`
	Boundaries         []policy.BoundaryRule    `json:"boundaries,omitempty"`
	Active             []suppressionStatus      `json:"active_suppressions,omitempty"`
	Expired            []suppressionStatus      `json:"expired_suppressions,omitempty"`
	ExpiringSoon       []suppressionStatus      `json:"expiring_soon_suppressions,omitempty"`
	Invalid            []suppressionStatus      `json:"invalid_suppressions,omitempty"`
	PolicyViolations   []suppressionStatus      `json:"policy_violations,omitempty"`
	Issues             []policy.ValidationIssue `json:"issues,omitempty"`
	StrictModeReady    bool                     `json:"strict_mode_ready"`
	StrictModeSummary  string                   `json:"strict_mode_summary"`
	RulePacks          []policy.RulePackAudit   `json:"rule_packs,omitempty"`
	ResolvedConfigHash string                   `json:"resolved_config_hash"`
}

type resolvedConfigOutput struct {
	Config             policy.Config            `json:"config" yaml:"config"`
	RulePacks          []policy.RulePackAudit   `json:"rule_packs,omitempty" yaml:"rule_packs,omitempty"`
	Warnings           []policy.ValidationIssue `json:"warnings,omitempty" yaml:"warnings,omitempty"`
	ResolvedConfigHash string                   `json:"resolved_config_hash" yaml:"resolved_config_hash"`
}

func newConfigCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Validate and explain faultline.yaml",
	}
	cmd.AddCommand(newConfigValidateCommand())
	cmd.AddCommand(newConfigExplainCommand())
	cmd.AddCommand(newConfigSchemaCommand())
	cmd.AddCommand(newConfigDocsCommand())
	cmd.AddCommand(newConfigResolvedCommand())
	return cmd
}

func newConfigValidateCommand() *cobra.Command {
	var opts configOptions
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate faultline.yaml",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConfigValidate(cmd, opts)
		},
	}
	cmd.Flags().StringVar(&opts.config, "config", "faultline.yaml", "faultline config path")
	cmd.Flags().BoolVar(&opts.strict, "strict", false, "exit 1 when validation warnings are present")
	cmd.Flags().BoolVar(&opts.allowConfigOutsideRepo, "allow-config-outside-repo", false, "allow rule pack paths outside the repository root")
	return cmd
}

func newConfigExplainCommand() *cobra.Command {
	var opts configOptions
	cmd := &cobra.Command{
		Use:   "explain",
		Short: "Print normalized faultline.yaml policy inputs",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConfigExplain(cmd, opts)
		},
	}
	cmd.Flags().StringVar(&opts.config, "config", "faultline.yaml", "faultline config path")
	cmd.Flags().StringVar(&opts.format, "format", "markdown", "output format: markdown or json")
	cmd.Flags().StringVar(&opts.out, "out", "", "optional output path")
	cmd.Flags().BoolVar(&opts.allowConfigOutsideRepo, "allow-config-outside-repo", false, "allow rule pack paths outside the repository root")
	return cmd
}

func newConfigSchemaCommand() *cobra.Command {
	var opts configOptions
	cmd := &cobra.Command{
		Use:   "schema",
		Short: "Generate Faultline configuration schema documentation",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConfigSchema(cmd, opts)
		},
	}
	cmd.Flags().StringVar(&opts.format, "format", "markdown", "output format: markdown or json")
	cmd.Flags().StringVar(&opts.out, "out", "", "optional output path")
	return cmd
}

func newConfigDocsCommand() *cobra.Command {
	var opts configOptions
	cmd := &cobra.Command{
		Use:   "docs",
		Short: "Generate governance documentation from faultline.yaml",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConfigDocs(cmd, opts)
		},
	}
	cmd.Flags().StringVar(&opts.config, "config", "faultline.yaml", "faultline config path")
	cmd.Flags().StringVar(&opts.format, "format", "markdown", "output format: markdown or html")
	cmd.Flags().StringVar(&opts.out, "out", "", "optional output path")
	cmd.Flags().BoolVar(&opts.allowConfigOutsideRepo, "allow-config-outside-repo", false, "allow rule pack paths outside the repository root")
	return cmd
}

func newConfigResolvedCommand() *cobra.Command {
	var opts configOptions
	cmd := &cobra.Command{
		Use:   "resolved",
		Short: "Write the fully resolved Faultline config",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConfigResolved(cmd, opts)
		},
	}
	cmd.Flags().StringVar(&opts.config, "config", "faultline.yaml", "faultline config path")
	cmd.Flags().StringVar(&opts.format, "format", "yaml", "output format: yaml or json")
	cmd.Flags().StringVar(&opts.out, "out", "", "optional output path")
	cmd.Flags().BoolVar(&opts.allowConfigOutsideRepo, "allow-config-outside-repo", false, "allow rule pack paths outside the repository root")
	return cmd
}

func runConfigValidate(cmd *cobra.Command, opts configOptions) error {
	_, validation, err := resolveConfigForCLI(opts.config, opts.allowConfigOutsideRepo)
	if err != nil && validation.ConfigHash == "" {
		return ExitError{Code: 2, Err: err}
	}
	for _, issue := range validation.Issues {
		fmt.Fprintf(cmd.OutOrStdout(), "%s\n", formatValidationIssue(issue))
	}
	if validation.WarningCount == 0 && validation.ErrorCount == 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "valid: %s\nconfig_hash: %s\n", opts.config, validation.ConfigHash)
	}
	if validation.ErrorCount > 0 || err != nil {
		return ExitError{Code: 2, Err: fmt.Errorf("config validation failed with %d error(s)", validation.ErrorCount)}
	}
	if opts.strict && validation.WarningCount > 0 {
		if hasStrictConfigFailureWarning(validation) {
			return ExitError{Code: 2, Err: fmt.Errorf("strict config validation failed on enforcement warning(s)")}
		}
		return ExitError{Code: 1, Err: fmt.Errorf("config validation produced %d warning(s)", validation.WarningCount)}
	}
	return nil
}

func hasStrictConfigFailureWarning(validation policy.ValidationReport) bool {
	for _, issue := range validation.Issues {
		if issue.Level != policy.ValidationWarning {
			continue
		}
		if strings.Contains(issue.Message, "unknown key") && (strings.Contains(issue.Path, ".") || strings.Contains(issue.Path, "[")) {
			return true
		}
		if strings.HasPrefix(issue.Path, "suppressions[") || strings.HasPrefix(issue.Path, "suppression_policy") {
			return true
		}
	}
	return false
}

func runConfigExplain(cmd *cobra.Command, opts configOptions) error {
	cfg, validation, err := resolveConfigForCLI(opts.config, opts.allowConfigOutsideRepo)
	if err != nil && validation.ConfigHash == "" {
		return ExitError{Code: 2, Err: err}
	}
	if cfg == nil {
		return ExitError{Code: 2, Err: err}
	}
	format := strings.ToLower(strings.TrimSpace(opts.format))
	if format != "markdown" && format != "json" {
		return ExitError{Code: 2, Err: fmt.Errorf("unsupported format %q: expected markdown or json", opts.format)}
	}
	expl := explainConfig(opts.config, *cfg, validation, time.Now().UTC())
	var data []byte
	switch format {
	case "json":
		data, err = json.MarshalIndent(expl, "", "  ")
		if err == nil {
			data = append(data, '\n')
		}
	case "markdown":
		data = []byte(renderConfigExplanationMarkdown(expl))
	}
	if err != nil {
		return ExitError{Code: 2, Err: fmt.Errorf("render config explanation: %w", err)}
	}
	if opts.out != "" {
		if err := writeOutputFile(opts.out, data); err != nil {
			return ExitError{Code: 2, Err: err}
		}
	} else {
		fmt.Fprint(cmd.OutOrStdout(), string(data))
	}
	if validation.ErrorCount > 0 {
		return ExitError{Code: 2, Err: fmt.Errorf("config validation failed with %d error(s)", validation.ErrorCount)}
	}
	return nil
}

func runConfigSchema(cmd *cobra.Command, opts configOptions) error {
	format := strings.ToLower(strings.TrimSpace(opts.format))
	schema := buildConfigSchema()
	var data []byte
	var err error
	switch format {
	case "json":
		data, err = json.MarshalIndent(schema, "", "  ")
		if err == nil {
			data = append(data, '\n')
		}
	case "markdown":
		data = []byte(renderConfigSchemaMarkdown(schema))
	default:
		return ExitError{Code: 2, Err: fmt.Errorf("unsupported format %q: expected markdown or json", opts.format)}
	}
	if err != nil {
		return ExitError{Code: 2, Err: fmt.Errorf("render config schema: %w", err)}
	}
	if opts.out != "" {
		if err := writeOutputFile(opts.out, data); err != nil {
			return ExitError{Code: 2, Err: err}
		}
	} else {
		fmt.Fprint(cmd.OutOrStdout(), string(data))
	}
	return nil
}

func runConfigDocs(cmd *cobra.Command, opts configOptions) error {
	cfg, validation, err := resolveConfigForCLI(opts.config, opts.allowConfigOutsideRepo)
	if err != nil && validation.ConfigHash == "" {
		return ExitError{Code: 2, Err: err}
	}
	if cfg == nil {
		return ExitError{Code: 2, Err: err}
	}
	format := strings.ToLower(strings.TrimSpace(opts.format))
	if format != "markdown" && format != "html" {
		return ExitError{Code: 2, Err: fmt.Errorf("unsupported format %q: expected markdown or html", opts.format)}
	}
	docs := buildConfigDocs(opts.config, *cfg, validation, time.Now().UTC())
	var data []byte
	switch format {
	case "markdown":
		data = []byte(renderConfigDocsMarkdown(docs))
	case "html":
		var b strings.Builder
		if execErr := configDocsHTML.Execute(&b, docs); execErr != nil {
			return ExitError{Code: 2, Err: fmt.Errorf("render config docs HTML: %w", execErr)}
		}
		b.WriteByte('\n')
		data = []byte(b.String())
	}
	if opts.out != "" {
		if err := writeOutputFile(opts.out, data); err != nil {
			return ExitError{Code: 2, Err: err}
		}
	} else {
		fmt.Fprint(cmd.OutOrStdout(), string(data))
	}
	if validation.ErrorCount > 0 || err != nil {
		return ExitError{Code: 2, Err: fmt.Errorf("config validation failed with %d error(s)", validation.ErrorCount)}
	}
	return nil
}

func runConfigResolved(cmd *cobra.Command, opts configOptions) error {
	cfg, validation, err := resolveConfigForCLI(opts.config, opts.allowConfigOutsideRepo)
	if err != nil && validation.ConfigHash == "" {
		return ExitError{Code: 2, Err: err}
	}
	if cfg == nil {
		return ExitError{Code: 2, Err: err}
	}
	format := strings.ToLower(strings.TrimSpace(opts.format))
	out := resolvedConfigOutput{
		Config:             *cfg,
		RulePacks:          append([]policy.RulePackAudit{}, validation.RulePacks...),
		Warnings:           append([]policy.ValidationIssue{}, validation.Issues...),
		ResolvedConfigHash: validation.ConfigHash,
	}
	var data []byte
	switch format {
	case "json":
		var marshalErr error
		data, marshalErr = json.MarshalIndent(out, "", "  ")
		if marshalErr != nil {
			return ExitError{Code: 2, Err: fmt.Errorf("marshal resolved config: %w", marshalErr)}
		}
		data = append(data, '\n')
	case "yaml":
		var marshalErr error
		data, marshalErr = yaml.Marshal(out)
		if marshalErr != nil {
			return ExitError{Code: 2, Err: fmt.Errorf("marshal resolved config: %w", marshalErr)}
		}
	default:
		return ExitError{Code: 2, Err: fmt.Errorf("unsupported format %q: expected yaml or json", opts.format)}
	}
	if opts.out != "" {
		if err := writeOutputFile(opts.out, data); err != nil {
			return ExitError{Code: 2, Err: err}
		}
	} else {
		fmt.Fprint(cmd.OutOrStdout(), string(data))
	}
	if validation.ErrorCount > 0 || err != nil {
		return ExitError{Code: 2, Err: fmt.Errorf("config validation failed with %d error(s)", validation.ErrorCount)}
	}
	return nil
}

func resolveConfigForCLI(path string, allowOutside bool) (*policy.Config, policy.ValidationReport, error) {
	repoRoot, err := os.Getwd()
	if err != nil {
		return nil, policy.ValidationReport{Path: path}, fmt.Errorf("get working directory: %w", err)
	}
	return policy.ResolveConfigWithValidation(path, policy.ResolveOptions{
		RepoRoot:               repoRoot,
		AllowConfigOutsideRepo: allowOutside,
	})
}

func explainConfig(path string, cfg policy.Config, validation policy.ValidationReport, now time.Time) configExplanation {
	warnings := make([]policy.ValidationIssue, 0, len(validation.Issues))
	for _, issue := range validation.Issues {
		if issue.Level == policy.ValidationWarning {
			warnings = append(warnings, issue)
		}
	}
	return configExplanation{
		Path:               path,
		ConfigHash:         validation.ConfigHash,
		Ownership:          cfg.Ownership,
		Owners:             cfg.Owners,
		Coverage:           cfg.Coverage,
		TestRatioThreshold: cfg.TestRatioThreshold,
		Scoring:            policy.NormalizeScoringConfig(cfg.Scoring),
		SuppressionPolicy:  cfg.SuppressionPolicy,
		Boundaries:         append([]policy.BoundaryRule{}, cfg.Boundaries...),
		Suppressions:       suppressionStatuses(cfg.Suppressions, cfg.SuppressionPolicy, now),
		Warnings:           warnings,
		WarningCount:       len(warnings),
		RulePacks:          append([]policy.RulePackAudit{}, validation.RulePacks...),
	}
}

func renderConfigExplanationMarkdown(expl configExplanation) string {
	var b strings.Builder
	fmt.Fprintln(&b, "# Faultline Config Explanation")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "- Path: `%s`\n", expl.Path)
	fmt.Fprintf(&b, "- Config hash: `%s`\n", expl.ConfigHash)
	if len(expl.RulePacks) > 0 {
		fmt.Fprintln(&b, "- Rule packs:")
		for _, pack := range expl.RulePacks {
			fmt.Fprintf(&b, "  - `%s` imported `%v` hash `%s`\n", pack.Path, pack.Imported, pack.ContentHash)
		}
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Ownership")
	fmt.Fprintf(&b, "- Require CODEOWNERS: `%v`\n", expl.Ownership.RequireCodeowners)
	fmt.Fprintf(&b, "- Max authors in 90 days: `%d`\n", expl.Ownership.MaxAuthorCount90d)
	if len(expl.Owners.Modules) > 0 {
		fmt.Fprintln(&b, "- Module owners:")
		for _, modulePath := range sortedModuleOwnerKeys(expl.Owners.Modules) {
			fmt.Fprintf(&b, "  - `%s`: `%s`\n", modulePath, expl.Owners.Modules[modulePath].Owner)
		}
	}
	if len(expl.Owners.Aliases) > 0 {
		fmt.Fprintln(&b, "- Ownership aliases:")
		for _, owner := range sortedAliasKeys(expl.Owners.Aliases) {
			fmt.Fprintf(&b, "  - `%s`: `%s`\n", owner, strings.Join(expl.Owners.Aliases[owner], ", "))
		}
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Coverage")
	fmt.Fprintf(&b, "- Minimum package coverage: `%.2f`\n", expl.Coverage.MinPackageCoverage)
	fmt.Fprintf(&b, "- Test-to-code ratio threshold: `%.2f`\n", expl.TestRatioThreshold)
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Scoring Calibration")
	fmt.Fprintf(&b, "- Churn max lines in 30 days: `%d`\n", expl.Scoring.ChurnMaxLines30d)
	fmt.Fprintf(&b, "- Complexity max LOC: `%d`\n", expl.Scoring.ComplexityMaxLOC)
	fmt.Fprintf(&b, "- Complexity max imports: `%d`\n", expl.Scoring.ComplexityMaxImports)
	fmt.Fprintf(&b, "- Complexity max files: `%d`\n", expl.Scoring.ComplexityMaxFiles)
	fmt.Fprintf(&b, "- Dependency centrality max reverse imports: `%d`\n", expl.Scoring.DependencyCentralityMaxReverseImportCount)
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Suppression Policy")
	fmt.Fprintf(&b, "- Require owner: `%v`\n", expl.SuppressionPolicy.RequireOwner)
	fmt.Fprintf(&b, "- Require reason: `%v`\n", expl.SuppressionPolicy.RequireReason)
	fmt.Fprintf(&b, "- Require expiry: `%v`\n", expl.SuppressionPolicy.RequireExpires)
	if expl.SuppressionPolicy.MaxDays > 0 {
		fmt.Fprintf(&b, "- Maximum waiver duration: `%d` days\n", expl.SuppressionPolicy.MaxDays)
	} else {
		fmt.Fprintln(&b, "- Maximum waiver duration: not enforced")
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Boundaries")
	if len(expl.Boundaries) == 0 {
		fmt.Fprintln(&b, "No boundary rules configured.")
	} else {
		for _, rule := range expl.Boundaries {
			fmt.Fprintf(&b, "- `%s`: from `%s`, deny `%s`", rule.Name, rule.From, strings.Join(rule.Deny, ", "))
			if len(rule.Except) > 0 {
				fmt.Fprintf(&b, ", except `%s`", strings.Join(rule.Except, ", "))
			}
			fmt.Fprintln(&b)
		}
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Suppressions")
	if len(expl.Suppressions) == 0 {
		fmt.Fprintln(&b, "No suppressions configured.")
	} else {
		for _, s := range expl.Suppressions {
			fmt.Fprintf(&b, "- `%s` for `%s`: %s, owner `%s`, expires `%s`", s.ID, s.Package, s.Status, s.Owner, s.Expires)
			if len(s.Warnings) > 0 {
				fmt.Fprintf(&b, " (%s)", strings.Join(s.Warnings, "; "))
			}
			fmt.Fprintln(&b)
		}
	}
	if len(expl.Warnings) > 0 {
		fmt.Fprintln(&b)
		fmt.Fprintln(&b, "## Warnings")
		for _, warning := range expl.Warnings {
			fmt.Fprintf(&b, "- %s\n", formatValidationIssue(warning))
		}
	}
	return b.String()
}

func buildConfigSchema() configSchema {
	return configSchema{
		SupportedVersion: policy.SupportedConfigVersion,
		Sections: []schemaSection{
			{
				Name:        "version",
				Description: "Configuration schema version.",
				Required:    true,
				Fields: []schemaField{
					{Path: "version", Type: "integer", Required: true, Default: "No default in policy files; value must be present for auditable CI use.", Validation: []string{"must equal 1"}, Description: "Faultline config schema version."},
					{Path: "test_ratio_threshold", Type: "number", Default: "0.20", Validation: []string{"must be zero or greater", "values at or below zero use the default"}, Description: "Minimum TestLOC/LOC ratio before FL-TST-002 is emitted for packages that have test files."},
				},
			},
			{
				Name:        "ownership",
				Description: "Ownership policy thresholds and CODEOWNERS expectations.",
				Fields: []schemaField{
					{Path: "ownership.require_codeowners", Type: "boolean", Default: "false", Description: "When true, missing CODEOWNERS owners can produce ownership findings."},
					{Path: "ownership.max_author_count_90d", Type: "integer", Default: "6", Validation: []string{"must be zero or greater", "values over 1000 warn as suspicious"}, Description: "Maximum expected distinct authors in 90 days before ownership risk increases."},
				},
			},
			{
				Name:        "owners",
				Description: "Enterprise owner aliases and explicit module owners used for package ownership resolution.",
				Fields: []schemaField{
					{Path: "owners.aliases.<owner>", Type: "array of strings", Default: "empty", Validation: []string{"owner key must not be empty", "identity values must not be empty"}, Description: "Maps emails or external team handles to a canonical owner/team."},
					{Path: "owners.modules.<module_path>.owner", Type: "string", Default: "empty", Validation: []string{"owner must not be empty when module entry is present"}, Description: "Explicit owner for a Go module path. This has the highest ownership precedence."},
				},
			},
			{
				Name:        "rule_packs",
				Description: "Local reusable governance policy files imported before repo-local overrides.",
				Fields: []schemaField{
					{Path: "rule_packs[].path", Type: "string", Required: true, Validation: []string{"local file only", "no environment expansion", "must stay inside repo root unless --allow-config-outside-repo is used"}, Description: "Repo-relative or absolute local rule pack path."},
				},
			},
			{
				Name:        "coverage",
				Description: "Coverage thresholds used when a Go cover profile is supplied.",
				Fields: []schemaField{
					{Path: "coverage.min_package_coverage", Type: "number", Default: "60", Validation: []string{"must be between 0 and 100"}, Description: "Minimum acceptable package coverage percentage."},
				},
			},
			{
				Name:        "scoring",
				Description: "Calibration constants for normalized risk score components.",
				Fields: []schemaField{
					{Path: "scoring.churn_max_lines_30d", Type: "integer", Default: "1000", Validation: []string{"must be greater than zero"}, Description: "Added plus deleted lines in 30 days that maps to a 100 churn component score."},
					{Path: "scoring.complexity_max_loc", Type: "integer", Default: "1000", Validation: []string{"must be greater than zero"}, Description: "Non-generated package LOC that maps to a 100 LOC complexity subcomponent."},
					{Path: "scoring.complexity_max_imports", Type: "integer", Default: "20", Validation: []string{"must be greater than zero"}, Description: "Direct non-standard imports that map to a 100 import complexity subcomponent."},
					{Path: "scoring.complexity_max_files", Type: "integer", Default: "30", Validation: []string{"must be greater than zero"}, Description: "Non-generated files that map to a 100 file-count complexity subcomponent."},
					{Path: "scoring.dependency_centrality_max_reverse_imports", Type: "integer", Default: "10", Validation: []string{"must be greater than zero"}, Description: "Reverse imports that map to a 100 dependency centrality component score."},
				},
			},
			{
				Name:        "suppression_policy",
				Description: "Default governance expectations for repo-local suppressions.",
				Fields: []schemaField{
					{Path: "suppression_policy.require_owner", Type: "boolean", Default: "true", Description: "Require suppression owner metadata."},
					{Path: "suppression_policy.require_reason", Type: "boolean", Default: "true", Description: "Require suppression reason metadata."},
					{Path: "suppression_policy.require_expiry", Type: "boolean", Default: "true", Description: "Require suppression expiry metadata."},
					{Path: "suppression_policy.max_days", Type: "integer", Default: "0 (no maximum duration)", Validation: []string{"must be zero or greater", "when positive, suppressions must expire within created date or scan date plus this many days"}, Description: "Maximum waiver duration in days."},
				},
			},
			{
				Name:        "boundaries",
				Description: "Architecture boundary rules evaluated against package imports.",
				Fields: []schemaField{
					{Path: "boundaries[].name", Type: "string", Required: true, Validation: []string{"must not be empty"}, Description: "Human-readable rule name."},
					{Path: "boundaries[].from", Type: "glob string", Required: true, Validation: []string{"must be a valid package import path or directory glob"}, Description: "Importing package pattern the rule applies to."},
					{Path: "boundaries[].deny", Type: "array of glob strings", Required: true, Validation: []string{"must contain at least one valid glob"}, Description: "Denied imported package patterns."},
					{Path: "boundaries[].except", Type: "array of glob strings", Default: "empty", Validation: []string{"each value must be a valid glob"}, Description: "Allowed exceptions for importers or denied imports."},
				},
			},
			{
				Name:        "suppressions",
				Description: "Expiring waivers for specific findings.",
				Fields: []schemaField{
					{Path: "suppressions[].id", Type: "string", Required: true, Validation: []string{"must not be empty"}, Description: "Faultline finding ID, for example FL-BND-001."},
					{Path: "suppressions[].package", Type: "glob string", Required: true, Validation: []string{"must be a valid package import path or directory glob"}, Description: "Package import path or directory pattern."},
					{Path: "suppressions[].category", Type: "string", Default: "any category for the finding ID", Validation: []string{"when present, must be one of OWNERSHIP, CHURN, COVERAGE, COMPLEXITY, BOUNDARY"}, Description: "Optional category narrowing."},
					{Path: "suppressions[].reason", Type: "string", Required: true, Validation: []string{"must not be empty"}, Description: "Governance reason for the waiver."},
					{Path: "suppressions[].owner", Type: "string", Required: true, Validation: []string{"must not be empty"}, Description: "Team or person accountable for the waiver."},
					{Path: "suppressions[].created", Type: "date string", Default: "scan/config validation date", Validation: []string{"must use YYYY-MM-DD when present", "used as the starting date for suppression_policy.max_days"}, Description: "Optional waiver creation date."},
					{Path: "suppressions[].expires", Type: "date string", Required: true, Validation: []string{"must use YYYY-MM-DD", "expired suppressions are ignored and warned", "must not exceed suppression_policy.max_days when configured"}, Description: "Expiry date for waiver review."},
				},
			},
		},
		Examples: []schemaExample{
			{
				Name: "basic policy",
				YAML: `version: 1
rule_packs:
  - path: .faultline/rules/platform.yaml
ownership:
  require_codeowners: true
  max_author_count_90d: 6
owners:
  aliases:
    "@payments-platform":
      - "alice@example.com"
      - "bob@example.com"
      - "@github-team/payments"
  modules:
    "github.com/acme/service-a":
      owner: "@service-a-team"
coverage:
  min_package_coverage: 60
scoring:
  churn_max_lines_30d: 1000
  complexity_max_loc: 1000
  complexity_max_imports: 20
  complexity_max_files: 30
  dependency_centrality_max_reverse_imports: 10
suppression_policy:
  require_owner: true
  require_reason: true
  require_expiry: true
  max_days: 90
boundaries:
  - name: handlers-must-not-import-storage
    from: "*/internal/handlers/*"
    deny:
      - "*/internal/storage/*"
    except:
      - "*/internal/storage/contracts"
suppressions:
  - id: FL-BND-001
    category: BOUNDARY
    package: "*/internal/legacy/*"
    reason: "Legacy migration in progress"
    owner: "@platform-team"
    created: "2026-04-01"
    expires: "2026-06-30"
`,
			},
		},
	}
}

func renderConfigSchemaMarkdown(schema configSchema) string {
	var b strings.Builder
	fmt.Fprintln(&b, "# Faultline Config Schema")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "- Supported version: `%d`\n", schema.SupportedVersion)
	for _, section := range schema.Sections {
		fmt.Fprintf(&b, "\n## %s\n\n", section.Name)
		fmt.Fprintln(&b, section.Description)
		fmt.Fprintln(&b)
		fmt.Fprintln(&b, "| Field | Required | Type | Default behavior | Validation | Description |")
		fmt.Fprintln(&b, "|---|---:|---|---|---|---|")
		for _, field := range section.Fields {
			fmt.Fprintf(&b, "| `%s` | %v | %s | %s | %s | %s |\n",
				field.Path, field.Required, field.Type, field.Default, strings.Join(field.Validation, "; "), field.Description)
		}
	}
	if len(schema.Examples) > 0 {
		fmt.Fprintln(&b, "\n## Examples")
		for _, example := range schema.Examples {
			fmt.Fprintf(&b, "\n### %s\n\n", example.Name)
			fmt.Fprintf(&b, "```yaml\n%s```\n", example.YAML)
		}
	}
	return b.String()
}

func buildConfigDocs(path string, cfg policy.Config, validation policy.ValidationReport, now time.Time) configDocs {
	docs := configDocs{
		Path:               path,
		ConfigHash:         validation.ConfigHash,
		GeneratedAt:        now.UTC(),
		Ownership:          cfg.Ownership,
		Owners:             cfg.Owners,
		Coverage:           cfg.Coverage,
		TestRatioThreshold: cfg.TestRatioThreshold,
		Scoring:            policy.NormalizeScoringConfig(cfg.Scoring),
		SuppressionPolicy:  cfg.SuppressionPolicy,
		Boundaries:         append([]policy.BoundaryRule{}, cfg.Boundaries...),
		Issues:             append([]policy.ValidationIssue{}, validation.Issues...),
		RulePacks:          append([]policy.RulePackAudit{}, validation.RulePacks...),
		ResolvedConfigHash: validation.ConfigHash,
	}
	for _, status := range suppressionStatuses(cfg.Suppressions, cfg.SuppressionPolicy, now) {
		if status.PolicyViolating {
			docs.PolicyViolations = append(docs.PolicyViolations, status)
		}
		switch status.Status {
		case "expired":
			docs.Expired = append(docs.Expired, status)
		case "expiring_soon":
			docs.ExpiringSoon = append(docs.ExpiringSoon, status)
			docs.Active = append(docs.Active, status)
		case "invalid":
			docs.Invalid = append(docs.Invalid, status)
		default:
			docs.Active = append(docs.Active, status)
		}
	}
	sortSuppressionStatuses(docs.Active)
	sortSuppressionStatuses(docs.Expired)
	sortSuppressionStatuses(docs.ExpiringSoon)
	sortSuppressionStatuses(docs.Invalid)
	sortSuppressionStatuses(docs.PolicyViolations)
	docs.StrictModeReady = validation.WarningCount == 0 && validation.ErrorCount == 0
	if docs.StrictModeReady {
		docs.StrictModeSummary = "Ready for --strict-config enforcement."
	} else {
		docs.StrictModeSummary = fmt.Sprintf("Not ready for --strict-config: %d warning(s), %d error(s).", validation.WarningCount, validation.ErrorCount)
	}
	return docs
}

func renderConfigDocsMarkdown(docs configDocs) string {
	var b strings.Builder
	fmt.Fprintln(&b, "# Faultline Policy Documentation")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "- Config: `%s`\n", docs.Path)
	fmt.Fprintf(&b, "- Config hash: `%s`\n", docs.ConfigHash)
	if len(docs.RulePacks) > 0 {
		fmt.Fprintln(&b, "- Rule packs:")
		for _, pack := range docs.RulePacks {
			fmt.Fprintf(&b, "  - `%s` imported `%v` hash `%s`\n", pack.Path, pack.Imported, pack.ContentHash)
		}
	}
	fmt.Fprintf(&b, "- Generated at: `%s`\n", docs.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "- Strict-mode suitability: %s\n", docs.StrictModeSummary)
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Ownership Rules")
	fmt.Fprintf(&b, "- Require CODEOWNERS: `%v`\n", docs.Ownership.RequireCodeowners)
	fmt.Fprintf(&b, "- Max authors in 90 days: `%d`\n", docs.Ownership.MaxAuthorCount90d)
	if len(docs.Owners.Modules) > 0 {
		fmt.Fprintln(&b, "- Module owners:")
		for _, modulePath := range sortedModuleOwnerKeys(docs.Owners.Modules) {
			fmt.Fprintf(&b, "  - `%s`: `%s`\n", modulePath, docs.Owners.Modules[modulePath].Owner)
		}
	}
	if len(docs.Owners.Aliases) > 0 {
		fmt.Fprintln(&b, "- Ownership aliases:")
		for _, owner := range sortedAliasKeys(docs.Owners.Aliases) {
			fmt.Fprintf(&b, "  - `%s`: `%s`\n", owner, strings.Join(docs.Owners.Aliases[owner], ", "))
		}
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Coverage Thresholds")
	fmt.Fprintf(&b, "- Minimum package coverage: `%.2f`\n", docs.Coverage.MinPackageCoverage)
	fmt.Fprintf(&b, "- Test-to-code ratio threshold: `%.2f`\n", docs.TestRatioThreshold)
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Scoring Calibration")
	fmt.Fprintf(&b, "- Churn max lines in 30 days: `%d`\n", docs.Scoring.ChurnMaxLines30d)
	fmt.Fprintf(&b, "- Complexity max LOC: `%d`\n", docs.Scoring.ComplexityMaxLOC)
	fmt.Fprintf(&b, "- Complexity max imports: `%d`\n", docs.Scoring.ComplexityMaxImports)
	fmt.Fprintf(&b, "- Complexity max files: `%d`\n", docs.Scoring.ComplexityMaxFiles)
	fmt.Fprintf(&b, "- Dependency centrality max reverse imports: `%d`\n", docs.Scoring.DependencyCentralityMaxReverseImportCount)
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Suppression Policy")
	fmt.Fprintf(&b, "- Require owner: `%v`\n", docs.SuppressionPolicy.RequireOwner)
	fmt.Fprintf(&b, "- Require reason: `%v`\n", docs.SuppressionPolicy.RequireReason)
	fmt.Fprintf(&b, "- Require expiry: `%v`\n", docs.SuppressionPolicy.RequireExpires)
	if docs.SuppressionPolicy.MaxDays > 0 {
		fmt.Fprintf(&b, "- Maximum waiver duration: `%d` days\n", docs.SuppressionPolicy.MaxDays)
	} else {
		fmt.Fprintln(&b, "- Maximum waiver duration: not enforced")
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Boundary Rules")
	if len(docs.Boundaries) == 0 {
		fmt.Fprintln(&b, "No boundary rules configured.")
	} else {
		for _, rule := range docs.Boundaries {
			fmt.Fprintf(&b, "- `%s`: from `%s`, deny `%s`", rule.Name, rule.From, strings.Join(rule.Deny, ", "))
			if len(rule.Except) > 0 {
				fmt.Fprintf(&b, ", except `%s`", strings.Join(rule.Except, ", "))
			}
			fmt.Fprintln(&b)
		}
	}
	renderSuppressionSection(&b, "Active Suppressions", docs.Active)
	renderSuppressionSection(&b, "Expired Suppressions", docs.Expired)
	renderSuppressionSection(&b, "Expiring Soon Suppressions", docs.ExpiringSoon)
	renderSuppressionSection(&b, "Invalid Suppressions", docs.Invalid)
	renderSuppressionSection(&b, "Policy-Violating Suppressions", docs.PolicyViolations)
	if len(docs.Issues) > 0 {
		fmt.Fprintln(&b, "\n## Warnings And Errors")
		for _, issue := range docs.Issues {
			fmt.Fprintf(&b, "- %s\n", formatValidationIssue(issue))
		}
	}
	return b.String()
}

func sortedModuleOwnerKeys(values map[string]policy.ModuleOwnerConfig) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedAliasKeys(values map[string][]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

var configDocsHTML = template.Must(template.New("config-docs").Funcs(template.FuncMap{"join": strings.Join}).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Faultline Policy Documentation</title>
<style>body{font-family:system-ui,sans-serif;margin:32px;color:#17202a}table{width:100%;border-collapse:collapse;margin:16px 0}th,td{border-bottom:1px solid #d7dde5;padding:8px;text-align:left;vertical-align:top}th{background:#eef2f6}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}.warn{background:#fff7e8;border:1px solid #e4c37a;border-radius:8px;padding:10px;margin:8px 0}</style></head>
<body><h1>Faultline Policy Documentation</h1>
<p>Config <span class="mono">{{.Path}}</span> · hash <span class="mono">{{.ConfigHash}}</span></p>
<p>{{.StrictModeSummary}}</p>
{{if .RulePacks}}<h2>Rule Packs</h2><table><thead><tr><th>Path</th><th>Imported</th><th>Content Hash</th></tr></thead><tbody>{{range .RulePacks}}<tr><td class="mono">{{.Path}}</td><td>{{.Imported}}</td><td class="mono">{{.ContentHash}}</td></tr>{{end}}</tbody></table>{{end}}
<h2>Ownership Rules</h2><ul><li>Require CODEOWNERS: <span class="mono">{{.Ownership.RequireCodeowners}}</span></li><li>Max authors in 90 days: <span class="mono">{{.Ownership.MaxAuthorCount90d}}</span></li></ul>
<h2>Coverage Thresholds</h2><p>Minimum package coverage: <span class="mono">{{printf "%.2f" .Coverage.MinPackageCoverage}}</span></p><p>Test-to-code ratio threshold: <span class="mono">{{printf "%.2f" .TestRatioThreshold}}</span></p>
<h2>Scoring Calibration</h2><ul><li>Churn max lines in 30 days: <span class="mono">{{.Scoring.ChurnMaxLines30d}}</span></li><li>Complexity max LOC: <span class="mono">{{.Scoring.ComplexityMaxLOC}}</span></li><li>Complexity max imports: <span class="mono">{{.Scoring.ComplexityMaxImports}}</span></li><li>Complexity max files: <span class="mono">{{.Scoring.ComplexityMaxFiles}}</span></li><li>Dependency centrality max reverse imports: <span class="mono">{{.Scoring.DependencyCentralityMaxReverseImportCount}}</span></li></ul>
<h2>Suppression Policy</h2><ul><li>Require owner: <span class="mono">{{.SuppressionPolicy.RequireOwner}}</span></li><li>Require reason: <span class="mono">{{.SuppressionPolicy.RequireReason}}</span></li><li>Require expiry: <span class="mono">{{.SuppressionPolicy.RequireExpires}}</span></li><li>Maximum waiver duration: <span class="mono">{{.SuppressionPolicy.MaxDays}}</span> days</li></ul>
<h2>Boundary Rules</h2>{{if .Boundaries}}<table><thead><tr><th>Name</th><th>From</th><th>Deny</th><th>Except</th></tr></thead><tbody>{{range .Boundaries}}<tr><td>{{.Name}}</td><td class="mono">{{.From}}</td><td class="mono">{{join .Deny ", "}}</td><td class="mono">{{join .Except ", "}}</td></tr>{{end}}</tbody></table>{{else}}<p>No boundary rules configured.</p>{{end}}
<h2>Active Suppressions</h2>{{template "supps" .Active}}
{{if .Expired}}<h2>Expired Suppressions</h2>{{template "supps" .Expired}}{{end}}
{{if .ExpiringSoon}}<h2>Expiring Soon Suppressions</h2>{{template "supps" .ExpiringSoon}}{{end}}
{{if .Invalid}}<h2>Invalid Suppressions</h2>{{template "supps" .Invalid}}{{end}}
{{if .PolicyViolations}}<h2>Policy-Violating Suppressions</h2>{{template "supps" .PolicyViolations}}{{end}}
{{if .Issues}}<h2>Warnings And Errors</h2>{{range .Issues}}<div class="warn"><span class="mono">{{.Level}} {{.Path}}</span>: {{.Message}}</div>{{end}}{{end}}
</body></html>
{{define "supps"}}{{if .}}<table><thead><tr><th>ID</th><th>Package</th><th>Owner</th><th>Created</th><th>Expires</th><th>Status</th><th>Warnings</th></tr></thead><tbody>{{range .}}<tr><td>{{.ID}}</td><td class="mono">{{.Package}}</td><td>{{.Owner}}</td><td>{{.Created}}</td><td>{{.Expires}}</td><td>{{.Status}}</td><td>{{join .Warnings "; "}}</td></tr>{{end}}</tbody></table>{{else}}<p>No suppressions in this group.</p>{{end}}{{end}}`))

func suppressionStatuses(suppressions []policy.Suppression, suppressionPolicy policy.SuppressionPolicy, now time.Time) []suppressionStatus {
	out := make([]suppressionStatus, 0, len(suppressions))
	for i, suppression := range suppressions {
		status := suppressionStatus{
			Index:    i,
			ID:       suppression.ID,
			Package:  suppression.Package,
			Category: suppression.Category,
			Reason:   suppression.Reason,
			Owner:    suppression.Owner,
			Expires:  suppression.Expires,
			Created:  suppression.Created,
			Status:   "active",
		}
		for _, issue := range policy.ValidateSuppressionIssues(suppression, suppressionPolicy, fmt.Sprintf("suppressions[%d]", i), now) {
			status.PolicyViolating = true
			status.Warnings = append(status.Warnings, issue.Message)
		}
		if suppressionBlockedByPolicy(suppression, suppressionPolicy) {
			status.Status = "invalid"
		}
		expires := suppression.ExpiresTime()
		if suppression.Expires != "" && expires.IsZero() {
			status.Status = "invalid"
		} else if !expires.IsZero() {
			days := int(expires.Sub(dateOnly(now)).Hours() / 24)
			status.DaysUntil = &days
			if days < 0 {
				status.Status = "expired"
			} else if days <= 30 && status.Status == "active" {
				status.Status = "expiring_soon"
			}
		}
		out = append(out, status)
	}
	return out
}

func suppressionBlockedByPolicy(suppression policy.Suppression, suppressionPolicy policy.SuppressionPolicy) bool {
	if strings.TrimSpace(suppression.ID) == "" || strings.TrimSpace(suppression.Package) == "" {
		return true
	}
	if suppressionPolicy.RequireOwner && strings.TrimSpace(suppression.Owner) == "" {
		return true
	}
	if suppressionPolicy.RequireReason && strings.TrimSpace(suppression.Reason) == "" {
		return true
	}
	if suppressionPolicy.RequireExpires && strings.TrimSpace(suppression.Expires) == "" {
		return true
	}
	if strings.TrimSpace(suppression.Expires) != "" && suppression.ExpiresTime().IsZero() {
		return true
	}
	return false
}

func dateOnly(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

type suppressionAudit struct {
	ConfigPath       string              `json:"config_path"`
	ConfigHash       string              `json:"config_hash"`
	GeneratedAt      time.Time           `json:"generated_at"`
	Active           []suppressionStatus `json:"active,omitempty"`
	Expired          []suppressionStatus `json:"expired,omitempty"`
	ExpiringSoon     []suppressionStatus `json:"expiring_soon,omitempty"`
	Invalid          []suppressionStatus `json:"invalid,omitempty"`
	PolicyViolations []suppressionStatus `json:"policy_violations,omitempty"`
	Unmatched        []suppressionStatus `json:"unmatched,omitempty"`
	Warnings         []report.Warning    `json:"warnings,omitempty"`
}

type suppressionOptions struct {
	config                 string
	format                 string
	out                    string
	strictConfig           bool
	allowConfigOutsideRepo bool
	coverage               string
	tags                   string
	includeGenerated       bool
	excludes               []string
	verbose                bool
}

func newSuppressionsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "suppressions",
		Short: "Audit configured suppressions",
	}
	cmd.AddCommand(newSuppressionsAuditCommand())
	return cmd
}

func newSuppressionsAuditCommand() *cobra.Command {
	var opts suppressionOptions
	cmd := &cobra.Command{
		Use:   "audit [patterns...]",
		Short: "Audit suppression age, ownership, expiry, and current matches",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				args = []string{"./..."}
			}
			return runSuppressionsAudit(cmd, opts, args)
		},
	}
	cmd.Flags().StringVar(&opts.config, "config", "faultline.yaml", "faultline config path")
	cmd.Flags().StringVar(&opts.format, "format", "markdown", "output format: json, markdown, or html")
	cmd.Flags().StringVar(&opts.out, "out", "", "optional output path")
	cmd.Flags().BoolVar(&opts.strictConfig, "strict-config", false, "fail on config validation warnings or errors")
	cmd.Flags().BoolVar(&opts.allowConfigOutsideRepo, "allow-config-outside-repo", false, "allow rule pack paths outside the repository root")
	cmd.Flags().StringVar(&opts.coverage, "coverage", "", "optional Go coverage profile")
	cmd.Flags().StringVar(&opts.tags, "tags", "", "comma-separated Go build tags")
	cmd.Flags().BoolVar(&opts.includeGenerated, "include-generated", false, "include generated code LOC in complexity scoring")
	cmd.Flags().StringArrayVar(&opts.excludes, "exclude", nil, "exclude package directories matching a repo-relative glob; repeatable")
	cmd.Flags().BoolVar(&opts.verbose, "verbose", false, "print scan progress")
	return cmd
}

func runSuppressionsAudit(cmd *cobra.Command, opts suppressionOptions, patterns []string) error {
	cfg, validation, err := resolveConfigForCLI(opts.config, opts.allowConfigOutsideRepo)
	if err != nil {
		return ExitError{Code: 2, Err: err}
	}
	if opts.strictConfig && validation.HasWarnings() {
		return ExitError{Code: 2, Err: fmt.Errorf("strict config validation failed with %d warning(s)", validation.WarningCount)}
	}
	rep, err := buildScanReport(cmd, scanOptions{
		coverage:               opts.coverage,
		config:                 opts.config,
		tags:                   opts.tags,
		includeGenerated:       opts.includeGenerated,
		excludes:               append([]string{}, opts.excludes...),
		noHistory:              true,
		strictConfig:           opts.strictConfig,
		allowConfigOutsideRepo: opts.allowConfigOutsideRepo,
		verbose:                opts.verbose,
	}, patterns)
	if err != nil {
		return ExitError{Code: 2, Err: err}
	}
	audit := buildSuppressionAudit(opts.config, validation.ConfigHash, *cfg, rep, time.Now().UTC())
	data, err := marshalSuppressionAudit(opts.format, audit)
	if err != nil {
		return ExitError{Code: 2, Err: err}
	}
	if opts.out != "" {
		if err := writeOutputFile(opts.out, data); err != nil {
			return ExitError{Code: 2, Err: err}
		}
	} else {
		fmt.Fprint(cmd.OutOrStdout(), string(data))
	}
	return nil
}

func buildSuppressionAudit(path, configHash string, cfg policy.Config, rep *report.Report, now time.Time) suppressionAudit {
	audit := suppressionAudit{
		ConfigPath:  path,
		ConfigHash:  configHash,
		GeneratedAt: now.UTC(),
		Warnings:    append([]report.Warning{}, rep.Warnings...),
	}
	statuses := suppressionStatuses(cfg.Suppressions, cfg.SuppressionPolicy, now)
	matched := matchedSuppressionKeys(rep.SuppressedFindings)
	for _, status := range statuses {
		if status.PolicyViolating {
			audit.PolicyViolations = append(audit.PolicyViolations, status)
		}
		switch status.Status {
		case "invalid":
			audit.Invalid = append(audit.Invalid, status)
		case "expired":
			audit.Expired = append(audit.Expired, status)
		case "expiring_soon":
			audit.ExpiringSoon = append(audit.ExpiringSoon, status)
			audit.Active = append(audit.Active, status)
			if !matched[suppressionKey(status)] {
				audit.Unmatched = append(audit.Unmatched, status)
			}
		default:
			audit.Active = append(audit.Active, status)
			if !matched[suppressionKey(status)] {
				audit.Unmatched = append(audit.Unmatched, status)
			}
		}
	}
	sortSuppressionStatuses(audit.Active)
	sortSuppressionStatuses(audit.Expired)
	sortSuppressionStatuses(audit.ExpiringSoon)
	sortSuppressionStatuses(audit.Invalid)
	sortSuppressionStatuses(audit.PolicyViolations)
	sortSuppressionStatuses(audit.Unmatched)
	return audit
}

func matchedSuppressionKeys(items []report.SuppressedFinding) map[string]bool {
	out := make(map[string]bool, len(items))
	for _, item := range items {
		out[suppressionStatusKey(item.FindingID, item.Suppression.Package, item.Suppression.Category, item.Suppression.Reason, item.Suppression.Owner, item.Suppression.Expires, item.Suppression.Created)] = true
	}
	return out
}

func suppressionKey(status suppressionStatus) string {
	return suppressionStatusKey(status.ID, status.Package, status.Category, status.Reason, status.Owner, status.Expires, status.Created)
}

func suppressionStatusKey(id, pkg, category, reason, owner, expires, created string) string {
	return strings.Join([]string{id, pkg, strings.ToUpper(category), reason, owner, expires, created}, "\x1f")
}

func sortSuppressionStatuses(items []suppressionStatus) {
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Package != items[j].Package {
			return items[i].Package < items[j].Package
		}
		if items[i].ID != items[j].ID {
			return items[i].ID < items[j].ID
		}
		return items[i].Index < items[j].Index
	})
}

func marshalSuppressionAudit(format string, audit suppressionAudit) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "json":
		data, err := json.MarshalIndent(audit, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("marshal suppression audit: %w", err)
		}
		return append(data, '\n'), nil
	case "markdown":
		return []byte(renderSuppressionAuditMarkdown(audit)), nil
	case "html":
		var b strings.Builder
		if err := suppressionAuditHTML.Execute(&b, audit); err != nil {
			return nil, fmt.Errorf("render suppression audit HTML: %w", err)
		}
		b.WriteByte('\n')
		return []byte(b.String()), nil
	default:
		return nil, fmt.Errorf("unsupported format %q: expected json, markdown, or html", format)
	}
}

func renderSuppressionAuditMarkdown(audit suppressionAudit) string {
	var b strings.Builder
	fmt.Fprintln(&b, "# Faultline Suppression Audit")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "- Config: `%s`\n", audit.ConfigPath)
	fmt.Fprintf(&b, "- Config hash: `%s`\n", audit.ConfigHash)
	fmt.Fprintf(&b, "- Active: `%d`\n", len(audit.Active))
	fmt.Fprintf(&b, "- Expired: `%d`\n", len(audit.Expired))
	fmt.Fprintf(&b, "- Expiring within 30 days: `%d`\n", len(audit.ExpiringSoon))
	fmt.Fprintf(&b, "- Invalid or incomplete: `%d`\n", len(audit.Invalid))
	fmt.Fprintf(&b, "- Policy-violating: `%d`\n", len(audit.PolicyViolations))
	fmt.Fprintf(&b, "- Unmatched current findings: `%d`\n", len(audit.Unmatched))
	renderSuppressionSection(&b, "Active Suppressions", audit.Active)
	renderSuppressionSection(&b, "Expired Suppressions", audit.Expired)
	renderSuppressionSection(&b, "Expiring Within 30 Days", audit.ExpiringSoon)
	renderSuppressionSection(&b, "Invalid Suppressions", audit.Invalid)
	renderSuppressionSection(&b, "Policy-Violating Suppressions", audit.PolicyViolations)
	renderSuppressionSection(&b, "Unmatched Suppressions", audit.Unmatched)
	return b.String()
}

func renderSuppressionSection(b *strings.Builder, title string, items []suppressionStatus) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(b, "\n## %s\n", title)
	for _, item := range items {
		fmt.Fprintf(b, "- `%s` for `%s`, owner `%s`, created `%s`, expires `%s`, status `%s`", item.ID, item.Package, item.Owner, item.Created, item.Expires, item.Status)
		if len(item.Warnings) > 0 {
			fmt.Fprintf(b, " (%s)", strings.Join(item.Warnings, "; "))
		}
		fmt.Fprintln(b)
	}
}

var suppressionAuditHTML = template.Must(template.New("suppression-audit").Funcs(template.FuncMap{"dict": func(values ...any) map[string]any {
	out := make(map[string]any, len(values)/2)
	for i := 0; i+1 < len(values); i += 2 {
		key, _ := values[i].(string)
		out[key] = values[i+1]
	}
	return out
}, "join": strings.Join}).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Faultline Suppression Audit</title>
<style>body{font-family:system-ui,sans-serif;margin:32px;color:#17202a}table{width:100%;border-collapse:collapse;margin:16px 0}th,td{border-bottom:1px solid #d7dde5;padding:8px;text-align:left}th{background:#eef2f6}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}</style></head>
<body><h1>Faultline Suppression Audit</h1><p>Config <span class="mono">{{.ConfigPath}}</span> · hash <span class="mono">{{.ConfigHash}}</span></p>
<p>Active {{len .Active}} · Expired {{len .Expired}} · Expiring soon {{len .ExpiringSoon}} · Invalid {{len .Invalid}} · Policy-violating {{len .PolicyViolations}} · Unmatched {{len .Unmatched}}</p>
{{template "table" dict "Title" "Active Suppressions" "Items" .Active}}
{{template "table" dict "Title" "Expired Suppressions" "Items" .Expired}}
{{template "table" dict "Title" "Expiring Within 30 Days" "Items" .ExpiringSoon}}
{{template "table" dict "Title" "Invalid Suppressions" "Items" .Invalid}}
{{template "table" dict "Title" "Policy-Violating Suppressions" "Items" .PolicyViolations}}
{{template "table" dict "Title" "Unmatched Suppressions" "Items" .Unmatched}}
</body></html>
{{define "table"}}{{if .Items}}<h2>{{.Title}}</h2><table><thead><tr><th>ID</th><th>Package</th><th>Owner</th><th>Created</th><th>Expires</th><th>Status</th><th>Warnings</th></tr></thead><tbody>{{range .Items}}<tr><td>{{.ID}}</td><td class="mono">{{.Package}}</td><td>{{.Owner}}</td><td>{{.Created}}</td><td>{{.Expires}}</td><td>{{.Status}}</td><td>{{join .Warnings "; "}}</td></tr>{{end}}</tbody></table>{{end}}{{end}}`))
