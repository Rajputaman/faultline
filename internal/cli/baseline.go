package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	bl "github.com/faultline-go/faultline/internal/baseline"
	"github.com/faultline-go/faultline/internal/report"
	"github.com/spf13/cobra"
)

type baselineScanOptions struct {
	out                    string
	baseline               string
	format                 string
	failOnNew              string
	failOnRiskDelta        float64
	coverage               string
	config                 string
	tags                   string
	includeGenerated       bool
	excludes               []string
	strictConfig           bool
	allowConfigOutsideRepo bool
	verbose                bool
}

func newBaselineCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "baseline",
		Short: "Create and check local governance baselines",
	}
	cmd.AddCommand(newBaselineCreateCommand())
	cmd.AddCommand(newBaselineCheckCommand())
	return cmd
}

func newBaselineCreateCommand() *cobra.Command {
	var opts baselineScanOptions
	cmd := &cobra.Command{
		Use:   "create [patterns...]",
		Short: "Create a source-free baseline JSON file from the current scan",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				args = []string{"./..."}
			}
			return runBaselineCreate(cmd, opts, args)
		},
	}
	cmd.Flags().StringVar(&opts.out, "out", "faultline-baseline.json", "baseline output path")
	addBaselineScanFlags(cmd, &opts)
	return cmd
}

func newBaselineCheckCommand() *cobra.Command {
	var opts baselineScanOptions
	cmd := &cobra.Command{
		Use:   "check [patterns...]",
		Short: "Compare the current scan against a baseline",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				args = []string{"./..."}
			}
			return runBaselineCheck(cmd, opts, args)
		},
	}
	cmd.Flags().StringVar(&opts.baseline, "baseline", "", "baseline JSON path")
	cmd.Flags().StringVar(&opts.format, "format", "markdown", "check report format: json, html, or markdown")
	cmd.Flags().StringVar(&opts.out, "out", "", "optional check report output path; stdout when omitted")
	cmd.Flags().StringVar(&opts.failOnNew, "fail-on-new", "none", "exit non-zero on new findings at threshold: none, high, or critical")
	cmd.Flags().Float64Var(&opts.failOnRiskDelta, "fail-on-risk-delta", -1, "exit non-zero when a package risk score increases by more than this value; negative disables")
	addBaselineScanFlags(cmd, &opts)
	return cmd
}

func addBaselineScanFlags(cmd *cobra.Command, opts *baselineScanOptions) {
	cmd.Flags().StringVar(&opts.coverage, "coverage", "", "optional Go coverage profile")
	cmd.Flags().StringVar(&opts.config, "config", "", "optional faultline.yaml path")
	cmd.Flags().StringVar(&opts.tags, "tags", "", "comma-separated Go build tags")
	cmd.Flags().BoolVar(&opts.includeGenerated, "include-generated", false, "include generated code LOC in complexity scoring")
	cmd.Flags().StringArrayVar(&opts.excludes, "exclude", nil, "exclude package directories matching a repo-relative glob; repeatable")
	cmd.Flags().BoolVar(&opts.strictConfig, "strict-config", false, "fail on config validation warnings or errors")
	cmd.Flags().BoolVar(&opts.allowConfigOutsideRepo, "allow-config-outside-repo", false, "allow rule pack paths outside the repository root")
	cmd.Flags().BoolVar(&opts.verbose, "verbose", false, "print scan progress")
}

func runBaselineCreate(cmd *cobra.Command, opts baselineScanOptions, patterns []string) error {
	if opts.out == "" {
		return ExitError{Code: 2, Err: fmt.Errorf("--out is required")}
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
	baseline := bl.Create(rep)
	data, err := bl.MarshalBaseline(baseline)
	if err != nil {
		return ExitError{Code: 2, Err: err}
	}
	if err := writeOutputFile(opts.out, data); err != nil {
		return ExitError{Code: 2, Err: err}
	}
	if opts.verbose {
		fmt.Fprintf(cmd.ErrOrStderr(), "wrote baseline to %s\n", opts.out)
	}
	return nil
}

func runBaselineCheck(cmd *cobra.Command, opts baselineScanOptions, patterns []string) error {
	if opts.baseline == "" {
		return ExitError{Code: 2, Err: fmt.Errorf("--baseline is required")}
	}
	format := strings.ToLower(strings.TrimSpace(opts.format))
	if format != "json" && format != "html" && format != "markdown" {
		return ExitError{Code: 2, Err: fmt.Errorf("unsupported format %q: expected json, html, or markdown", opts.format)}
	}
	failOnNew, err := parseFailOn(opts.failOnNew)
	if err != nil {
		return ExitError{Code: 2, Err: err}
	}
	baseline, err := readBaseline(opts.baseline)
	if err != nil {
		return ExitError{Code: 2, Err: err}
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
	result := bl.Compare(baseline, rep, bl.CheckOptions{
		FailOnNew:       report.Severity(failOnNew),
		FailOnRiskDelta: opts.failOnRiskDelta,
	})
	data, err := marshalBaselineCheck(format, result)
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
	if result.Summary.Failed {
		return ExitError{Code: 1, Err: fmt.Errorf("baseline check failed configured gates")}
	}
	return nil
}

func readBaseline(path string) (bl.Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return bl.Baseline{}, fmt.Errorf("read baseline %s: %w", path, err)
	}
	var baseline bl.Baseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		return bl.Baseline{}, fmt.Errorf("parse baseline %s: %w", path, err)
	}
	if baseline.SchemaVersion != bl.SchemaVersion {
		return bl.Baseline{}, fmt.Errorf("baseline %s: unsupported schema version %d", path, baseline.SchemaVersion)
	}
	return baseline, nil
}

func marshalBaselineCheck(format string, result bl.CheckResult) ([]byte, error) {
	switch format {
	case "json":
		return bl.MarshalCheckJSON(result)
	case "html":
		return bl.RenderHTML(result)
	case "markdown":
		return []byte(bl.RenderMarkdown(result)), nil
	default:
		return nil, fmt.Errorf("unsupported baseline report format %q", format)
	}
}

func writeOutputFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create output directory: %w", err)
		}
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
