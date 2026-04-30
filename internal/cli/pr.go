package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/faultline-go/faultline/internal/policy"
	"github.com/faultline-go/faultline/internal/prreview"
	"github.com/faultline-go/faultline/internal/report"
	"github.com/spf13/cobra"
)

type prOptions struct {
	base                   string
	head                   string
	repo                   string
	prNumber               string
	commentOut             string
	sarifOut               string
	post                   bool
	failOn                 string
	config                 string
	strictConfig           bool
	allowConfigOutsideRepo bool
	compareMode            string
}

func newPRCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pr",
		Short: "Pull request analysis workflows",
	}
	cmd.AddCommand(newPRReviewCommand())
	return cmd
}

func newPRReviewCommand() *cobra.Command {
	var opts prOptions
	cmd := &cobra.Command{
		Use:   "review",
		Short: "Generate a pull request risk review",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPRReview(cmd, opts)
		},
	}
	cmd.Flags().StringVar(&opts.base, "base", "", "base git ref (default: detected default branch or origin/main)")
	cmd.Flags().StringVar(&opts.head, "head", "", "head git ref (default: HEAD or GitHub SHA)")
	cmd.Flags().StringVar(&opts.repo, "repo", "", "GitHub repository owner/name")
	cmd.Flags().StringVar(&opts.prNumber, "pr", "", "GitHub pull request number")
	cmd.Flags().StringVar(&opts.commentOut, "comment-out", "", "write markdown review to a file")
	cmd.Flags().StringVar(&opts.sarifOut, "sarif-out", "", "write SARIF with new unsuppressed PR findings")
	cmd.Flags().BoolVar(&opts.post, "post", false, "post or update a GitHub PR comment when token and PR context are available")
	cmd.Flags().StringVar(&opts.failOn, "fail-on", "none", "exit non-zero on new findings at threshold: none, high, or critical")
	cmd.Flags().StringVar(&opts.config, "config", "", "optional faultline.yaml path")
	cmd.Flags().BoolVar(&opts.strictConfig, "strict-config", false, "fail on config validation warnings or errors")
	cmd.Flags().BoolVar(&opts.allowConfigOutsideRepo, "allow-config-outside-repo", false, "allow rule pack paths outside the repository root")
	cmd.Flags().StringVar(&opts.compareMode, "compare-mode", "auto", "comparison source: auto, worktree, or history")
	return cmd
}

func runPRReview(cmd *cobra.Command, opts prOptions) error {
	failOn, err := parseFailOn(opts.failOn)
	if err != nil {
		return ExitError{Code: 2, Err: err}
	}
	cfg := policy.DefaultConfig()
	var configWarnings []report.Warning
	var validation policy.ValidationReport
	repoRoot, err := os.Getwd()
	if err != nil {
		return ExitError{Code: 2, Err: fmt.Errorf("get working directory: %w", err)}
	}
	if opts.config != "" {
		loaded, resolvedValidation, err := policy.ResolveConfigWithValidation(opts.config, policy.ResolveOptions{
			RepoRoot:               repoRoot,
			AllowConfigOutsideRepo: opts.allowConfigOutsideRepo,
		})
		if err != nil {
			return ExitError{Code: 2, Err: err}
		}
		validation = resolvedValidation
		configWarnings = validationReportWarnings(validation)
		if opts.strictConfig && validation.HasWarnings() {
			return ExitError{Code: 2, Err: fmt.Errorf("strict config validation failed with %d warning(s)", validation.WarningCount)}
		}
		cfg = *loaded
	}
	review, body, err := prreview.Run(cmd.Context(), prreview.Options{
		RepoRoot:        repoRoot,
		Base:            opts.base,
		Head:            opts.head,
		HeadExplicit:    cmd.Flags().Changed("head"),
		Repo:            opts.repo,
		PRNumber:        opts.prNumber,
		CompareMode:     opts.compareMode,
		Config:          cfg,
		ConfigPath:      opts.config,
		ConfigWarnings:  configWarnings,
		ConfigRulePacks: reportRulePacks(validation.RulePacks),
		ConfigHash:      validation.ConfigHash,
		StrictConfig:    opts.strictConfig,
		CommentOut:      opts.commentOut,
		SARIFOut:        opts.sarifOut,
		Post:            opts.post,
	})
	if err != nil {
		return ExitError{Code: 2, Err: err}
	}
	if opts.commentOut == "" {
		fmt.Fprint(cmd.OutOrStdout(), body)
	}
	if len(review.Warnings) > 0 {
		for _, warning := range review.Warnings {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s\n", warning)
		}
	}
	if failOn != "" && prreview.HasFailingNewFinding(review, report.Severity(failOn)) {
		return ExitError{Code: 1, Err: fmt.Errorf("PR review found new findings at or above %s", strings.ToLower(failOn))}
	}
	return nil
}
