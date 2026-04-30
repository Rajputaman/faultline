package cli

import (
	"fmt"

	"github.com/faultline-go/faultline/internal/version"
	"github.com/spf13/cobra"
)

// NewRootCommand builds the top-level faultline command.
func NewRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "faultline",
		Short:         "Structural risk analysis for Go codebases",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version.String(),
	}
	cmd.AddCommand(newScanCommand())
	cmd.AddCommand(newBaselineCommand())
	cmd.AddCommand(newConfigCommand())
	cmd.AddCommand(newHistoryCommand())
	cmd.AddCommand(newPRCommand())
	cmd.AddCommand(newSuppressionsCommand())
	cmd.AddCommand(newVersionCommand())
	return cmd
}

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print build version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(cmd.OutOrStdout(), version.FullString())
		},
	}
}
