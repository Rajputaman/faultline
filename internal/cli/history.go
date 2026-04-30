package cli

import (
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/faultline-go/faultline/internal/storage"
	"github.com/spf13/cobra"
)

func newHistoryCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "history",
		Short: "Inspect local Faultline scan history",
	}
	cmd.AddCommand(newHistoryListCommand())
	cmd.AddCommand(newHistoryShowCommand())
	cmd.AddCommand(newHistoryPruneCommand())
	cmd.AddCommand(newHistoryDoctorCommand())
	return cmd
}

func newHistoryListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List stored scans",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := openHistoryFromWD()
			if err != nil {
				return ExitError{Code: 2, Err: err}
			}
			defer store.Close()
			scans, err := store.ListScans(cmd.Context())
			if err != nil {
				return ExitError{Code: 2, Err: err}
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "SCAN ID\tTIMESTAMP\tPACKAGES\tFINDINGS\tFINGERPRINT\tREPO")
			for _, scan := range scans {
				fmt.Fprintf(w, "%d\t%s\t%d\t%d\t%s\t%s\n", scan.ID, scan.Timestamp.Format(time.RFC3339), scan.PackageCount, scan.FindingCount, shortFingerprint(scan.RepoFingerprint), scan.RepoRoot)
			}
			return w.Flush()
		},
	}
}

func newHistoryShowCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "show <scan-id>",
		Short: "Show stored scan details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return ExitError{Code: 2, Err: fmt.Errorf("invalid scan id %q: %w", args[0], err)}
			}
			store, err := openHistoryFromWD()
			if err != nil {
				return ExitError{Code: 2, Err: err}
			}
			defer store.Close()
			detail, err := store.ShowScan(cmd.Context(), id)
			if err != nil {
				return ExitError{Code: 2, Err: err}
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintf(w, "Scan ID:\t%d\nTimestamp:\t%s\nRepo:\t%s\nDisplay Name:\t%s\nFingerprint:\t%s\nVersion:\t%s\nConfig Hash:\t%s\nPackages:\t%d\nFindings:\t%d\n\n",
				detail.Scan.ID, detail.Scan.Timestamp.Format(time.RFC3339), detail.Scan.RepoRoot, detail.Scan.RepoDisplayName, detail.Scan.RepoFingerprint, detail.Scan.Version, detail.Scan.ConfigHash, detail.Scan.PackageCount, detail.Scan.FindingCount)
			fmt.Fprintln(w, "PACKAGE\tRISK\tDELTA\tTREND")
			for _, pkg := range detail.Packages {
				delta := "n/a"
				if pkg.RiskDelta != nil {
					delta = fmt.Sprintf("%.2f", *pkg.RiskDelta)
				}
				fmt.Fprintf(w, "%s\t%.2f\t%s\t%s\n", pkg.ImportPath, pkg.RiskScore, delta, pkg.Trend)
			}
			if len(detail.Findings) > 0 {
				fmt.Fprintln(w, "\nFINDING\tSEVERITY\tSUPPRESSED\tPACKAGE\tTITLE")
				for _, finding := range detail.Findings {
					fmt.Fprintf(w, "%s\t%s\t%v\t%s\t%s\n", finding.ID, finding.Severity, finding.Suppressed, finding.PackageImportPath, finding.Title)
				}
			}
			return w.Flush()
		},
	}
}

func newHistoryPruneCommand() *cobra.Command {
	var before string
	cmd := &cobra.Command{
		Use:   "prune --before <date>",
		Short: "Delete scans before a date",
		RunE: func(cmd *cobra.Command, args []string) error {
			if before == "" {
				return ExitError{Code: 2, Err: fmt.Errorf("--before is required")}
			}
			t, err := time.Parse("2006-01-02", before)
			if err != nil {
				return ExitError{Code: 2, Err: fmt.Errorf("parse --before date: %w", err)}
			}
			store, err := openHistoryFromWD()
			if err != nil {
				return ExitError{Code: 2, Err: err}
			}
			defer store.Close()
			n, err := store.PruneBefore(cmd.Context(), t)
			if err != nil {
				return ExitError{Code: 2, Err: err}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "pruned %d scans\n", n)
			return nil
		},
	}
	cmd.Flags().StringVar(&before, "before", "", "delete scans before YYYY-MM-DD")
	return cmd
}

func newHistoryDoctorCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Inspect local history database health",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := openHistoryFromWD()
			if err != nil {
				return ExitError{Code: 2, Err: err}
			}
			defer store.Close()
			rep, err := store.Doctor(cmd.Context())
			if err != nil {
				return ExitError{Code: 2, Err: err}
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintf(w, "DB Path:\t%s\n", rep.DBPath)
			fmt.Fprintf(w, "Schema Version:\t%d\n", rep.SchemaVersion)
			fmt.Fprintf(w, "Scan Count:\t%d\n", rep.ScanCount)
			fmt.Fprintf(w, "Repo Fingerprints:\t%d\n", rep.FingerprintCount)
			fmt.Fprintf(w, "Missing Fingerprints:\t%d\n", rep.MissingFingerprintCount)
			fmt.Fprintf(w, "Legacy Rows:\t%d\n", rep.LegacyRowsCount)
			fmt.Fprintf(w, "Migration Status:\t%s\n", rep.MigrationStatus)
			fmt.Fprintf(w, "Driver:\t%s\n", rep.DriverName)
			return w.Flush()
		},
	}
}

func openHistoryFromWD() (*storage.SQLiteStore, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("get working directory: %w", err)
	}
	return storage.Open(storage.DefaultPath(wd))
}

func shortFingerprint(value string) string {
	if len(value) <= 12 {
		return value
	}
	return value[:12]
}
