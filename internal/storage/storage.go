package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/faultline-go/faultline/internal/report"
	_ "modernc.org/sqlite"
)

const DefaultRelPath = ".faultline/faultline.db"
const DriverName = "modernc.org/sqlite"
const schemaVersion = 2

type HistoryMatchMethod string

const (
	HistoryMatchFingerprint HistoryMatchMethod = "FINGERPRINT"
	HistoryMatchPath        HistoryMatchMethod = "PATH"
	HistoryMatchNone        HistoryMatchMethod = "NONE"
)

type RepoIdentity struct {
	Fingerprint string
	DisplayName string
	RootPath    string
}

type Store interface {
	SaveReport(ctx context.Context, rep *report.Report) (int64, error)
	PreviousPackageScores(ctx context.Context, identity RepoIdentity) (map[string]float64, HistoryMatchMethod, error)
	PreviousFindingKeys(ctx context.Context, identity RepoIdentity) (map[string]bool, HistoryMatchMethod, error)
	ListScans(ctx context.Context) ([]ScanRecord, error)
	ShowScan(ctx context.Context, id int64) (*ScanDetail, error)
	PruneBefore(ctx context.Context, before time.Time) (int64, error)
	Doctor(ctx context.Context) (*DoctorReport, error)
	Close() error
}

type SQLiteStore struct {
	db   *sql.DB
	path string
}

type ScanRecord struct {
	ID              int64
	Timestamp       time.Time
	RepoRoot        string
	RepoFingerprint string
	RepoDisplayName string
	Version         string
	ConfigHash      string
	PackageCount    int
	FindingCount    int
}

type DoctorReport struct {
	DBPath                  string
	SchemaVersion           int
	ScanCount               int
	FingerprintCount        int
	MissingFingerprintCount int
	LegacyRowsCount         int
	MigrationStatus         string
	DriverName              string
}

type ScanDetail struct {
	Scan     ScanRecord
	Packages []PackageRecord
	Findings []FindingRecord
	Warnings []report.Warning
}

type PackageRecord struct {
	ImportPath string
	RiskScore  float64
	Trend      string
	RiskDelta  *float64
}

type FindingRecord struct {
	PackageImportPath string
	ID                string
	Category          string
	Severity          string
	Suppressed        bool
	Title             string
}

func DefaultPath(repoRoot string) string {
	return filepath.Join(repoRoot, DefaultRelPath)
}

func Open(path string) (*SQLiteStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("create history directory: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite history: %w", err)
	}
	store := &SQLiteStore{db: db, path: path}
	if err := store.init(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *SQLiteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *SQLiteStore) init(ctx context.Context) error {
	stmts := []string{
		`PRAGMA foreign_keys = ON`,
		`CREATE TABLE IF NOT EXISTS scans (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp TEXT NOT NULL,
			repo_root TEXT NOT NULL,
			repo_root_path TEXT,
			repo_fingerprint TEXT,
			repo_display_name TEXT,
			faultline_version TEXT NOT NULL,
			config_hash TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_scans_repo_time ON scans(repo_root, timestamp, id)`,
		`CREATE TABLE IF NOT EXISTS package_metrics (
			scan_id INTEGER NOT NULL,
			import_path TEXT NOT NULL,
			dir TEXT NOT NULL,
			risk_score REAL NOT NULL,
			previous_risk_score REAL,
			risk_delta REAL,
			trend TEXT,
			churn_score REAL NOT NULL,
			coverage_gap_score REAL NOT NULL,
			complexity_score REAL NOT NULL,
			ownership_entropy_score REAL NOT NULL,
			dependency_centrality_score REAL NOT NULL,
			coverage_pct REAL,
			churn_30d INTEGER NOT NULL,
			churn_90d INTEGER NOT NULL,
			author_count_90d INTEGER NOT NULL,
			owner TEXT,
			reverse_import_count INTEGER NOT NULL,
			PRIMARY KEY(scan_id, import_path),
			FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS findings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_id INTEGER NOT NULL,
			package_import_path TEXT NOT NULL,
			finding_id TEXT NOT NULL,
			category TEXT NOT NULL,
			severity TEXT NOT NULL,
			title TEXT NOT NULL,
			suppressed INTEGER NOT NULL,
			FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS finding_evidence (
			finding_row_id INTEGER NOT NULL,
			key TEXT NOT NULL,
			value TEXT NOT NULL,
			source TEXT NOT NULL,
			FOREIGN KEY(finding_row_id) REFERENCES findings(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS warnings (
			scan_id INTEGER NOT NULL,
			source TEXT NOT NULL,
			message TEXT NOT NULL,
			FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS suppressions (
			scan_id INTEGER NOT NULL,
			package_import_path TEXT NOT NULL,
			finding_id TEXT NOT NULL,
			category TEXT NOT NULL,
			severity TEXT NOT NULL,
			reason TEXT NOT NULL,
			owner TEXT NOT NULL,
			expires TEXT NOT NULL,
			package_pattern TEXT NOT NULL,
			FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS schema_meta (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("initialize history database: %w", err)
		}
	}
	if err := s.migrate(ctx); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_scans_fingerprint_time ON scans(repo_fingerprint, timestamp, id)`); err != nil {
		return fmt.Errorf("create fingerprint index: %w", err)
	}
	return nil
}

func (s *SQLiteStore) migrate(ctx context.Context) error {
	additions := map[string]string{
		"repo_root_path":    "TEXT",
		"repo_fingerprint":  "TEXT",
		"repo_display_name": "TEXT",
	}
	columns, err := s.tableColumns(ctx, "scans")
	if err != nil {
		return fmt.Errorf("inspect scans schema: %w", err)
	}
	for name, typ := range additions {
		if columns[name] {
			continue
		}
		if _, err := s.db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE scans ADD COLUMN %s %s", name, typ)); err != nil {
			return fmt.Errorf("migrate scans add %s: %w", name, err)
		}
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE scans SET repo_root_path = repo_root WHERE repo_root_path IS NULL OR repo_root_path = ''`); err != nil {
		return fmt.Errorf("backfill repo_root_path: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `INSERT OR REPLACE INTO schema_meta(key, value) VALUES('schema_version', ?)`, fmt.Sprintf("%d", schemaVersion)); err != nil {
		return fmt.Errorf("write schema version: %w", err)
	}
	return nil
}

func (s *SQLiteStore) tableColumns(ctx context.Context, table string) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]bool)
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull int
		var defaultValue any
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			return nil, err
		}
		out[name] = true
	}
	return out, rows.Err()
}

func (s *SQLiteStore) SaveReport(ctx context.Context, rep *report.Report) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin history transaction: %w", err)
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx, `INSERT INTO scans(timestamp, repo_root, repo_root_path, repo_fingerprint, repo_display_name, faultline_version, config_hash) VALUES(?, ?, ?, ?, ?, ?, ?)`,
		rep.Meta.ScanTime.UTC().Format(time.RFC3339Nano), rep.Meta.RepoPath, rep.Meta.RepoPath, rep.Meta.RepoFingerprint, rep.Meta.RepoDisplayName, rep.Meta.Version, rep.Meta.ConfigHash)
	if err != nil {
		return 0, fmt.Errorf("insert scan: %w", err)
	}
	scanID, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("get scan id: %w", err)
	}

	for _, pkg := range rep.Packages {
		var coverage any
		if pkg.CoveragePct != nil {
			coverage = *pkg.CoveragePct
		}
		var previous any
		if pkg.PreviousRiskScore != nil {
			previous = *pkg.PreviousRiskScore
		}
		var delta any
		if pkg.RiskDelta != nil {
			delta = *pkg.RiskDelta
		}
		var owner any
		if pkg.DominantOwner != nil {
			owner = *pkg.DominantOwner
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO package_metrics(
			scan_id, import_path, dir, risk_score, previous_risk_score, risk_delta, trend,
			churn_score, coverage_gap_score, complexity_score, ownership_entropy_score, dependency_centrality_score,
			coverage_pct, churn_30d, churn_90d, author_count_90d, owner, reverse_import_count
		) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			scanID, pkg.ImportPath, pkg.Dir, pkg.RiskScore, previous, delta, pkg.Trend,
			pkg.ScoreBreakdown.ChurnScore, pkg.ScoreBreakdown.CoverageGapScore, pkg.ScoreBreakdown.ComplexityScore,
			pkg.ScoreBreakdown.OwnershipEntropyScore, pkg.ScoreBreakdown.DependencyCentralityScore,
			coverage, pkg.Churn30d, pkg.Churn90d, pkg.AuthorCount90d, owner, pkg.ReverseImportCount); err != nil {
			return 0, fmt.Errorf("insert package metric %s: %w", pkg.ImportPath, err)
		}
		for _, finding := range pkg.Findings {
			res, err := tx.ExecContext(ctx, `INSERT INTO findings(scan_id, package_import_path, finding_id, category, severity, title, suppressed) VALUES(?, ?, ?, ?, ?, ?, ?)`,
				scanID, pkg.ImportPath, finding.ID, string(finding.Category), string(finding.Severity), finding.Title, boolInt(finding.Suppressed))
			if err != nil {
				return 0, fmt.Errorf("insert finding %s/%s: %w", pkg.ImportPath, finding.ID, err)
			}
			findingRowID, err := res.LastInsertId()
			if err != nil {
				return 0, fmt.Errorf("get finding row id: %w", err)
			}
			for _, ev := range finding.Evidence {
				if _, err := tx.ExecContext(ctx, `INSERT INTO finding_evidence(finding_row_id, key, value, source) VALUES(?, ?, ?, ?)`,
					findingRowID, ev.Key, ev.Value, ev.Source); err != nil {
					return 0, fmt.Errorf("insert finding evidence: %w", err)
				}
			}
		}
	}
	for _, warning := range rep.Warnings {
		if _, err := tx.ExecContext(ctx, `INSERT INTO warnings(scan_id, source, message) VALUES(?, ?, ?)`, scanID, warning.Source, warning.Message); err != nil {
			return 0, fmt.Errorf("insert warning: %w", err)
		}
	}
	for _, suppressed := range rep.SuppressedFindings {
		if _, err := tx.ExecContext(ctx, `INSERT INTO suppressions(scan_id, package_import_path, finding_id, category, severity, reason, owner, expires, package_pattern) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			scanID, suppressed.PackageImportPath, suppressed.FindingID, string(suppressed.Category), string(suppressed.Severity),
			suppressed.Suppression.Reason, suppressed.Suppression.Owner, suppressed.Suppression.Expires, suppressed.Suppression.Package); err != nil {
			return 0, fmt.Errorf("insert suppression: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit history transaction: %w", err)
	}
	return scanID, nil
}

func (s *SQLiteStore) PreviousPackageScores(ctx context.Context, identity RepoIdentity) (map[string]float64, HistoryMatchMethod, error) {
	scanID, method, err := s.previousScanID(ctx, identity)
	if scanID == 0 && err == nil {
		return map[string]float64{}, HistoryMatchNone, nil
	}
	if err != nil {
		return nil, HistoryMatchNone, fmt.Errorf("query previous scan: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT import_path, risk_score FROM package_metrics WHERE scan_id = ?`, scanID)
	if err != nil {
		return nil, HistoryMatchNone, fmt.Errorf("query previous package scores: %w", err)
	}
	defer rows.Close()
	out := make(map[string]float64)
	for rows.Next() {
		var importPath string
		var risk float64
		if err := rows.Scan(&importPath, &risk); err != nil {
			return nil, HistoryMatchNone, fmt.Errorf("scan previous package score: %w", err)
		}
		out[importPath] = risk
	}
	return out, method, rows.Err()
}

func (s *SQLiteStore) PreviousFindingKeys(ctx context.Context, identity RepoIdentity) (map[string]bool, HistoryMatchMethod, error) {
	scanID, method, err := s.previousScanID(ctx, identity)
	if scanID == 0 && err == nil {
		return map[string]bool{}, HistoryMatchNone, nil
	}
	if err != nil {
		return nil, HistoryMatchNone, fmt.Errorf("query previous scan: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT
		f.id, f.package_import_path, f.finding_id, f.title,
		COALESCE(e.key, ''), COALESCE(e.value, ''), COALESCE(e.source, '')
		FROM findings f
		LEFT JOIN finding_evidence e ON e.finding_row_id = f.id
		WHERE f.scan_id = ? AND f.suppressed = 0
		ORDER BY f.package_import_path, f.finding_id, f.title, e.key, e.value, e.source`, scanID)
	if err != nil {
		return nil, HistoryMatchNone, fmt.Errorf("query previous findings: %w", err)
	}
	defer rows.Close()
	type findingParts struct {
		PackageImportPath string
		Finding           report.Finding
	}
	byRowID := make(map[int64]*findingParts)
	var rowOrder []int64
	for rows.Next() {
		var rowID int64
		var pkg, findingID, title, key, value, source string
		if err := rows.Scan(&rowID, &pkg, &findingID, &title, &key, &value, &source); err != nil {
			return nil, HistoryMatchNone, fmt.Errorf("scan previous finding: %w", err)
		}
		parts, ok := byRowID[rowID]
		if !ok {
			parts = &findingParts{
				PackageImportPath: pkg,
				Finding: report.Finding{
					ID:    findingID,
					Title: title,
				},
			}
			byRowID[rowID] = parts
			rowOrder = append(rowOrder, rowID)
		}
		if key != "" || value != "" || source != "" {
			parts.Finding.Evidence = append(parts.Finding.Evidence, report.Evidence{Key: key, Value: value, Source: source})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, HistoryMatchNone, err
	}
	out := make(map[string]bool, len(rowOrder))
	for _, rowID := range rowOrder {
		parts := byRowID[rowID]
		out[FindingKey(parts.PackageImportPath, parts.Finding)] = true
	}
	return out, method, nil
}

// FindingKey identifies a finding across scans without storing source text.
// Evidence is included so a new boundary or dependency issue with the same
// package and rule ID is treated as a new review finding.
func FindingKey(packageImportPath string, finding report.Finding) string {
	evidence := append([]report.Evidence{}, finding.Evidence...)
	sort.SliceStable(evidence, func(i, j int) bool {
		if evidence[i].Key != evidence[j].Key {
			return evidence[i].Key < evidence[j].Key
		}
		if evidence[i].Value != evidence[j].Value {
			return evidence[i].Value < evidence[j].Value
		}
		return evidence[i].Source < evidence[j].Source
	})
	parts := []string{packageImportPath, finding.ID, finding.Title}
	for _, ev := range evidence {
		parts = append(parts, ev.Key, ev.Value, ev.Source)
	}
	return strings.Join(parts, "\x1f")
}

func (s *SQLiteStore) previousScanID(ctx context.Context, identity RepoIdentity) (int64, HistoryMatchMethod, error) {
	var scanID int64
	method := HistoryMatchNone
	var err error
	if identity.Fingerprint != "" {
		err = s.db.QueryRowContext(ctx, `SELECT id FROM scans WHERE repo_fingerprint = ? ORDER BY timestamp DESC, id DESC LIMIT 1`, identity.Fingerprint).Scan(&scanID)
		if err == nil {
			return scanID, HistoryMatchFingerprint, nil
		}
	}
	if err != nil && err != sql.ErrNoRows {
		return 0, HistoryMatchNone, err
	}
	if identity.RootPath != "" {
		err = s.db.QueryRowContext(ctx, `SELECT id FROM scans WHERE repo_root = ? OR repo_root_path = ? ORDER BY timestamp DESC, id DESC LIMIT 1`, identity.RootPath, identity.RootPath).Scan(&scanID)
		if err == nil {
			method = HistoryMatchPath
		}
	}
	if err == sql.ErrNoRows {
		return 0, HistoryMatchNone, nil
	}
	return scanID, method, err
}

func (s *SQLiteStore) ListScans(ctx context.Context) ([]ScanRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT
		s.id, s.timestamp, COALESCE(s.repo_root_path, s.repo_root), COALESCE(s.repo_fingerprint, ''), COALESCE(s.repo_display_name, ''), s.faultline_version, s.config_hash,
		COUNT(DISTINCT pm.import_path), COUNT(f.id)
		FROM scans s
		LEFT JOIN package_metrics pm ON pm.scan_id = s.id
		LEFT JOIN findings f ON f.scan_id = s.id
		GROUP BY s.id
		ORDER BY s.timestamp DESC, s.id DESC`)
	if err != nil {
		return nil, fmt.Errorf("list scans: %w", err)
	}
	defer rows.Close()
	var out []ScanRecord
	for rows.Next() {
		rec, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) ShowScan(ctx context.Context, id int64) (*ScanDetail, error) {
	var row scanner = s.db.QueryRowContext(ctx, `SELECT
		s.id, s.timestamp, COALESCE(s.repo_root_path, s.repo_root), COALESCE(s.repo_fingerprint, ''), COALESCE(s.repo_display_name, ''), s.faultline_version, s.config_hash,
		(SELECT COUNT(*) FROM package_metrics WHERE scan_id = s.id),
		(SELECT COUNT(*) FROM findings WHERE scan_id = s.id)
		FROM scans s WHERE s.id = ?`, id)
	rec, err := scanRecord(row)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("scan %d not found", id)
	}
	if err != nil {
		return nil, err
	}
	detail := &ScanDetail{Scan: rec}

	pkgRows, err := s.db.QueryContext(ctx, `SELECT import_path, risk_score, trend, risk_delta FROM package_metrics WHERE scan_id = ? ORDER BY import_path`, id)
	if err != nil {
		return nil, fmt.Errorf("query scan packages: %w", err)
	}
	defer pkgRows.Close()
	for pkgRows.Next() {
		var rec PackageRecord
		var delta sql.NullFloat64
		if err := pkgRows.Scan(&rec.ImportPath, &rec.RiskScore, &rec.Trend, &delta); err != nil {
			return nil, fmt.Errorf("scan package record: %w", err)
		}
		if delta.Valid {
			rec.RiskDelta = &delta.Float64
		}
		detail.Packages = append(detail.Packages, rec)
	}

	findingRows, err := s.db.QueryContext(ctx, `SELECT package_import_path, finding_id, category, severity, suppressed, title FROM findings WHERE scan_id = ? ORDER BY package_import_path, finding_id, title`, id)
	if err != nil {
		return nil, fmt.Errorf("query scan findings: %w", err)
	}
	defer findingRows.Close()
	for findingRows.Next() {
		var rec FindingRecord
		var suppressed int
		if err := findingRows.Scan(&rec.PackageImportPath, &rec.ID, &rec.Category, &rec.Severity, &suppressed, &rec.Title); err != nil {
			return nil, fmt.Errorf("scan finding record: %w", err)
		}
		rec.Suppressed = suppressed != 0
		detail.Findings = append(detail.Findings, rec)
	}

	warningRows, err := s.db.QueryContext(ctx, `SELECT source, message FROM warnings WHERE scan_id = ? ORDER BY source, message`, id)
	if err != nil {
		return nil, fmt.Errorf("query scan warnings: %w", err)
	}
	defer warningRows.Close()
	for warningRows.Next() {
		var warning report.Warning
		if err := warningRows.Scan(&warning.Source, &warning.Message); err != nil {
			return nil, fmt.Errorf("scan warning record: %w", err)
		}
		detail.Warnings = append(detail.Warnings, warning)
	}
	return detail, nil
}

func (s *SQLiteStore) PruneBefore(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM scans WHERE timestamp < ?`, before.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, fmt.Errorf("prune scans: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("get prune count: %w", err)
	}
	return n, nil
}

func (s *SQLiteStore) Doctor(ctx context.Context) (*DoctorReport, error) {
	report := &DoctorReport{
		DBPath:          s.path,
		SchemaVersion:   schemaVersion,
		MigrationStatus: "ok",
		DriverName:      DriverName,
	}
	_ = s.db.QueryRowContext(ctx, `SELECT value FROM schema_meta WHERE key = 'schema_version'`).Scan(&report.SchemaVersion)
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM scans`).Scan(&report.ScanCount); err != nil {
		return nil, fmt.Errorf("doctor scan count: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT repo_fingerprint) FROM scans WHERE repo_fingerprint IS NOT NULL AND repo_fingerprint != ''`).Scan(&report.FingerprintCount); err != nil {
		return nil, fmt.Errorf("doctor fingerprint count: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM scans WHERE repo_fingerprint IS NULL OR repo_fingerprint = ''`).Scan(&report.MissingFingerprintCount); err != nil {
		return nil, fmt.Errorf("doctor missing fingerprint count: %w", err)
	}
	report.LegacyRowsCount = report.MissingFingerprintCount
	return report, nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanRecord(row scanner) (ScanRecord, error) {
	var rec ScanRecord
	var timestamp string
	if err := row.Scan(&rec.ID, &timestamp, &rec.RepoRoot, &rec.RepoFingerprint, &rec.RepoDisplayName, &rec.Version, &rec.ConfigHash, &rec.PackageCount, &rec.FindingCount); err != nil {
		return ScanRecord{}, err
	}
	t, err := time.Parse(time.RFC3339Nano, timestamp)
	if err != nil {
		return ScanRecord{}, fmt.Errorf("parse scan timestamp: %w", err)
	}
	rec.Timestamp = t
	return rec, nil
}

func ApplyTrends(rep *report.Report, previous map[string]float64) {
	for i := range rep.Packages {
		prev, ok := previous[rep.Packages[i].ImportPath]
		if !ok {
			rep.Packages[i].Trend = "NEW"
			continue
		}
		prev = round2(prev)
		current := round2(rep.Packages[i].RiskScore)
		delta := round2(current - prev)
		rep.Packages[i].PreviousRiskScore = &prev
		rep.Packages[i].RiskDelta = &delta
		switch {
		case delta > 0.01:
			rep.Packages[i].Trend = "WORSENED"
		case delta < -0.01:
			rep.Packages[i].Trend = "IMPROVED"
		default:
			rep.Packages[i].Trend = "UNCHANGED"
		}
	}
	sort.SliceStable(rep.Packages, func(i, j int) bool {
		return rep.Packages[i].ImportPath < rep.Packages[j].ImportPath
	})
}

func ComputeRepoIdentity(ctx context.Context, repoRoot string, packageImportPaths []string) RepoIdentity {
	repoRoot, _ = filepath.Abs(repoRoot)
	basename := filepath.Base(repoRoot)
	if remote := gitOutput(ctx, repoRoot, "config", "--get", "remote.origin.url"); remote != "" {
		remote = normalizeRemote(remote)
		branch := gitDefaultBranch(ctx, repoRoot)
		material := "git|" + remote + "|" + basename + "|" + branch
		return RepoIdentity{
			Fingerprint: hashBytes([]byte(material)),
			DisplayName: displayName(remote, basename),
			RootPath:    repoRoot,
		}
	}
	if modulePath := modulePath(repoRoot); modulePath != "" {
		material := "gomod|" + modulePath + "|" + basename
		return RepoIdentity{
			Fingerprint: hashBytes([]byte(material)),
			DisplayName: modulePath,
			RootPath:    repoRoot,
		}
	}
	roots := append([]string{}, packageImportPaths...)
	sort.Strings(roots)
	material := "packages|" + strings.Join(roots, ",") + "|" + basename
	return RepoIdentity{
		Fingerprint: hashBytes([]byte(material)),
		DisplayName: basename,
		RootPath:    repoRoot,
	}
}

func gitOutput(ctx context.Context, dir string, args ...string) string {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func gitDefaultBranch(ctx context.Context, dir string) string {
	if out := gitOutput(ctx, dir, "symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD"); out != "" {
		return strings.TrimPrefix(out, "origin/")
	}
	if out := gitOutput(ctx, dir, "branch", "--show-current"); out != "" {
		return out
	}
	return ""
}

func normalizeRemote(remote string) string {
	remote = strings.TrimSpace(remote)
	remote = strings.TrimSuffix(remote, ".git")
	remote = strings.TrimPrefix(remote, "ssh://")
	if strings.HasPrefix(remote, "git@") {
		remote = strings.TrimPrefix(remote, "git@")
		remote = strings.Replace(remote, ":", "/", 1)
	}
	for _, prefix := range []string{"https://", "http://"} {
		remote = strings.TrimPrefix(remote, prefix)
	}
	if at := strings.LastIndex(remote, "@"); at >= 0 && strings.Contains(remote[:at], ":") {
		remote = remote[at+1:]
	}
	remote = strings.TrimRight(remote, "/")
	parts := strings.SplitN(remote, "/", 2)
	if len(parts) == 2 {
		parts[0] = strings.ToLower(parts[0])
		remote = parts[0] + "/" + parts[1]
	}
	return remote
}

func displayName(remote, fallback string) string {
	parts := strings.Split(remote, "/")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "/" + parts[len(parts)-1]
	}
	return fallback
}

func modulePath(repoRoot string) string {
	data, err := os.ReadFile(filepath.Join(repoRoot, "go.mod"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module "))
		}
	}
	return ""
}

func ConfigHash(configPath string, config any) string {
	if configPath != "" {
		if data, err := os.ReadFile(configPath); err == nil {
			return hashBytes(data)
		}
	}
	data, _ := json.Marshal(config)
	return hashBytes(data)
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum)
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}
