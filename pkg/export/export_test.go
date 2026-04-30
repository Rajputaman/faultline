package export

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFromReportJSONMetadataOnlySnapshot(t *testing.T) {
	input := []byte(`{
  "meta": {
    "version": "1.2.3",
    "commit": "abc123",
    "scan_time": "2026-04-30T16:00:00Z",
    "repo_path": "/private/source/acme",
    "repo_display_name": "acme",
    "repo_fingerprint": "repo-fp",
    "patterns": ["./..."],
    "config_hash": "cfg",
    "scan_id": 42
  },
  "warnings": [{"source": "coverage", "message": "coverage missing"}],
  "scoring_version": "risk.v1",
  "config_summary": {
    "boundary_rule_count": 1,
    "suppression_count": 1
  },
  "packages": [{
    "package_id": "pkg",
    "import_path": "example.com/acme/internal/payments",
    "dir": "internal/payments",
    "module_path": "example.com/acme",
    "risk_score": 80,
    "score_breakdown": {"churn_score": 10, "coverage_gap_score": 20, "complexity_score": 30, "ownership_entropy_score": 40, "dependency_centrality_score": 50},
    "churn_30d": 12,
    "churn_90d": 30,
    "author_count_90d": 3,
    "reverse_import_count": 4,
    "dominant_owner": "@payments",
    "owner_source": "CODEOWNERS",
    "findings": [{
      "id": "FL-BND-001",
      "category": "BOUNDARY",
      "severity": "HIGH",
      "title": "Boundary violation",
      "description": "imports denied package",
      "evidence": [{"key": "matched_import", "value": "example.com/acme/internal/storage", "source": "imports"}],
      "recommendation": "Invert dependency",
      "confidence": 0.9,
      "suppressed": true,
      "suppression": {"reason": "migration", "owner": "@platform", "expires": "2026-06-01", "package": "example.com/acme/internal/*"}
    }]
  }],
  "summary": {
    "total_packages": 1,
    "high_risk_count": 1,
    "warning_count": 1,
    "suppressed_count": 1,
    "total_findings": 1,
    "high_count": 0
  }
}`)

	snapshot, err := FromReportJSON(input)
	if err != nil {
		t.Fatalf("FromReportJSON() error = %v", err)
	}
	if snapshot.SchemaVersion != SnapshotSchemaVersion {
		t.Fatalf("schema version = %q", snapshot.SchemaVersion)
	}
	if snapshot.Source.RepoFingerprint != "repo-fp" {
		t.Fatalf("repo fingerprint = %q", snapshot.Source.RepoFingerprint)
	}
	if len(snapshot.Packages) != 1 {
		t.Fatalf("package count = %d", len(snapshot.Packages))
	}
	if snapshot.Packages[0].Owner != "@payments" {
		t.Fatalf("owner = %q", snapshot.Packages[0].Owner)
	}
	if len(snapshot.Findings) != 1 || !snapshot.Findings[0].Suppressed {
		t.Fatalf("finding snapshot = %+v", snapshot.Findings)
	}
	if len(snapshot.Suppressions) != 1 {
		t.Fatalf("suppression count = %d", len(snapshot.Suppressions))
	}

	data, err := MarshalJSON(snapshot)
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	if !json.Valid(data) {
		t.Fatal("snapshot JSON is invalid")
	}
	if strings.Contains(string(data), "/private/source") || strings.Contains(string(data), `"dir"`) {
		t.Fatalf("snapshot leaked source path or package dir: %s", string(data))
	}
}

func TestFromReportJSONDeterministic(t *testing.T) {
	input := []byte(`{
  "meta": {"version": "1.2.3", "scan_time": "2026-04-30T16:00:00Z"},
  "scoring_version": "risk.v1",
  "config_summary": {},
  "packages": [
    {"package_id": "b", "import_path": "example.com/b", "risk_score": 10, "score_breakdown": {}, "findings": [{"id": "FL-OWN-001", "category": "OWNERSHIP", "severity": "LOW", "title": "No owner", "evidence": [{"key":"owner","value":"unknown","source":"ownership"}]}]},
    {"package_id": "a", "import_path": "example.com/a", "risk_score": 20, "score_breakdown": {}, "findings": [{"id": "FL-COV-002", "category": "COVERAGE", "severity": "INFO", "title": "Missing coverage"}]}
  ],
  "summary": {"total_packages": 2, "total_findings": 2}
}`)
	left, err := FromReportJSON(input)
	if err != nil {
		t.Fatalf("FromReportJSON(left) error = %v", err)
	}
	right, err := FromReportJSON(input)
	if err != nil {
		t.Fatalf("FromReportJSON(right) error = %v", err)
	}
	leftJSON, err := MarshalJSON(left)
	if err != nil {
		t.Fatalf("MarshalJSON(left) error = %v", err)
	}
	rightJSON, err := MarshalJSON(right)
	if err != nil {
		t.Fatalf("MarshalJSON(right) error = %v", err)
	}
	if string(leftJSON) != string(rightJSON) {
		t.Fatalf("snapshot output is not deterministic\nleft=%s\nright=%s", leftJSON, rightJSON)
	}
	if left.Packages[0].ImportPath != "example.com/a" {
		t.Fatalf("packages not sorted: %+v", left.Packages)
	}
}
