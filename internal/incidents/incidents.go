// Package incidents parses faultline.incidents.v1 input files and annotates
// scan packages with incident correlation signals.
package incidents

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/faultline-go/faultline/internal/report"
)

const SchemaVersion = "faultline.incidents.v1"

// Severity represents incident severity levels.
type Severity string

const (
	SeverityP1       Severity = "p1"
	SeverityP2       Severity = "p2"
	SeverityP3       Severity = "p3"
	SeverityP4       Severity = "p4"
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// Incident represents a single operational incident.
type Incident struct {
	ID               string     `json:"id"`
	Title            string     `json:"title"`
	Severity         Severity   `json:"severity"`
	StartedAt        time.Time  `json:"started_at"`
	ResolvedAt       *time.Time `json:"resolved_at,omitempty"`
	AffectedPackages []string   `json:"affected_packages"`
	URL              string     `json:"url,omitempty"`
}

// File is the top-level faultline.incidents.v1 document.
type File struct {
	Schema    string     `json:"schema"`
	Incidents []Incident `json:"incidents"`
}

// LoadFile reads and parses a faultline.incidents.v1 JSON file.
func LoadFile(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read incidents file %s: %w", path, err)
	}
	var f File
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse incidents file %s: %w", path, err)
	}
	if f.Schema != SchemaVersion {
		return nil, fmt.Errorf("unsupported incidents schema %q: expected %s", f.Schema, SchemaVersion)
	}
	return &f, nil
}

// PackageIndex builds a map from package import path to the incidents that
// affected it, filtered to incidents within the lookback window.
func PackageIndex(items []Incident, lookbackDays int) map[string][]report.SnapshotIncident {
	if lookbackDays <= 0 {
		lookbackDays = 90
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -lookbackDays)
	index := make(map[string][]report.SnapshotIncident)
	for _, inc := range ToSnapshotIncidents(items) {
		if inc.StartedAt.Before(cutoff) {
			continue
		}
		for _, pkg := range inc.AffectedPackages {
			index[pkg] = append(index[pkg], inc)
		}
	}
	return index
}

// ToSnapshotIncidents converts parsed incidents into the report model.
func ToSnapshotIncidents(items []Incident) []report.SnapshotIncident {
	out := make([]report.SnapshotIncident, 0, len(items))
	for _, inc := range items {
		out = append(out, report.SnapshotIncident{
			ID:               inc.ID,
			Title:            inc.Title,
			Severity:         string(inc.Severity),
			StartedAt:        inc.StartedAt,
			ResolvedAt:       inc.ResolvedAt,
			AffectedPackages: append([]string{}, inc.AffectedPackages...),
			URL:              inc.URL,
		})
	}
	return out
}
