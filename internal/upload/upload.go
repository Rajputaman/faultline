// Package upload sends a faultline snapshot to a Faultline Enterprise instance.
package upload

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Config holds the Enterprise connection parameters.
type Config struct {
	BaseURL string // e.g. https://api.gofaultline.dev
	Token   string // Faultline API token (flt_...)
	OrgID   string // Organization UUID
}

// IsConfigured returns true if all three fields are set.
func (c Config) IsConfigured() bool {
	return c.BaseURL != "" && c.Token != "" && c.OrgID != ""
}

// Result is the response from a successful snapshot upload.
type Result struct {
	SnapshotID   string `json:"snapshot_id"`
	RepoID       string `json:"repo_id"`
	PackageCount int    `json:"package_count"`
	FindingCount int    `json:"finding_count"`
	CreatedAt    string `json:"created_at"`
}

// UploadSnapshot posts snapshotJSON to the Enterprise ingest endpoint.
// snapshotJSON must be a valid faultline.snapshot.v1 JSON document.
func UploadSnapshot(ctx context.Context, cfg Config, snapshotJSON []byte) (Result, error) {
	if !cfg.IsConfigured() {
		return Result{}, fmt.Errorf("enterprise upload not configured: set --enterprise-url, --enterprise-token, and --enterprise-org-id")
	}

	base := strings.TrimRight(cfg.BaseURL, "/")
	url := fmt.Sprintf("%s/v1/orgs/%s/snapshots", base, cfg.OrgID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(snapshotJSON))
	if err != nil {
		return Result{}, fmt.Errorf("build upload request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("User-Agent", "faultline-cli/upload")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("upload snapshot: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusUnauthorized {
		return Result{}, fmt.Errorf("upload failed: invalid or expired API token (401)")
	}
	if resp.StatusCode == http.StatusForbidden {
		return Result{}, fmt.Errorf("upload failed: token lacks permission to upload snapshots (403)")
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return Result{}, fmt.Errorf("upload failed: rate limit exceeded - try again in 60 seconds (429)")
	}
	if resp.StatusCode == http.StatusRequestEntityTooLarge {
		return Result{}, fmt.Errorf("upload failed: snapshot too large for plan limits (413)")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Result{}, fmt.Errorf("upload failed: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var result Result
	if err := json.Unmarshal(body, &result); err != nil {
		// Upload succeeded but response parsing failed. Treat the upload as successful.
		return Result{}, nil
	}
	return result, nil
}
