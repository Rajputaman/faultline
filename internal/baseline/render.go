package baseline

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"
)

func RenderMarkdown(result CheckResult) string {
	var b strings.Builder
	fmt.Fprintln(&b, "# Faultline Baseline Check")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "Summary: %d new findings, %d resolved findings, %d worsened packages, %d improved packages, %d suppressed findings.\n\n",
		result.Summary.NewFindings, result.Summary.ResolvedFindings, result.Summary.WorsenedPackages, result.Summary.ImprovedPackages, result.Summary.SuppressedFindings)
	if result.Summary.Failed {
		fmt.Fprintln(&b, "Status: failed configured baseline gates.")
	} else {
		fmt.Fprintln(&b, "Status: passed configured baseline gates.")
	}
	fmt.Fprintln(&b)
	if len(result.Warnings) > 0 {
		fmt.Fprintln(&b, "## Warnings")
		for _, warning := range result.Warnings {
			fmt.Fprintf(&b, "- %s: %s\n", warning.Source, warning.Message)
		}
		fmt.Fprintln(&b)
	}
	if len(result.NewFindings) > 0 {
		fmt.Fprintln(&b, "## New Findings")
		for _, finding := range result.NewFindings {
			fmt.Fprintf(&b, "- %s %s %s: %s\n", finding.Severity, finding.ID, finding.PackageImportPath, finding.Title)
		}
		fmt.Fprintln(&b)
	}
	if len(result.WorsenedPackages) > 0 {
		fmt.Fprintln(&b, "## Worsened Packages")
		fmt.Fprintln(&b, "| Package | Previous | Current | Delta |")
		fmt.Fprintln(&b, "|---|---:|---:|---:|")
		for _, pkg := range result.WorsenedPackages {
			fmt.Fprintf(&b, "| `%s` | %.2f | %.2f | +%.2f |\n", pkg.ImportPath, pkg.PreviousRiskScore, pkg.CurrentRiskScore, pkg.RiskDelta)
		}
		fmt.Fprintln(&b)
	}
	if len(result.ResolvedFindings) > 0 {
		fmt.Fprintln(&b, "## Resolved Findings")
		for _, finding := range result.ResolvedFindings {
			fmt.Fprintf(&b, "- %s %s %s: %s\n", finding.Severity, finding.ID, finding.PackageImportPath, finding.Title)
		}
		fmt.Fprintln(&b)
	}
	if len(result.ImprovedPackages) > 0 {
		fmt.Fprintln(&b, "## Improved Packages")
		fmt.Fprintln(&b, "| Package | Previous | Current | Delta |")
		fmt.Fprintln(&b, "|---|---:|---:|---:|")
		for _, pkg := range result.ImprovedPackages {
			fmt.Fprintf(&b, "| `%s` | %.2f | %.2f | %.2f |\n", pkg.ImportPath, pkg.PreviousRiskScore, pkg.CurrentRiskScore, pkg.RiskDelta)
		}
		fmt.Fprintln(&b)
	}
	if len(result.SuppressedFindings) > 0 {
		fmt.Fprintln(&b, "## Suppressed Findings")
		for _, finding := range result.SuppressedFindings {
			owner, expires, reason := "", "", ""
			if finding.Suppression != nil {
				owner = finding.Suppression.Owner
				expires = finding.Suppression.Expires
				reason = finding.Suppression.Reason
			}
			fmt.Fprintf(&b, "- %s %s %s: %s (owner: %s, expires: %s, reason: %s)\n", finding.Severity, finding.ID, finding.PackageImportPath, finding.Title, owner, expires, reason)
		}
		fmt.Fprintln(&b)
	}
	fmt.Fprintln(&b, "## Method")
	fmt.Fprintf(&b, "- Baseline created: %s\n", result.BaselineCreatedAt.Format("2006-01-02T15:04:05Z07:00"))
	fmt.Fprintf(&b, "- Baseline fingerprint: `%s`\n", result.BaselineFingerprint)
	fmt.Fprintf(&b, "- Current fingerprint: `%s`\n", result.CurrentFingerprint)
	fmt.Fprintf(&b, "- Fail on new: `%s`\n", result.Summary.FailOnNew)
	if result.Summary.FailOnRiskDelta >= 0 {
		fmt.Fprintf(&b, "- Fail on risk delta: `%.2f`\n", result.Summary.FailOnRiskDelta)
	} else {
		fmt.Fprintln(&b, "- Fail on risk delta: disabled")
	}
	return b.String()
}

func RenderHTML(result CheckResult) ([]byte, error) {
	var buf bytes.Buffer
	if err := htmlTemplate.Execute(&buf, result); err != nil {
		return nil, fmt.Errorf("render baseline HTML: %w", err)
	}
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}

var htmlTemplate = template.Must(template.New("baseline").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Faultline Baseline Check</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:0;color:#17202a;background:#f7f8fa}
main{max-width:1120px;margin:0 auto;padding:32px}
h1,h2{margin:0 0 12px}
.meta,.muted{color:#566573}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:20px 0}
.card{background:white;border:1px solid #d7dde5;border-radius:8px;padding:16px}
.num{font-size:28px;font-weight:700}.failed{color:#b42318}.passed{color:#027a48}
table{width:100%;border-collapse:collapse;background:white;border:1px solid #d7dde5;margin:12px 0 28px}
th,td{text-align:left;border-bottom:1px solid #e6eaf0;padding:8px;vertical-align:top}th{background:#eef2f6}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px}.finding{background:white;border:1px solid #d7dde5;border-radius:8px;padding:12px;margin:8px 0}
</style>
</head>
<body><main>
<h1>Faultline Baseline Check</h1>
<p class="meta">Checked {{.CheckedAt}} against baseline from {{.BaselineCreatedAt}}</p>
{{if .Summary.Failed}}<p class="failed"><strong>Status:</strong> failed configured baseline gates.</p>{{else}}<p class="passed"><strong>Status:</strong> passed configured baseline gates.</p>{{end}}
<section class="grid">
<div class="card"><div class="num">{{.Summary.NewFindings}}</div><div>New findings</div></div>
<div class="card"><div class="num">{{.Summary.ResolvedFindings}}</div><div>Resolved findings</div></div>
<div class="card"><div class="num">{{.Summary.WorsenedPackages}}</div><div>Worsened packages</div></div>
<div class="card"><div class="num">{{.Summary.SuppressedFindings}}</div><div>Suppressed findings</div></div>
</section>
{{if .Warnings}}<h2>Warnings</h2><ul>{{range .Warnings}}<li><span class="mono">{{.Source}}</span>: {{.Message}}</li>{{end}}</ul>{{end}}
{{if .NewFindings}}<h2>New Findings</h2>{{range .NewFindings}}<div class="finding"><strong>{{.Severity}} {{.ID}}</strong> <span class="mono">{{.PackageImportPath}}</span><br>{{.Title}}{{if .Location}}<br><span class="muted mono">{{.Location}}</span>{{end}}</div>{{end}}{{end}}
{{if .WorsenedPackages}}<h2>Worsened Packages</h2><table><thead><tr><th>Package</th><th>Previous</th><th>Current</th><th>Delta</th></tr></thead><tbody>{{range .WorsenedPackages}}<tr><td class="mono">{{.ImportPath}}</td><td>{{printf "%.2f" .PreviousRiskScore}}</td><td>{{printf "%.2f" .CurrentRiskScore}}</td><td>{{printf "+%.2f" .RiskDelta}}</td></tr>{{end}}</tbody></table>{{end}}
{{if .ResolvedFindings}}<h2>Resolved Findings</h2>{{range .ResolvedFindings}}<div class="finding"><strong>{{.Severity}} {{.ID}}</strong> <span class="mono">{{.PackageImportPath}}</span><br>{{.Title}}</div>{{end}}{{end}}
{{if .ImprovedPackages}}<h2>Improved Packages</h2><table><thead><tr><th>Package</th><th>Previous</th><th>Current</th><th>Delta</th></tr></thead><tbody>{{range .ImprovedPackages}}<tr><td class="mono">{{.ImportPath}}</td><td>{{printf "%.2f" .PreviousRiskScore}}</td><td>{{printf "%.2f" .CurrentRiskScore}}</td><td>{{printf "%.2f" .RiskDelta}}</td></tr>{{end}}</tbody></table>{{end}}
{{if .SuppressedFindings}}<h2>Suppressed Findings</h2><table><thead><tr><th>Finding</th><th>Package</th><th>Owner</th><th>Expires</th><th>Reason</th></tr></thead><tbody>{{range .SuppressedFindings}}<tr><td>{{.ID}}</td><td class="mono">{{.PackageImportPath}}</td><td>{{if .Suppression}}{{.Suppression.Owner}}{{end}}</td><td>{{if .Suppression}}{{.Suppression.Expires}}{{end}}</td><td>{{if .Suppression}}{{.Suppression.Reason}}{{end}}</td></tr>{{end}}</tbody></table>{{end}}
<h2>Method</h2>
<p>Baseline fingerprint <code>{{.BaselineFingerprint}}</code>; current fingerprint <code>{{.CurrentFingerprint}}</code>.</p>
<p>Fail on new: <code>{{.Summary.FailOnNew}}</code>; fail on risk delta: {{if ge .Summary.FailOnRiskDelta 0.0}}<code>{{printf "%.2f" .Summary.FailOnRiskDelta}}</code>{{else}}<code>disabled</code>{{end}}.</p>
</main></body></html>`))
