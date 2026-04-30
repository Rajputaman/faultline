package report

import (
	"fmt"
	"html/template"
	"os"
	"sort"
	"strings"
)

// WriteHTMLFile writes a self-contained static HTML report.
func WriteHTMLFile(path string, rep *Report) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create HTML report %s: %w", path, err)
	}
	defer f.Close()

	view := htmlView{
		Report:     rep,
		Top:        topRisk(rep.Packages, 10),
		Worsened:   topWorsened(rep.Packages, 10),
		BySeverity: groupFindings(rep.Packages),
	}
	if err := htmlTemplate.Execute(f, view); err != nil {
		return fmt.Errorf("render HTML report %s: %w", path, err)
	}
	return nil
}

type htmlView struct {
	Report     *Report
	Top        []PackageRisk
	Worsened   []PackageRisk
	BySeverity []severityGroup
}

type severityGroup struct {
	Severity Severity
	Groups   []findingGroup
}

type findingGroup struct {
	Category Category
	Items    []findingItem
}

type findingItem struct {
	Package PackageRisk
	Finding Finding
}

func topRisk(pkgs []PackageRisk, n int) []PackageRisk {
	out := append([]PackageRisk{}, pkgs...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].RiskScore == out[j].RiskScore {
			return out[i].ImportPath < out[j].ImportPath
		}
		return out[i].RiskScore > out[j].RiskScore
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func topWorsened(pkgs []PackageRisk, n int) []PackageRisk {
	out := make([]PackageRisk, 0, len(pkgs))
	for _, pkg := range pkgs {
		if pkg.RiskDelta != nil && *pkg.RiskDelta > 0 {
			out = append(out, pkg)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if *out[i].RiskDelta == *out[j].RiskDelta {
			return out[i].ImportPath < out[j].ImportPath
		}
		return *out[i].RiskDelta > *out[j].RiskDelta
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func groupFindings(pkgs []PackageRisk) []severityGroup {
	by := make(map[Severity]map[Category][]findingItem)
	for _, pkg := range pkgs {
		for _, finding := range pkg.Findings {
			if by[finding.Severity] == nil {
				by[finding.Severity] = make(map[Category][]findingItem)
			}
			by[finding.Severity][finding.Category] = append(by[finding.Severity][finding.Category], findingItem{Package: pkg, Finding: finding})
		}
	}
	severities := []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow}
	categories := []Category{CategoryOwnership, CategoryChurn, CategoryCoverage, CategoryComplexity, CategoryBoundary}
	categories = append(categories, CategoryDependency)
	out := make([]severityGroup, 0, len(by))
	for _, severity := range severities {
		catMap := by[severity]
		if len(catMap) == 0 {
			continue
		}
		sg := severityGroup{Severity: severity}
		for _, cat := range categories {
			items := catMap[cat]
			if len(items) == 0 {
				continue
			}
			sort.SliceStable(items, func(i, j int) bool {
				if items[i].Package.ImportPath == items[j].Package.ImportPath {
					return items[i].Finding.ID < items[j].Finding.ID
				}
				return items[i].Package.ImportPath < items[j].Package.ImportPath
			})
			sg.Groups = append(sg.Groups, findingGroup{Category: cat, Items: items})
		}
		out = append(out, sg)
	}
	return out
}

var htmlTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"pct": func(v *float64) string {
		if v == nil {
			return "n/a"
		}
		return fmt.Sprintf("%.1f%%", *v)
	},
	"owner": func(v *string) string {
		if v == nil {
			return "n/a"
		}
		return *v
	},
	"num": func(v *float64) string {
		if v == nil {
			return "n/a"
		}
		return fmt.Sprintf("%.2f", *v)
	},
	"delta": func(v *float64) string {
		if v == nil {
			return "n/a"
		}
		return fmt.Sprintf("%+.2f", *v)
	},
	"short": func(v string) string {
		if v == "" {
			return "n/a"
		}
		if len(v) <= 12 {
			return v
		}
		return v[:12]
	},
	"candidates": func(values []OwnerCandidate) string {
		if len(values) == 0 {
			return "n/a"
		}
		parts := make([]string, 0, len(values))
		for _, value := range values {
			parts = append(parts, value.Owner+" ("+value.Source+")")
		}
		return strings.Join(parts, ", ")
	},
}).Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Faultline Report</title>
<style>
:root{color-scheme:light;--bg:#f7f7f4;--fg:#1e2420;--muted:#68716b;--line:#d8ddd5;--panel:#fff;--accent:#2f6f73;--warn:#a14d1b;--bad:#9f2435}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
header{background:#142320;color:#fff;padding:28px 32px}
header h1{font-size:28px;margin:0 0 8px}
header p{margin:0;color:#cbd9d2}
main{max-width:1180px;margin:0 auto;padding:24px 20px 48px}
section{margin:0 0 28px}
h2{font-size:18px;margin:0 0 12px}
.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.metric{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px}
.metric strong{display:block;font-size:22px}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line)}
th,td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{font-size:12px;text-transform:uppercase;color:#48524c;background:#eef1ec}
th button{all:unset;cursor:pointer}
tr:last-child td{border-bottom:0}
.score{font-weight:700}
.score.high{color:var(--bad)}
.score.med{color:var(--warn)}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}
.warning{background:#fff7e8;border:1px solid #e4c37a;border-radius:8px;padding:10px;margin:8px 0}
.finding{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px;margin:8px 0}
.finding.suppressed{border-color:#b8c5d6;background:#f7f9fc}
.finding h3{font-size:15px;margin:0 0 6px}
.badge{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:1px 7px;font-size:11px;color:var(--muted)}
.muted{color:var(--muted)}
details{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:10px;margin:8px 0}
summary{cursor:pointer;font-weight:700}
</style>
</head>
<body>
<header>
<h1>Faultline Report</h1>
<p>Scan time: {{.Report.Meta.ScanTime.Format "2006-01-02 15:04:05 UTC"}} · Version: {{.Report.Meta.Version}} · Repository: {{if .Report.Meta.RepoDisplayName}}{{.Report.Meta.RepoDisplayName}}{{else}}{{.Report.Meta.RepoPath}}{{end}} · Fingerprint: {{short .Report.Meta.RepoFingerprint}} · Config hash: {{short .Report.Meta.ConfigHash}} · History match: {{.Report.Meta.HistoryMatchMethod}}</p>
{{if .Report.Meta.RulePacks}}<p>Rule packs: {{range .Report.Meta.RulePacks}}<span class="mono">{{.Path}}</span> {{end}}</p>{{end}}
</header>
<main>
<section class="summary">
<div class="metric"><span class="muted">Packages</span><strong>{{.Report.Summary.TotalPackages}}</strong></div>
<div class="metric"><span class="muted">High risk</span><strong>{{.Report.Summary.HighRiskCount}}</strong></div>
<div class="metric"><span class="muted">Warnings</span><strong>{{.Report.Summary.WarningCount}}</strong></div>
<div class="metric"><span class="muted">Suppressed</span><strong>{{.Report.Summary.SuppressedCount}}</strong></div>
<div class="metric"><span class="muted">Generated files</span><strong>{{printf "%.1f%%" .Report.Summary.GeneratedFilePct}}</strong></div>
<div class="metric"><span class="muted">Dependencies</span><strong>{{.Report.Summary.DependencyCount}}</strong></div>
</section>

{{if .Report.Warnings}}<section>
<h2>Warnings</h2>
{{range .Report.Warnings}}<div class="warning"><span class="mono">{{.Source}}</span> {{.Message}}</div>{{end}}
</section>{{end}}

{{if .Report.Modules}}<section>
<h2>Modules</h2>
{{if .Report.Meta.GoWorkPath}}<p>Workspace: <span class="mono">{{.Report.Meta.GoWorkPath}}</span></p>{{end}}
<table><thead><tr><th>Module</th><th>Root</th><th>go.mod</th><th>go.work</th><th>Scanned</th></tr></thead><tbody>
{{range .Report.Modules}}<tr><td class="mono">{{.ModulePath}}</td><td class="mono">{{.ModuleRoot}}</td><td class="mono">{{.GoModPath}}</td><td>{{.IncludedByGoWork}}</td><td>{{.Selected}}</td></tr>{{end}}
</tbody></table>
</section>{{end}}

{{if .Report.Dependencies}}<section>
<h2>Dependency Risk</h2>
{{if .Report.Govulncheck}}<div class="warning"><span class="mono">govulncheck</span> optional external tool mode {{.Report.Govulncheck.Mode}} · ran {{.Report.Govulncheck.Ran}}{{if .Report.Govulncheck.Error}} · {{.Report.Govulncheck.Error}}{{end}}</div>{{end}}
<table><thead><tr><th>Source Module</th><th>Dependency</th><th>Version</th><th>Kind</th><th>Replace</th><th>Used By</th><th>Findings</th></tr></thead><tbody>
{{range .Report.Dependencies}}<tr><td class="mono">{{.SourceModulePath}}</td><td class="mono">{{.ModulePath}}</td><td class="mono">{{.Version}}</td><td>{{if .Indirect}}indirect{{else}}direct{{end}}</td><td>{{if .Replace}}<span class="mono">{{.Replace.NewPath}} {{.Replace.NewVersion}}</span>{{if .LocalReplace}} <span class="badge">local</span>{{end}}{{if .CrossModuleReplace}} <span class="badge">cross-module</span>{{end}}{{else}}none{{end}}</td><td>{{.ImportingPackageCount}}</td><td>{{range .Findings}}<div><strong>{{.ID}}</strong> {{.Title}}</div>{{else}}none{{end}}</td></tr>{{end}}
</tbody></table>
{{if .Report.DependencyFindings}}<h3>Dependency Findings</h3>{{range .Report.DependencyFindings}}<div class="finding"><h3>{{.ID}} · {{.Title}}</h3><p>{{.Description}}</p><p><strong>Recommendation:</strong> {{.Recommendation}}</p>{{range .Evidence}}<div class="mono">{{.Key}}={{.Value}} ({{.Source}})</div>{{end}}</div>{{end}}{{end}}
</section>{{end}}

<section>
<h2>Top 10 Risky Packages</h2>
<table><thead><tr><th>Package</th><th>Risk</th><th>LOC</th><th>Coverage</th><th>Churn 30d</th><th>Reverse Imports</th></tr></thead><tbody>
{{range .Top}}<tr><td class="mono">{{.ImportPath}}</td><td class="score {{if ge .RiskScore 70.0}}high{{else if ge .RiskScore 40.0}}med{{end}}">{{printf "%.2f" .RiskScore}}</td><td>{{.LOC}}</td><td>{{pct .CoveragePct}}</td><td>{{.Churn30d}}</td><td>{{.ReverseImportCount}}</td></tr>{{end}}
</tbody></table>
</section>

{{if .Worsened}}<section>
<h2>Top Worsened Packages</h2>
<table><thead><tr><th>Package</th><th>Current Risk</th><th>Previous Risk</th><th>Delta</th><th>Trend</th></tr></thead><tbody>
{{range .Worsened}}<tr><td class="mono">{{.ImportPath}}</td><td>{{printf "%.2f" .RiskScore}}</td><td>{{num .PreviousRiskScore}}</td><td>{{delta .RiskDelta}}</td><td>{{.Trend}}</td></tr>{{end}}
</tbody></table>
</section>{{end}}

<section>
<h2>Package Risk Table</h2>
<table id="packages"><thead><tr><th><button data-sort="text">Module</button></th><th><button data-sort="text">Package</button></th><th><button data-sort="text">Dir</button></th><th><button data-sort="num">Risk</button></th><th><button data-sort="num">Delta</button></th><th><button data-sort="text">Trend</button></th><th><button data-sort="num">Complexity</button></th><th><button data-sort="num">Files</button></th><th><button data-sort="num">Generated</button></th><th><button data-sort="num">Imports</button></th><th><button data-sort="num">Reverse</button></th><th><button data-sort="text">Owner</button></th><th><button data-sort="text">Owner Source</button></th><th><button data-sort="num">Owner Confidence</button></th><th><button data-sort="text">Owner Candidates</button></th></tr></thead><tbody>
{{range .Report.Packages}}<tr><td class="mono">{{.ModulePath}}</td><td class="mono">{{.ImportPath}}</td><td class="mono">{{.Dir}}</td><td class="score {{if ge .RiskScore 70.0}}high{{else if ge .RiskScore 40.0}}med{{end}}">{{printf "%.2f" .RiskScore}}</td><td>{{delta .RiskDelta}}</td><td>{{.Trend}}</td><td>{{printf "%.2f" .ComplexityScore}}</td><td>{{.FileCount}}</td><td>{{.GeneratedFileCount}}</td><td>{{.ImportCount}}</td><td>{{.ReverseImportCount}}</td><td>{{owner .DominantOwner}}</td><td>{{.OwnerSource}}</td><td>{{printf "%.2f" .OwnershipConfidence}}</td><td class="mono">{{candidates .CandidateOwners}}</td></tr>{{end}}
</tbody></table>
</section>

<section>
<h2>Findings By Severity And Category</h2>
{{range .BySeverity}}
<h3>{{.Severity}}</h3>
{{range .Groups}}<h4>{{.Category}}</h4>
{{range .Items}}<div class="finding {{if .Finding.Suppressed}}suppressed{{end}}"><h3>{{.Finding.ID}} · {{.Finding.Title}} {{if .Finding.Suppressed}}<span class="badge">suppressed</span>{{end}} <span class="muted mono">{{.Package.ImportPath}}</span></h3><p>{{.Finding.Description}}</p><p><strong>Recommendation:</strong> {{.Finding.Recommendation}}</p>{{if .Finding.Suppression}}<p><strong>Suppression:</strong> {{.Finding.Suppression.Reason}} · {{.Finding.Suppression.Owner}} · expires {{.Finding.Suppression.Expires}}</p>{{end}}{{range .Finding.Evidence}}<div class="mono">{{.Key}}={{.Value}} ({{.Source}})</div>{{end}}</div>{{end}}{{end}}
{{else}}<p>No findings.</p>{{end}}
</section>

{{if .Report.SuppressedFindings}}<section>
<h2>Suppression Audit</h2>
<table><thead><tr><th>Package</th><th>Finding</th><th>Severity</th><th>Owner</th><th>Expires</th><th>Reason</th></tr></thead><tbody>
{{range .Report.SuppressedFindings}}<tr><td class="mono">{{.PackageImportPath}}</td><td>{{.FindingID}}</td><td>{{.Severity}}</td><td>{{.Suppression.Owner}}</td><td>{{.Suppression.Expires}}</td><td>{{.Suppression.Reason}}</td></tr>{{end}}
</tbody></table>
</section>{{end}}

<section>
<h2>Evidence Appendix</h2>
{{range .Report.Packages}}<details><summary>{{.ImportPath}} · risk {{printf "%.2f" .RiskScore}}</summary>{{range .Evidence}}<div class="mono">{{.Key}}={{.Value}} ({{.Source}})</div>{{end}}{{range .LoadErrors}}<div class="mono">load_error={{.}} (loader)</div>{{end}}</details>{{end}}
</section>

<section>
<h2>Limitations</h2>
<p>Faultline uses simple package-level and module-level heuristics. Scores are directional, not proof of defects. Git history may be unavailable in shallow clones, coverage is only considered when a profile is supplied, CODEOWNERS matching is approximate, and dependency risk is structural rather than vulnerability scanning.</p>
</section>
</main>
<script>
document.querySelectorAll("#packages th button").forEach(function(button, index) {
  button.addEventListener("click", function() {
    var tbody = document.querySelector("#packages tbody");
    var rows = Array.from(tbody.querySelectorAll("tr"));
    var numeric = button.dataset.sort === "num";
    var dir = button.dataset.dir === "asc" ? -1 : 1;
    document.querySelectorAll("#packages th button").forEach(function(b) { b.dataset.dir = ""; });
    button.dataset.dir = dir === 1 ? "asc" : "desc";
    rows.sort(function(a, b) {
      var av = a.children[index].textContent.trim();
      var bv = b.children[index].textContent.trim();
      if (numeric) {
        av = parseFloat(av) || 0;
        bv = parseFloat(bv) || 0;
        return (av - bv) * dir;
      }
      return av.localeCompare(bv) * dir;
    });
    rows.forEach(function(row) { tbody.appendChild(row); });
  });
});
</script>
</body>
</html>`))
