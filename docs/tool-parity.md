# Static Analysis Tool Parity

Faultline is a structural risk scanner, not a replacement for the Go compiler,
language server, or every dedicated linter. This repository keeps parity with
the established Go quality toolchain by running the dedicated tools where their
semantics are stronger than Faultline's native model.

## Coverage Matrix

| Area | Parity Tooling | Faultline Native Coverage | Repository Gate |
| --- | --- | --- | --- |
| Dead code | `staticcheck`, `unused`, `deadcode` | None. Whole-program reachability is delegated. | `make quality` runs `golangci-lint` and `scripts/deadcode-check.sh`, which compares `deadcode -test ./cmd/faultline` against `docs/deadcode-baseline.txt`. |
| Unused dependencies | `go mod tidy` | `FL-DEP-004` flags direct dependencies not matched to loaded imports, with lower confidence. | `make tidy-check` fails if `go mod tidy` changes `go.mod` or `go.sum`. |
| Complexity | `gocyclo`, `cyclop`, `gocognit` | Package-level LOC, import count, file count, and generated-code scoring. | `.golangci.yml` enables all three function/package complexity linters. |
| Duplication | `dupl` | None. Token-level duplicate detection is delegated. | `.golangci.yml` enables `dupl`. |
| Architecture rules | `depguard`, `gomodguard` | `FL-BND-001` package import boundary rules from `faultline.yaml`; dependency governance findings from local `go.mod` and `go.sum`. | `.golangci.yml` enables `depguard`, `gomodguard`, and `gomoddirectives`; `faultline scan --strict-config` validates Faultline policy. |
| Meta-runner | `golangci-lint` | None. Faultline reports structural risk; `golangci-lint` runs dedicated static analyzers. | `make lint` runs `golangci-lint run`; CI runs the same gate on Linux. |
| IDE integration | `gopls` | Reports are CLI artifacts. | `.vscode/settings.json` enables `gopls` staticcheck and selected analyses, and points VS Code linting at `.golangci.yml`. |

## Local Workflow

Install the external tools once:

```sh
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.11.4
go install golang.org/x/tools/cmd/deadcode@latest
go install golang.org/x/tools/gopls@latest
```

Run the full local parity gate:

```sh
make quality
```

When `deadcode` output changes, review whether the functions should be removed
or whether they are intentional public API/planned hooks. Update
`docs/deadcode-baseline.txt` only after that review.

Run only the Faultline structural scanner against the repository:

```sh
go run ./cmd/faultline scan ./... --config faultline.example.yaml --strict-config --format json --out faultline-report.json
```

## Boundary Between Tools

Use dedicated analyzers for exact compiler/linter semantics:

- `deadcode` for call-graph reachability from executable entry points.
- `staticcheck` and `unused` for precise package-level unused code signals.
- `go mod tidy` for module graph hygiene.
- `gocyclo`, `cyclop`, and `gocognit` for function-level complexity.
- `dupl` for token-level duplicate detection.
- `depguard` and `gomodguard` for lint-time import and module allow/deny rules.
- `gopls` for editor diagnostics, refactors, and fast feedback while editing.

Use Faultline for risk prioritization across local, auditable repository signals:

- package risk scoring from churn, coverage gaps, complexity size signals,
  ownership entropy, and dependency centrality
- ownership and CODEOWNERS evidence
- architecture boundary findings configured in `faultline.yaml`
- local module dependency inventory and structural dependency findings
- baselines, suppressions, SARIF, PR summaries, and local history
