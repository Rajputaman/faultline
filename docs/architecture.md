# Faultline Architecture

Faultline is a local-only CLI for package-level structural risk analysis of Go repositories.

## Components

- `cmd/faultline`: process entrypoint.
- `internal/cli`: Cobra command setup and flag parsing.
- `internal/analyzer`: package loading, import graph construction, filesystem metrics, and scan orchestration.
- `internal/git`: read-only git history helpers. It only invokes `git log` and `git rev-parse`.
- `internal/coverage`: Go coverage profile parser.
- `internal/ownership`: CODEOWNERS matching and ownership entropy helpers.
- `internal/policy`: YAML config parsing and future boundary policy evaluation.
- `internal/scoring`: deterministic score and finding rules.
- `internal/report`: shared report model plus JSON and HTML writers.
- `internal/storage`: future persistence interface for scan history.
- `internal/sarif`: future SARIF export seam.

## Boundaries

The analyzer produces raw package facts. Scoring turns those facts into evidence-backed scores and findings. Report writers serialize the model without re-computing domain logic. This keeps future outputs such as SARIF, SQLite history, GitHub App checks, or SaaS upload from changing scanner behavior.

Faultline does not execute repository code or send data over the network. Runtime network access is not required.
