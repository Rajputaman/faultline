# Faultline Open-Core Architecture

This document defines the intended split between the public Faultline OSS CLI
and the private commercial product. The goal is to keep the local scanner
excellent while monetizing organization-wide coordination, governance evidence, and
workflow automation.

## Product Principle

Faultline should not become crippleware. The public CLI must remain useful for a
single repository, a developer laptop, and a CI job without login, telemetry, or
source-code upload. Paid value starts when teams need cross-repository
coordination, approvals, portfolio analytics, centralized policy distribution,
identity integration, signed exports, and managed workflow automation.

Brand boundary: Faultline is the governance evidence layer for Go-heavy
engineering organizations carrying production risk. The OSS scanner provides the
local structural signals; Enterprise turns those source-free signals into
organization-wide evidence, workflows, and audit artifacts.

## Recommended Architecture

```text
                            public Apache 2.0
                    github.com/faultline-go/faultline
              +----------------------------------------+
              | faultline CLI                          |
              | scan, SARIF, PR markdown, baselines    |
              | config governance, local SQLite history|
              | local rule packs, reports, Docker      |
              +------------------+---------------------+
                                 |
                    metadata-only JSON snapshots
                    pkg/export schema / released CLI
                                 |
                                 v
                           signed upload bundle
                                 |
                            private API
       github.com/faultline-go/faultline-enterprise
              +------------------+---------------------+
              | ingestion, auth, billing, RBAC         |
              | dashboards, approvals, alerts, exports |
              | centralized policy pack management     |
              +------------------+---------------------+
                                 |
                          optional private repo
              github.com/faultline-go/faultline-proto
              +----------------------------------------+
              | OpenAPI/protobuf contracts             |
              | generated clients for backend/frontend |
              +----------------------------------------+
```

## Repository Split Recommendation

### 1. `github.com/faultline-go/faultline`

Public, Apache 2.0. Contains:

- CLI entrypoint and local commands
- scanner engine and risk scoring
- ownership, boundary, dependency, baseline, history, config, and PR review
  workflows
- HTML, JSON, SARIF, and markdown report generation
- local SQLite history
- local rule-pack resolution
- release packaging, Dockerfile, Homebrew config, docs, and examples
- `pkg/export`, the public metadata snapshot contract for paid integrations

### 2. `github.com/faultline-go/faultline-enterprise`

Private, proprietary. Contains:

- API service and ingestion backend
- organization, repo, team, policy, waiver, and alert workflows
- SSO/SAML/OIDC, RBAC, audit logs, billing, entitlements
- dashboards and analytics UI
- Slack/Jira/GitHub workflow automation
- centralized policy pack distribution
- self-hosted enterprise control plane packaging

The enterprise repo should consume OSS via released binaries, the Go module,
metadata exports, and API contracts. It must not import `internal/*` from the
OSS repository.

### 3. `github.com/faultline-go/faultline-proto`

Recommendation: defer until the commercial backend has at least two independent
consumers of the same API contract.

A separate private schema repo is worthwhile when:

- backend, frontend, worker, and customer-side upload clients need versioned
  generated clients
- API compatibility becomes a customer-facing contract
- self-hosted and hosted deployments must share the same contract

Until then, keep OpenAPI/protobuf definitions inside `faultline-enterprise`.
Prematurely splitting schemas adds versioning overhead and release coupling.

## Target Folder Structures

### OSS Repository

```text
cmd/faultline/              CLI bootstrap
internal/analyzer/          local package scan orchestration
internal/baseline/          local baseline create/check
internal/cli/               command definitions and exit behavior
internal/coverage/          Go coverage parser
internal/dependency/        go.mod/go.sum structural dependency signals
internal/git/               local git history signals
internal/module/            module and go.work discovery
internal/ownership/         CODEOWNERS, git authorship, aliases
internal/policy/            config, rule packs, boundaries, suppressions
internal/prreview/          local PR markdown and SARIF review model
internal/report/            HTML/JSON report model/renderers
internal/sarif/             SARIF adapter
internal/scoring/           explainable risk scoring
internal/storage/           local SQLite history
internal/version/           build metadata
pkg/export/                 public metadata-only export schema
docs/                       OSS and architecture docs
testdata/                   local fixtures
```

Long-term naming cleanup may move `internal/analyzer` to `internal/scan` and
split finding taxonomy into `internal/findings`, but that should be a
compatibility-preserving refactor after export contracts settle.

### Enterprise Repository

```text
cmd/faultline-api/          hosted API entrypoint
cmd/faultline-worker/       ingestion and workflow worker
cmd/faultline-admin/        private operational CLI
internal/api/               REST/gRPC handlers
internal/auth/              SSO, SAML/OIDC, sessions
internal/billing/           plans, subscriptions, entitlements
internal/ingest/            signed bundle ingestion and validation
internal/policyhub/         centralized policy pack management
internal/rbac/              org/team/repo authorization
internal/storage/           database access and migrations
internal/workflows/         Slack, Jira, GitHub automation
internal/audit/             audit log and export pipeline
web/                        dashboard UI
deploy/                     self-hosted and hosted deployment manifests
contracts/                  OpenAPI/protobuf until split is justified
```

## Feature Matrix

| Capability | OSS | Paid |
| --- | --- | --- |
| Local `faultline scan` | Yes | Uses OSS |
| HTML/JSON/SARIF reports | Yes | Aggregates outputs |
| PR markdown review | Yes | Adds managed comment automation |
| Local baselines | Yes | Org baseline governance |
| Local SQLite trends | Yes | Cross-repo trends |
| Config validate/explain/docs | Yes | Central policy distribution |
| Local rule packs | Yes | Versioned managed policy packs |
| Ownership/boundary/dependency findings | Yes | Org scorecards and workflows |
| Suppression audit | Yes | Approval workflows and dashboards |
| Multi-repo portfolio dashboard | No | Yes |
| SSO/SAML/RBAC | No | Yes |
| Slack/Jira automation | No | Yes |
| Billing and entitlements | No | Yes |
| Managed onboarding/support | No | Yes |

## Technical Contracts

### OSS to Enterprise Inputs

The paid product should accept:

- released `faultline` binaries
- full scan JSON reports for local debugging
- metadata-only snapshots from `pkg/export`
- SARIF files for GitHub code scanning
- signed upload bundles built from metadata snapshots

The stable upload boundary is the `faultline.snapshot.v1` schema in
`pkg/export`. It intentionally excludes source code, full file contents, and
absolute local source paths.

### Uploadable Metadata

Allowed by default:

- repository fingerprint and display name
- config hash and rule-pack hashes
- package import paths and module names
- risk scores and component scores
- finding IDs, severities, categories, and metadata evidence
- timestamps and trend deltas
- owner identifiers
- suppression state, owner, reason, and expiry
- dependency module paths and structural flags

Not allowed by default:

- source file contents
- code snippets
- arbitrary file paths outside normalized repo-relative evidence
- git patches
- secrets, environment variables, credentials, or tokens

### Signed Upload Bundle

```text
faultline scan ./... --format json --out report.json
metadata snapshot = pkg/export.FromReportJSON(report.json)
bundle = snapshot.json + manifest.json + signature
faultline cloud push bundle
API verifies signature, org/repo identity, schema version, and entitlement
ingestion stores metadata only
dashboards query aggregated metrics
```

The signing model should identify the CLI build and the authenticated uploader.
Do not imply cryptographic trust in the underlying repository contents; the
signature means "this metadata was produced and uploaded by this actor/tool."

## Security Model

The OSS repository is local-first. It must not require login, source upload, or
network access for local scanning. Commercial upload must be explicit,
authenticated, and metadata-only in v1.

Security boundaries:

- OSS code must not contain production SaaS secrets, tenant logic, billing
  gates, or private service endpoints as required dependencies.
- Enterprise services must treat OSS scan metadata as untrusted customer input.
- Upload APIs validate schema version, bundle size, org/repo authorization, and
  suppression metadata.
- Central policy packs are distributed as signed content and resolved locally by
  the CLI before enforcement.
- Self-hosted enterprise deployments should support customer-managed keys later,
  but encryption is not a v1 blocker.

## Release Model

OSS:

- public semantic-versioned releases
- CGO-disabled binaries for Linux, macOS, and Windows
- Docker and Homebrew distribution
- checksums, signatures, provenance, and SBOMs
- Apache 2.0 license, NOTICE, DCO, SECURITY.md, CONTRIBUTING.md

Enterprise:

- private versioned releases mapped to compatible OSS versions
- backend and frontend CI with image builds and migrations
- tenant-safe deploy pipeline
- self-hosted image bundles after hosted product proves the control plane
- no secrets shared with OSS workflows

Compatibility rule: enterprise ingestion should accept at least the latest two
minor OSS snapshot schemas.

## Migration Plan From Single Repository

1. Define and publish the open-core boundary in the public repository.
2. Add `pkg/export` as the metadata-only integration contract.
3. Move any future hosted, auth, billing, dashboard, or workflow automation code
   into `faultline-enterprise`, not into OSS.
4. Keep all current CLI commands and report formats intact.
5. Add optional `faultline cloud` commands only after the enterprise API exists;
   they must be additive and no-op without login.
6. Create enterprise ingestion around `pkg/export` snapshots before building a
   dashboard.
7. Defer a `faultline-proto` repo until API schemas are shared by multiple
   independent deployables.

## 90-Day Roadmap

### Days 0-30

- Land OSS boundary docs, Apache 2.0/NOTICE/DCO/security scaffolding.
- Stabilize `pkg/export` snapshot schema and add golden tests.
- Add `faultline export snapshot` if customer pilots need a CLI wrapper around
  `pkg/export`.
- Build private enterprise ingestion spike: API accepts snapshot JSON and stores
  repo/package/finding summaries.
- Define tenant, org, repo, user, team, and role data model.

### Days 31-60

- Build portfolio dashboard: repo list, high-risk packages, trends, suppressions
  expiring soon, and policy drift.
- Add `faultline cloud login` and `faultline cloud push` against a dev API.
- Add signed bundle manifest and replay protection.
- Add centralized policy pack read API, but keep local file rule packs in OSS.
- Pilot Slack/Jira workflow as backend automation, not scanner gating.

### Days 61-90

- Add SSO/OIDC, RBAC, audit events, and org-level suppression approval workflow.
- Add GitHub App or GitHub Actions integration only for orchestration, not for
  replacing local CLI behavior.
- Publish enterprise compatibility matrix against OSS versions.
- Prepare self-hosted architecture design after hosted ingestion and dashboard
  prove customer value.

## Risks and Failure Modes

- Crippling OSS would destroy developer trust and reduce adoption.
- Putting cloud entitlements inside scanner paths would make local CI brittle and
  create procurement resistance.
- Uploading source code by default would slow security reviews and narrow the
  market.
- Splitting schemas too early would add release friction without customer value.
- Leaving no public export contract would force enterprise code to couple to
  OSS internals.
- Central policy packs can become a hidden lock-in mechanism; keep local rule
  packs fully functional.
- Suppression approvals are monetizable, but suppressions must remain visible in
  OSS reports so waivers do not hide risk.

## What To Implement Immediately

- Public metadata snapshot export contract.
- Open-core boundary and contribution policy.
- Private ingestion API proof of concept using metadata snapshots.
- First dashboard slice: org/repo/package/finding summary and waiver expiry.

## What To Defer

- Separate schema repository.
- GitHub App as the primary ingestion path.
- Self-hosted control plane packaging.
- Advanced benchmarking and industry comparisons.
- Inline dashboard editing of repo-local suppressions.

## What Would Destroy Trust

- Moving SARIF, PR markdown, local baselines, local history, or config policies
  behind a login.
- Emitting scary local warnings that require paid signup to explain.
- Uploading source code by default.
- Secretly adding telemetry.
- Making OSS reports intentionally incomplete.

## Fastest Enterprise Willingness To Pay

The fastest paid value is not "better local scanning." It is reducing
coordination cost across teams:

- portfolio rollups across many repos
- suppression expiry and approval governance
- centralized policy pack rollout
- Slack/Jira/GitHub workflow automation
- owner scorecards and stale ownership detection
- audit exports for engineering leadership and compliance

## One Repo vs Multi-Repo

Keep OSS and enterprise in separate repositories. A single repo with private
modules increases accidental leakage risk, complicates contributor trust, and
makes public CI/release hygiene harder. The public repo should be clean enough
that a skeptical buyer or contributor can inspect it without wondering which
parts are crippled or hidden.

Use the optional schema repo later only when the API contract has multiple
independent consumers.
