# Contributing to Faultline

Faultline is an open-source local analysis tool. Contributions should preserve
the local-first trust boundary: core scanning, local reports, SARIF, baselines,
history, config policy, and PR markdown review remain part of the public OSS
CLI.

## Development

```sh
go test ./...
go vet ./...
CGO_ENABLED=0 go build ./cmd/faultline
```

Run formatting before sending a change:

```sh
make fmt
```

## Developer Certificate of Origin

Faultline uses Developer Certificate of Origin sign-off for inbound
contributions. Add a sign-off line to each commit:

```sh
git commit -s
```

The sign-off certifies that you have the right to submit the contribution under
the project's Apache 2.0 license. The exact certification text is the standard
DCO 1.1 at https://developercertificate.org/.

## Open-Core Boundary

Do not add hosted-only product code, billing, SaaS control plane logic, SSO,
RBAC, Slack/Jira automation, or proprietary dashboard code to this repository.
Public integration points should be metadata-only and documented under
`pkg/export` or `docs/`.

Commercial integrations should consume public releases, Go module APIs, JSON
exports, or separately versioned API contracts.
