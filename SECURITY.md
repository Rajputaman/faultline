# Security Policy

## Supported Versions

Security fixes are made on the default branch and included in the next release.
Until Faultline reaches a stable 1.0 release, only the latest released version is
supported.

## Reporting a Vulnerability

Please do not open a public issue for a suspected vulnerability. Email
security@faultline.dev with:

- affected version or commit
- reproduction steps
- impact assessment
- whether any private repository data is involved

We will acknowledge reports within 5 business days where possible.

## Security Model

Faultline OSS is local-first:

- source code is not uploaded by default
- no telemetry is sent by default
- the scanner does not execute repository scripts
- optional exports are metadata-only unless explicitly documented otherwise

Commercial services must treat uploaded Faultline metadata as customer data and
must not require raw source code upload for the initial paid product model.
