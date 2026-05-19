# Security Policy

## Reporting a Vulnerability

If you find a security vulnerability in legitifier, please **do not open a public issue**.
Report via:
- GitHub Security Advisories: https://github.com/p3bri4n/legitifier/security/advisories/new
- Email: <to-be-set>

We acknowledge within 72 hours and aim to publish a fix or disclosure plan within 30 days.

## Scope

In scope: legitifier CLI/library code, seed reputation DB, default heuristic YAML,
GitHub Actions workflows, build/release pipeline.

Out of scope: upstream dependency vulnerabilities, verdicts on specific repos
(open a regular issue with `--output json`), social engineering of maintainers.

## Supported versions

Only the latest minor version receives security patches.

## Threat model

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full threat model,
including in-scope threats, complementary tools, and maintenance governance.
