# Threat Model

## In scope

| Threat | Mitigation |
|---|---|
| Compromised legitifier release on PyPI | Trusted Publishing OIDC, Sigstore attestation |
| Compromised seed (malicious whitelist PR) | CODEOWNERS review, validate_seed.py |
| Compromised heuristic YAML | CODEOWNERS review, tests on fixtures |
| Compromised dependency | Lockfile with hashes, pip-audit, OSV scanner, Dependabot |
| Exfiltration of local data | Reads only `~/.legitifier/*`, documented in PRIVACY.md |

## Out of scope

- Typosquatting of scanned repos (use Socket.dev, Snyk).
- Dependency confusion in the user's project.
- Active malware in scanned repos (legitifier scores credibility, not safety).
- Obfuscated or encrypted code in scanned repos.
- Social engineering of maintainers (see "Maintenance governance" below).
- Censorship via unfair SCAM verdict (DISPUTE_PROCESS — future work).
- Compromise of GitHub itself.

## Complementary tools

- **Socket.dev / Snyk** — dependency-level malware detection.
- **Semgrep** — static code analysis of scanned repos.
- **OSV-Scanner** — vulnerability database scans.
- **OpenSSF Scorecard** — open-source project health metrics.

## CVE management for non-patchable vulnerabilities

If a vulnerability is reported in a transitive dependency that has no upstream fix:

1. Open a GitHub Security Advisory to track it.
2. Annotate the affected line in `requirements.lock` or `pyproject.toml` with
   `# osv-scanner-ignore: GHSA-xxxx — <reason>` and link the advisory.
3. Re-evaluate every 30 days until a fix is available or the dependency is replaced.

## Maintenance governance

- Recruit 2 co-maintainers within 6 months of reaching 1 000 stars.
- Require 2 approvals on merges to `main` once multi-maintainer.
- Publish `MAINTAINERS.md` listing trusted maintainers and their GPG fingerprints.
- Document all `seed.jsonl` merges with rationale in the PR description.
- Rotate PyPI Trusted Publisher credentials if any maintainer leaves.
