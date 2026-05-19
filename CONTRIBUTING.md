# Contributing

## Quick start

```bash
git clone https://github.com/p3bri4n/legitifier
cd legitifier
make install
pip install pre-commit && pre-commit install
make test
```

## Setting up your environment

```bash
make install
pip install pre-commit && pre-commit install
```

The pre-commit hook will auto-fix lint issues before each commit.
`make lint-fix` to manually auto-correct, `make lint` to check (same as CI).

CI fails on any lint or formatting violation.

## What's most useful

1. **Scan and validate** with `--feedback`.
2. **Propose or refine a heuristic** by adding a YAML in `heuristics/`.
3. **Add to seed** in `data/seed.jsonl` (follow `data/seed_schema.md`).
4. **Report false positives** with `--output json` attached.

## Pull request process

1. One change per PR. Under 500 lines.
2. Tests required for logic changes.
3. Lint clean (`make lint`).
4. Update CHANGELOG.md.
5. PRs touching `data/seed.jsonl`, `legitifier_pkg/core/`, or `.github/workflows/*`
   require maintainer approval (CODEOWNERS).
6. By submitting a PR, you license your contribution under MIT.

## Security

Vulnerability? Do NOT open a public issue. See SECURITY.md.
