# Seed Database Schema

`data/seed.jsonl` is a public, versioned database of known scam actors and repositories.
It is loaded at startup and merged with the user's local scan history.

## Rules

- **Append-only** — never edit or delete existing entries. Add a new entry with `supersedes` if you need to correct one.
- **Evidence required** — every entry needs a `note` explaining why it was added.
- **Conservative by default** — prefer `probable` over `certain` unless you have strong proof.

## Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | `owner` \| `repo` \| `contributor` | ✅ | What the entry refers to |
| `login` | string | if type=owner/contributor | GitHub login |
| `slug` | string | if type=repo | `owner/repo` format |
| `verdict` | `SCAM` \| `SUSPICIOUS` \| `CLEAN` | ✅ | Assessment |
| `confidence` | `certain` \| `probable` \| `unsure` | ✅ | How sure we are |
| `source` | string | ✅ | Where this came from |
| `note` | string | ✅ | Evidence or reasoning |
| `added` | `YYYY-MM-DD` | ✅ | Date added |
| `supersedes` | string | — | login or slug of entry this overrides |

## Sources

- `manual` — reviewed and added by a maintainer
- `wall-of-shames` — from [Wall-of-Shames/scammer-analysis-guide](https://github.com/Wall-of-Shames/scammer-analysis-guide)
- `starscout` — from the [CMU StarScout dataset](https://github.com/hehao98/StarScout)
- `community` — submitted by a user and reviewed

## Contributing

Open a PR adding lines to `data/seed.jsonl`. Include:
1. Reproducible evidence in `note`
2. Link to source material in `source` or `note`
3. Conservative confidence level — when in doubt, use `probable`

Do not submit entries based solely on a high legitifier score.
Human review is required before merging into the seed.

## How confidence affects scoring

A seed entry's `confidence` acts as a **multiplier** on its risk contribution:

- `verdict: SCAM` → base contribution = 90
- `verdict: SUSPICIOUS` → base contribution = 50
- `verdict: CLEAN` → base contribution = 0 (caps the score instead, see below)

| Confidence | Multiplier |
|---|---|
| `certain` | ×1.0 |
| `probable` | ×0.6 |
| `unsure` | ×0.3 |

| Entry | Risk contribution |
|---|---|
| SCAM + certain | 90 |
| SCAM + probable | 54 |
| SCAM + unsure | 27 |
| SUSPICIOUS + certain | 50 |
| SUSPICIOUS + probable | 30 |
| SUSPICIOUS + unsure | 15 |

## Whitelist behavior

`CLEAN` entries cap the repo's final `risk_score` instead of contributing to it:

| Confidence | Effect |
|---|---|
| `certain` | Hard cap at 49 (SUSPICIOUS max) |
| `probable` | Hard cap at 65 (LIKELY_SCAM max) |
| `unsure` | Soft −10 penalty, no hard cap |

The cap is **bypassed** when 2 or more critical-severity signals from the `code_quality` or
`content_claims` heuristic categories trigger simultaneously. This handles supply chain
compromise scenarios (e.g. a trusted account taken over to distribute malware).
See `docs/THREAT_MODEL.md` for the full rationale.

## Example entries

```jsonl
{"type": "owner", "login": "fake-ai-org", "verdict": "SCAM", "confidence": "certain", "source": "manual", "note": "3 repos all wrapping OpenRouter, Telegram premium upsell", "added": "2026-05-16"}
{"type": "repo", "slug": "fake-ai-org/wormgpt", "verdict": "SCAM", "confidence": "certain", "source": "wall-of-shames", "note": "50 lines, API key stolen from users", "added": "2026-05-16"}
{"type": "owner", "login": "legit-researcher", "verdict": "CLEAN", "confidence": "certain", "source": "manual", "note": "Published author, verified academic affiliation", "added": "2026-05-16"}
```
