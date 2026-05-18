**legitifier**  
A command-line tool to evaluate the credibility of GitHub repositories — with a focus on projects making inflated or misleading claims, particularly in the AI/ML space.  
It checks social signals (star patterns, fork ratios, watcher engagement), repository metadata (account age, commit history), code quality (secrets, documentation, test coverage, API disguise), content (Telegram funnels, LLM analysis), and repository history (dormancy patterns). Each check is a standalone YAML-defined heuristic, making them easy to audit, extend, or disable.  
Useful for developers evaluating dependencies, investors doing open-source due diligence, and security researchers tracking fake-star campaigns. A [CMU study (ICSE 2026) found 6 million suspected fake stars across 18,617 repositories — with AI/LLM repos as the largest non-malicious category.](https://arxiv.org/abs/2412.13459 "https://arxiv.org/abs/2412.13459")  
Feedback from scans is stored locally and can be exported as a labeled dataset for future classifier training.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OQQmAABRAsSfYxKK/kJXEkyE8WcGbCFuCLTOzVXsAAPzFsVZ3dX4cAQDgvesB/vEF9H9odtUAAAAASUVORK5CYII=)  
**Installation**  
Requires Python 3.11+ and [uv.](https://docs.astral.sh/uv/getting-started/installation/ "https://docs.astral.sh/uv/getting-started/installation/")  
git clone https://github.com/p3bri4n/legitifier  
 cd legitifier  
 make install  
 source .venv/bin/activate  
   
For LLM support, use make install-llm instead.  
A GitHub token is strongly recommended to avoid rate limiting:  
export GITHUB_TOKEN=ghp_...  
For LLM-based README analysis (optional):  
pip install "legitifier[llm]"  
   
 # OpenAI  
 export OPENAI_API_KEY=sk-...  
 export OPENAI_MODEL=gpt-4o-mini          # optional, default: gpt-4o-mini  
   
 # Anthropic  
 export ANTHROPIC_API_KEY=sk-ant-...  
 export ANTHROPIC_MODEL=claude-haiku-4-5-20251001  # optional  
   
 # Ollama — local inference, no API key required  
 ollama pull qwen2.5:7b  
 export OLLAMA_MODEL=qwen2.5:7b  
 export OLLAMA_HOST=http://localhost:11434  # optional, default: localhost  
   
Priority when multiple are set: OLLAMA_MODEL > OPENAI_API_KEY > ANTHROPIC_API_KEY.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANklEQVR4nO3OYQ1AABSAwc8mi5wvkwZyCKCAACr4Z7a7BLfMzFYdAQDwF+da3dX+9QQAgNeuB6feBdUJcyS2AAAAAElFTkSuQmCC)  
**Usage**  
# Scan a single repo  
 legitifier scan github.com/someuser/somerepo  
   
 # With feedback prompt  
 legitifier scan github.com/someuser/somerepo --feedback  
   
 # JSON output (for scripting)  
 legitifier scan github.com/someuser/somerepo --output json  
   
 # Force fresh fetch (bypass cache)  
 legitifier scan github.com/someuser/somerepo --no-cache  
   
**Search and batch scan**  
# List available presets  
 legitifier search --list-presets  
   
 # Use a preset  
 legitifier search --preset scam-hunter --limit 20  
 legitifier search --preset wormgpt-variants --limit 10  
   
 # Custom criteria  
 legitifier search --topic llm --stars ">500" --forks "<30" --limit 20  
 legitifier search --topic ai --language python --created ">2024-06-01" --limit 15  
   
 # Raw GitHub search query  
 legitifier search --query "wormgpt stars:>50" --limit 10  
   
 # GitHub Trending — no token required, no criteria needed  
 legitifier search --source trending --limit 30  
 legitifier search --source trending --language python --since weekly --limit 30  
   
 # CMU StarScout dataset — repos with suspected fake stars, no token required  
 # Source: He et al., ICSE 2026 — https://arxiv.org/abs/2412.13459  
 legitifier search --source starscout --limit 50  
   
 # From a file (one URL or owner/repo per line, # for comments)  
 legitifier search --source file --input repos.txt --limit 100  
   
Available presets: scam-hunter, vibe-coding, fresh-suspect, wormgpt-variants, api-wrapper, educational.  
Each source remembers its position — re-running the same command continues where it left off.  
   
 Use --reset to start over, --rescan to re-scan already-seen repos.  
**Dataset and cache**  
# Export annotated scans as JSONL  
 legitifier export dataset.jsonl  
   
 # Clear expired cache entries  
 legitifier cache-clear  
   
 # Clear all cache  
 legitifier cache-clear --all  
   
Exit code is 0 if Trust ≥ 50, 1 otherwise — useful in CI pipelines.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANElEQVR4nO3OUQmAABBAsSdYxKbXxlpGEAOIFfwTYUuwZWa2ag8AgL841uquzq8nAAC8dj05VAYO3phhoQAAAABJRU5ErkJggg==)  
**How it works**  
Each heuristic is a YAML file in heuristics/. The pipeline loads them at runtime, runs the appropriate analyzer, and aggregates weighted scores into a final verdict.  
CLEAN < 25 — SUSPICIOUS < 50 — LIKELY_SCAM < 75 — SCAM  
 UNKNOWN — repository not found or inaccessible (404)  
   
Scoring uses a hybrid formula: weighted average of triggered heuristics only (not diluted by clean signals), boosted by the strongest single signal, and scaled by trigger coverage. This means a single critical signal raises the score meaningfully without being buried by the heuristics that found nothing.  
The output shows scan duration and only the heuristics that triggered — clean signals are hidden to reduce noise.  
**Current heuristics (18)**  
| | | | |  
|-|-|-|-|  
| **ID** | **Category** | **Severity** | **What it checks** |   
| stars_velocity | social | high | Abnormal star acquisition spikes (>100 stars absolute, >10x baseline) |   
| fork_ratio | social | medium | Fork/star ratio below 0.03 on repos older than 1 year |   
| watcher_to_star_ratio | social | high | Watcher/star ratio below 0.003 — organic repos average 0.005-0.030 |   
| low_activity_stargazers | social | high | High proportion of empty or aged-but-empty accounts among stargazers |   
| ai_prs | social | high | Burst of unmerged PRs from empty accounts (AI agent pattern) |   
| contributor_reputation | social | high | PR authors known in the reputation database |   
| account_age | metadata | medium | Recently created owner account (<90 days) |   
| commit_burst | metadata | high | All commits in first 2 weeks, dormant since |   
| no_activity | metadata | high | Popular repo with zero issues and no recent commits |   
| owner_reputation | metadata | critical | Owner or repo known in the reputation database |   
| abandoned_takeover | repo_history | critical | Long dormancy (6+ months) followed by sudden burst of commits |   
| api_disguised_as_local | code | critical | External API calls in a repo claiming to run locally or offline |   
| hardcoded_secrets | code | critical | API keys or tokens exposed directly in source files |   
| requirements_chaos | code | medium | Duplicate packages with conflicting versions in requirements.txt |   
| test_coverage_signals | code | medium | No tests, empty test patterns, or false coverage claims |   
| documentation_quality | code | medium | Short README, no structure, and near-zero comment ratio |   
| telegram_funnel | content | critical | Telegram link combined with commercial amplifiers (premium, crypto, payment) |   
| readme_llm_analysis | content | high | README claim vs. proof ratio — semantic analysis (requires LLM API key) |   
   
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANElEQVR4nO3OQQmAABRAsSdYxKa/jL0MIR7FCt5E2BJsmZmt2gMA4C+Otbqr8+sJAACvXQ85SAYUQNBTfQAAAABJRU5ErkJggg==)  
**Reputation database**  
legitifier ships with a seed database (data/seed.jsonl) of known scam actors and verified legitimate organizations. It is loaded at startup and merged with your local scan history.  
**Whitelist** — owners or repos marked CLEAN in the database have their score capped at SUSPICIOUS (49/100), preventing false positives on known legitimate projects. The seed includes major AI organizations (HuggingFace, Meta Research, Google DeepMind, Microsoft, OpenAI, Anthropic, Mistral AI, ggerganov).  
**Blacklist** — owners or repos marked SCAM or SUSPICIOUS contribute directly to the final score, weighted by confidence level (certain → 1.0, probable → 0.6, unsure → 0.3).  
**Local enrichment** — every time you use --feedback, your verdict is stored in ~/.legitifier/scans.db and factored into future scans of repos from the same owner or contributor.  
**Contributing to the seed**  
Add entries to data/seed.jsonl via pull request. The CI validates every PR automatically.  
Rules:  
- **Append-only** — never modify or delete existing entries  
- confidence: certain for SCAM/SUSPICIOUS requires an external published source (wall-of-shames, starscout, community)  
- confidence: certain for CLEAN (whitelist) is allowed with source: manual for verified organizations  
- Every entry needs a non-empty note with reproducible evidence  
Validate locally before submitting:  
python scripts/validate_seed.py  
   
Entry format:  
{"type": "owner", "login": "bad-actor", "verdict": "SCAM", "confidence": "probable", "source": "manual", "note": "3 repos wrapping OpenRouter, Telegram upsell", "added": "2026-05-16"}  
 {"type": "repo", "slug": "bad-actor/wormgpt", "verdict": "SCAM", "confidence": "certain", "source": "wall-of-shames", "note": "50 lines, API key theft", "added": "2026-05-16"}  
 {"type": "owner", "login": "legit-org", "verdict": "CLEAN", "confidence": "certain", "source": "manual", "note": "Verified academic organization", "added": "2026-05-16"}  
   
See [data/seed_schema.md for the full schema.](data/seed_schema.md "data/seed_schema.md")  
**Adding a heuristic**  
Create a YAML file in the appropriate heuristics/ subdirectory:  
id: my_heuristic  
 category: social_signals   # must match a registered analyzer  
 weight: 0.8  
 severity: medium           # low | medium | high | critical  
 description: What this checks.  
 inputs:  
   - github.stars  
 thresholds:  
   my_threshold: 42  
 scoring:  
   method: step  
   score_if_triggered: 60  
   score_if_clean: 0  
 evidence_template: "Found {value} (threshold: {my_threshold})"  
 tags: [example]  
   
No code change required — the registry picks it up automatically.  
To handle a new category, add an Analyzer class in legitifier_pkg/analyzers/ and decorate it:  
@analyzer_for("my_category")  
 class MyAnalyzer(BaseAnalyzer):  
     def analyze(self, config, data): ...  
   
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANklEQVR4nO3OQQmAABRAsSfYxZo/kSGMYQLPJrCCNxG2BFtmZquOAAD4i3Ot7mr/egIAwGvXA4qrBdGuSdJuAAAAAElFTkSuQmCC)  
**Dataset collection**  
Every scan is stored locally in ~/.legitifier/scans.db (SQLite). When you add --feedback, your verdict is recorded alongside the automated one.  
Export annotated scans:  
legitifier export dataset.jsonl  
   
The output is a JSONL file with one record per annotated scan, including heuristic scores, README content, and both the automated and human verdicts. This format is compatible with standard fine-tuning pipelines.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANElEQVR4nO3OUQmAABBAsSdYxKbXxlpGEAOIFfwTYUuwZWa2ag8AgL841uquzq8nAAC8dj05VAYO3phhoQAAAABJRU5ErkJggg==)  
**Batch collection**  
The legitifier search command covers all collection scenarios:  
# GitHub Trending (no token, no criteria)  
 legitifier search --source trending --limit 30  
   
 # GitHub Search with criteria  
 legitifier search --preset scam-hunter --limit 100  
   
 # CMU StarScout dataset (no token)  
 legitifier search --source starscout --limit 200  
   
 # From a file  
 legitifier search --source file --input repos.txt  
   
 # Combine with filters  
 legitifier search --source trending --language python --since weekly --limit 50  
   
Rate limits with token: ~620 scans/hour (5.8s delay). Without token: trending and starscout work fine; GitHub Search is severely limited (60 req/hour).  
Scan results are cached locally (~/.legitifier/cache.db, TTL 6h). Already-scanned repos are skipped automatically (1h TTL) — use --rescan to override.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANklEQVR4nO3OMQ2AABAAsSNBACP6MMH6NpGACyywEZJWQZeZ2aszAAD+4l6rrTq+ngAA8Nr1AL+6BElk4wV6AAAAAElFTkSuQmCC)  
**Project structure**  
data/  
   seed.jsonl             # Reputation database (scam actors + whitelist), versioned  
   seed_schema.md         # Schema and contribution rules  
   search_presets.yaml    # Built-in search presets for legitifier search  
 heuristics/              # YAML heuristic definitions (18 heuristics across 5 categories)  
   social/                # stars_velocity, fork_ratio, watcher_to_star_ratio,  
                          # low_activity_stargazers, ai_prs, contributor_reputation  
   metadata/              # account_age, commit_burst, no_activity, owner_reputation  
   repo_history/          # abandoned_takeover  
   code/                  # api_disguised_as_local, hardcoded_secrets,  
                          # requirements_chaos, test_coverage_signals, documentation_quality  
   content/               # telegram_funnel, readme_llm_analysis  
 prompts/                 # LLM prompt templates  
 legitifier_pkg/  
   core/                  # Models, registry, scorer (hybrid formula + whitelist capping)  
   data/                  # ReputationStore — merges seed + local DB  
   fetchers/              # GitHub API (httpx direct + GraphQL), LLM clients, LocalDB, cache  
   analyzers/             # One analyzer per heuristic category  
   feedback/              # Local scan storage and export  
   reports/               # Terminal and JSON output  
   cache.py               # SQLite cache with TTL and datetime serialization  
   search.py              # GitHub search, trending, StarScout, file sources  
 cli/                     # Entrypoint (scan / search / export / cache-clear / history)  
 scripts/  
   bump_version.py        # Bump version to YYYY.MMDD.hhmm  
   calibrate.py           # Calibration script with FP/detection rate report  
   validate_seed.py       # Validate seed.jsonl format and rules  
 tests/  
   fixtures/              # Realistic mock repo data for regression testing  
 .github/  
   workflows/  
     ci.yml               # Tests + lint on every push/PR  
     release.yml          # Build and publish to PyPI on tag  
     validate_seed.yml    # Validate seed.jsonl on PRs touching it  
   CODEOWNERS             # seed.jsonl and core/ require maintainer review  
   PULL_REQUEST_TEMPLATE/  
     seed_entry.md        # Template for seed contribution PRs  
   
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OMQ2AABAAsSNhwgJmkPYLLpnRgQU2QtIq6DIze3UGAMBf3Gu1VcfHEQAA3rseaHkEMn1wK7sAAAAASUVORK5CYII=)  
**How to contribute**  
legitifier improves through community effort. The more repos get scanned and validated, the better the heuristics become — for everyone.  
**Scan and validate verdicts**  
   
 The most impactful contribution. Scan repos you know well — legitimate projects from your own work, or suspected scams you've encountered — and use --feedback to validate the verdict. Each annotated scan enriches the shared dataset.  
legitifier scan github.com/suspicious/repo --feedback  
 legitifier scan github.com/my-trusted/library --feedback  
   
**Propose or refine a heuristic**  
   
 Each heuristic is a YAML file in heuristics/. No Python needed for existing categories — just add a YAML, write a test fixture, and open a PR. See data/seed_schema.md for the format and PULL_REQUEST_TEMPLATE/seed_entry.md for the PR template.  
**Add to the reputation seed**  
   
 data/seed.jsonl is append-only. If you have a confirmed scam actor or a well-known legitimate organization to add, follow the schema in data/seed_schema.md. PRs touching the seed require a source URL for SCAM entries with certain confidence.  
**Report false positives**  
   
 If a legitimate repo scores poorly, open an issue with the repo URL and the JSON output of legitifier scan <repo> --output json. This helps calibrate thresholds.  
**Add test fixtures**  
   
 tests/fixtures/repos.py contains mock repo profiles for regression testing. New patterns — a type of scam you've observed, a legitimate project that gets flagged — are welcome as fixtures with corresponding tests.  
Please do not open issues to report a specific repo as a scam. legitifier produces scores, not verdicts — human judgment is always required.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANElEQVR4nO3OUQmAABBAsSeILQSjXgcrmkOs4J8IW4ItM7NXZwAA/MW1Vlt1fBwBAOC9+wEukwQ+V/SggAAAAABJRU5ErkJggg==)  
**Sources and inspiration**  
**Research**  
- [He et al., "Demystifying Fake GitHub Stars" — ICSE 2026 — the CMU StarScout study that quantified 6M+ fake stars across 18,617 repos. The StarScout dataset is used directly in legitifier search --source starscout.](https://arxiv.org/abs/2412.13459 "https://arxiv.org/abs/2412.13459")  
- [FTC Rule on Fake Indicators of Social Media Influence (2024) — the regulatory context that makes this problem legally significant.](https://www.ftc.gov/news-events/news/press-releases/2024/08/ftc-announces-final-rule-banning-fake-reviews-testimonials "https://www.ftc.gov/news-events/news/press-releases/2024/08/ftc-announces-final-rule-banning-fake-reviews-testimonials")  
**Community work**  
- [Wall-of-Shames / scammer-analysis-guide — documented the Wrapper Trap, Telegram Funnel, and Fake Hacker Aesthetics patterns that directly inspired several heuristics (api_disguised_as_local, telegram_funnel, hardcoded_secrets, requirements_chaos).](https://github.com/Wall-of-Shames/scammer-analysis-guide "https://github.com/Wall-of-Shames/scammer-analysis-guide")  
- [Korben — "Faux repos GitHub et vibe coding" — the WiFi DensePose case study that motivated documentation_quality and test_coverage_signals.](https://korben.info/faux-repos-github-ia-vibe-coding.html "https://korben.info/faux-repos-github-ia-vibe-coding.html")  
- [Awesome Agents AI — "GitHub Fake Stars Investigation" — the Union Labs / FreeDomain analysis that refined watcher_to_star_ratio and fork_ratio thresholds.](https://awesomeagents.ai/news/github-fake-stars-investigation/ "https://awesomeagents.ai/news/github-fake-stars-investigation/")  
**Tooling**  
- [GHArchive — full GitHub event history, a future data source for improved star timeline analysis.](https://www.gharchive.org/ "https://www.gharchive.org/")  
- [HuggingFace Datasets — target format for the exported annotated dataset.](https://huggingface.co/docs/datasets "https://huggingface.co/docs/datasets")  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OMQ2AABAAsSPBCj7fFjsymJHAjAU2QtIq6DIzW7UHAMBfnGt1V8fXEwAAXrsexNkF4H1/HJoAAAAASUVORK5CYII=)  
**Limitations**  
- Star and stargazer analysis is based on a stratified sample (60-100 stargazers). Full historical analysis would require the GHArchive dataset.  
- Code analysis is limited to files visible in the repo root and common source directories. Obfuscated or minified code is not analyzed.  
- LLM analysis (readme_llm_analysis) requires an API key and is only as good as the prompt. README claims in languages other than English may score less accurately.  
- A high score is a signal, not proof. Some projects are just poorly maintained. Human judgment is always required before acting on a verdict.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAM0lEQVR4nO3OMQ0AIAwAwdIgBKl1gjacsGCAiZDcTT9+q6oRETMAAPjF6ify6QYAADdyA9Y0AypN+bdfAAAAAElFTkSuQmCC)  
**License**  
MIT  
