"""
Realistic GitHub repo data fixtures for heuristic testing.
Each fixture returns a dict matching GitHubFetcher.fetch() output exactly.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

now = datetime.now(UTC)


def _stargazers(n: int, followers: int = 5, repos: int = 10,
                account_age_days: int = 500, days_ago: int = 30) -> list[dict]:
    base = now - timedelta(days=days_ago)
    created = now - timedelta(days=account_age_days)
    return [{"login": f"user{i}", "starred_at": base, "followers": followers,
             "public_repos": repos, "created_at": created} for i in range(n)]


def _bought_stargazers(n: int) -> list[dict]:
    """Aged accounts (>365 days) but completely empty — purchased profile pattern."""
    created = now - timedelta(days=800)  # old account
    return [{"login": f"ghost{i}", "starred_at": now - timedelta(days=5),
             "followers": 0, "public_repos": 0, "created_at": created} for i in range(n)]


def _pr(days_ago: int = 10, merged: bool = False, comments: int = 0,
        followers: int = 0, repos: int = 1) -> dict:
    return {"title": "fix: update", "created_at": now - timedelta(days=days_ago),
            "merged": merged, "comments": comments, "user_login": f"pr_user_{days_ago}",
            "user_followers": followers, "user_public_repos": repos,
            "user_created_at": now - timedelta(days=30)}


def _timeline(monthly_counts: list[tuple[str, int]]) -> list[dict]:
    return [{"month": m, "count": c} for m, c in monthly_counts]


# ── Legitimate repos ──────────────────────────────────────────────────────────

def legit_popular_repo() -> dict:
    """Healthy, popular open-source project — should score CLEAN."""
    return {
        "slug": "owner/legit-repo",
        "stars": 8000,
        "forks": 1200,
        "open_issues": 45,
        "watchers": 80,  # ratio 0.010 — organic
        "created_at": now - timedelta(days=900),
        "pushed_at": now - timedelta(days=2),
        "owner_created_at": now - timedelta(days=2000),
        "owner_public_repos": 25,
        "owner_followers": 300,
        "readme": "A well-documented ML library. See paper at arxiv.org/...",
        "topics": ["machine-learning", "python"],
        "license": "MIT",
        "default_branch": "main",
        "commit_count": 30,
        "stargazers_sample": _stargazers(60, followers=15, repos=12, account_age_days=1500),
        "code_snippets": [{"path": "model.py", "content": "import torch\nclass Model(nn.Module): pass"}],
        "recent_prs": [_pr(i * 5, merged=True, comments=4, followers=20, repos=15) for i in range(5)],
        "commit_timeline": _timeline([(f"2024-{i:02d}", 8) for i in range(1, 13)]),
    }


def legit_small_repo() -> dict:
    """Small but genuine project — should score CLEAN."""
    return {
        "slug": "author/small-util",
        "stars": 280,
        "forks": 45,
        "open_issues": 8,
        "watchers": 12,
        "created_at": now - timedelta(days=400),
        "pushed_at": now - timedelta(days=7),
        "owner_created_at": now - timedelta(days=1800),
        "owner_public_repos": 18,
        "owner_followers": 90,
        "readme": "A small utility for X. Install with pip. See docs.",
        "topics": ["python", "utility"],
        "license": "MIT",
        "default_branch": "main",
        "commit_count": 12,
        "stargazers_sample": _stargazers(60, followers=8, repos=10, account_age_days=900),
        "code_snippets": [{"path": "main.py", "content": "def run(): pass"}],
        "recent_prs": [_pr(30, merged=True, comments=2)],
        "commit_timeline": _timeline([(f"2024-{i:02d}", 4) for i in range(1, 13)]),
    }


# ── Scam / suspicious repos ───────────────────────────────────────────────────

def bought_stars_repo() -> dict:
    """
    Repo with purchased stars — aged-but-empty accounts, low fork ratio,
    low watcher ratio. Typical blockchain/AI startup pattern from CMU study.
    """
    return {
        "slug": "startup/hot-ai-tool",
        "stars": 15000,
        "forks": 180,        # ratio 0.012 — well below 0.05 threshold
        "open_issues": 3,
        "watchers": 20,      # ratio 0.001 — below 0.003 threshold
        "created_at": now - timedelta(days=500),  # old enough for fork_ratio
        "pushed_at": now - timedelta(days=5),
        "owner_created_at": now - timedelta(days=350),
        "owner_public_repos": 2,
        "owner_followers": 5,
        "readme": "The most advanced AI tool. 10x faster than GPT-4.",
        "topics": ["ai", "llm"],
        "license": "MIT",
        "default_branch": "main",
        "commit_count": 3,
        "stargazers_sample": (
            _bought_stargazers(45) +           # 75% aged-but-empty
            _stargazers(15, followers=5, repos=8)  # 25% real
        ),
        "code_snippets": [{"path": "app.py", "content": "print('hello')"}],
        "recent_prs": [],
        "commit_timeline": _timeline([("2024-09", 5), ("2024-10", 2)]),
    }


def api_wrapper_repo() -> dict:
    """
    Repo claiming to run locally but actually calls OpenAI API.
    Should trigger api_disguised_as_local + low_activity_stargazers.
    """
    return {
        "slug": "fake/local-gpt",
        "stars": 3200,
        "forks": 40,
        "open_issues": 0,
        "watchers": 5,
        "created_at": now - timedelta(days=120),
        "pushed_at": now - timedelta(days=100),
        "owner_created_at": now - timedelta(days=130),
        "owner_public_repos": 1,
        "owner_followers": 0,
        "readme": "Run GPT-4 fully locally! No API key needed. Offline mode. Private.",
        "topics": ["local-llm", "ai"],
        "license": None,
        "default_branch": "main",
        "commit_count": 0,
        "stargazers_sample": _stargazers(60, followers=0, repos=0, account_age_days=400),
        "code_snippets": [{"path": "main.py",
                           "content": "from openai import OpenAI\nclient = OpenAI(api_key='sk-...')"}],
        "recent_prs": [],
        "commit_timeline": _timeline([("2024-11", 3)]),
    }


def empty_readme_repo() -> dict:
    """
    Repo with impressive README but no real code — vibe coding / portfolio padding.
    Should trigger no_activity + low fork ratio.
    """
    return {
        "slug": "vibe/wifi-densepose-clone",
        "stars": 8500,
        "forks": 95,         # ratio 0.011
        "open_issues": 0,
        "watchers": 8,       # ratio 0.001
        "created_at": now - timedelta(days=500),  # old enough for fork_ratio
        "pushed_at": now - timedelta(days=180),
        "owner_created_at": now - timedelta(days=210),
        "owner_public_repos": 1,
        "owner_followers": 2,
        "readme": (
            "# WiFi DensePose\n\nDetect human poses through walls using WiFi signals. "
            "Real-time tracking. Heart rate monitoring. Privacy-preserving.\n\n"
            "## Results\nAchieved 94.7% accuracy on our benchmark dataset."
        ),
        "topics": ["ai", "computer-vision", "wifi"],
        "license": "MIT",
        "default_branch": "main",
        "commit_count": 0,
        "stargazers_sample": (
            _bought_stargazers(50) +
            _stargazers(10, followers=3, repos=5)
        ),
        "code_snippets": [{"path": "demo.py",
                           "content": "import numpy as np\ndata = np.random.randn(100)\nprint(data.mean())"}],
        "recent_prs": [],
        "commit_timeline": _timeline([("2024-10", 2), ("2024-11", 1)]),
    }


def abandoned_takeover_repo() -> dict:
    """
    Legitimate old repo taken over — long dormancy then sudden burst.
    Should trigger abandoned_takeover.
    """
    return {
        "slug": "old-org/useful-lib",
        "stars": 1200,
        "forks": 180,
        "open_issues": 2,
        "watchers": 25,
        "created_at": now - timedelta(days=1800),
        "pushed_at": now - timedelta(days=10),
        "owner_created_at": now - timedelta(days=400),  # new owner, young account
        "owner_public_repos": 1,
        "owner_followers": 0,
        "readme": "A useful library. Now with AI features!",
        "topics": ["python"],
        "license": "MIT",
        "default_branch": "main",
        "commit_count": 20,
        "stargazers_sample": _stargazers(60, followers=10, repos=8, account_age_days=1200),
        "code_snippets": [{"path": "lib.py", "content": "def util(): pass"}],
        "recent_prs": [],
        "commit_timeline": _timeline([
            ("2022-01", 8), ("2022-02", 5), ("2022-03", 3),
            # 18 months dormant
            ("2022-04", 0), ("2022-05", 0), ("2022-06", 0),
            ("2022-07", 0), ("2022-08", 0), ("2022-09", 0),
            ("2022-10", 0), ("2022-11", 0), ("2022-12", 0),
            ("2023-01", 0), ("2023-02", 0), ("2023-03", 0),
            ("2023-04", 0), ("2023-05", 0), ("2023-06", 0),
            ("2023-07", 0), ("2023-08", 0), ("2023-09", 0),
            # burst
            ("2023-10", 25), ("2023-11", 18),
        ]),
    }


def wormgpt_pattern_repo() -> dict:
    """
    WormGPT/DarkGPT clone pattern — edgy name, minimal code, Telegram upsell.
    Should trigger multiple heuristics.
    """
    return {
        "slug": "hacker/ultragpt-uncensored",
        "stars": 450,
        "forks": 8,
        "open_issues": 0,
        "watchers": 2,
        "created_at": now - timedelta(days=90),
        "pushed_at": now - timedelta(days=85),
        "owner_created_at": now - timedelta(days=95),
        "owner_public_repos": 1,
        "owner_followers": 0,
        "readme": (
            "# UltraGPT Uncensored\nRun fully locally! No API key! Join Telegram for premium: t.me/ultragpt\n"
            "🔥 UNLIMITED. UNCENSORED. FREE. Premium version available - crypto payment accepted."
        ),
        "topics": ["worm-gpt", "ai", "hacking"],
        "license": None,
        "default_branch": "main",
        "commit_count": 0,
        "stargazers_sample": _stargazers(60, followers=0, repos=0, account_age_days=60),
        "code_snippets": [{"path": "bot.py",
                           "content": "import requests\nurl = 'https://openrouter.ai/api/v1'\n# premium only"}],
        "recent_prs": [],
        "commit_timeline": _timeline([("2024-12", 2)]),
    }
