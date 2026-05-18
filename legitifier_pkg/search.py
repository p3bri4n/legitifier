from __future__ import annotations

from pathlib import Path
from typing import Iterator

import httpx
import yaml

_SEARCH_API = "https://api.github.com/search/repositories"
_RATE_LIMIT_PAUSE = 2.0


def _find_presets() -> Path:
    candidates = [
        Path(__file__).parents[2] / "data" / "search_presets.yaml",  # source tree
        Path(__file__).parent / "search_presets.yaml",               # bundled alongside
    ]
    for p in candidates:
        if p.exists():
            return p
    return candidates[0]  # seconds between search pages (stricter limit)


def load_presets() -> dict[str, dict]:
    path = _find_presets()
    if not path.exists():
        return {}
    with path.open() as f:
        data = yaml.safe_load(f)
    return data.get("presets", {})


def build_query(
    topic: str | None = None,
    language: str | None = None,
    stars: str | None = None,
    forks: str | None = None,
    created: str | None = None,
    pushed: str | None = None,
    extra: str | None = None,
) -> str:
    parts = []
    if topic:
        parts.append(f"topic:{topic}")
    if language:
        parts.append(f"language:{language}")
    if stars:
        parts.append(f"stars:{stars}")
    if forks:
        parts.append(f"forks:{forks}")
    if created:
        parts.append(f"created:{created}")
    if pushed:
        parts.append(f"pushed:{pushed}")
    if extra:
        parts.append(extra)
    return " ".join(parts)


_TRENDING_URL = "https://github.com/trending"
_EXCLUDED_SLUGS = {"sponsors", "apps", "marketplace", "trending", "explore",
                   "topics", "collections", "features", "login", "signup"}


def trending_repos(
    language: str = "",
    since: str = "daily",
    limit: int = 30,
) -> Iterator[tuple[str, int]]:
    """
    Yield (repo_url, global_index) from GitHub Trending.
    No API key required — scrapes the public trending page.
    since: daily | weekly | monthly
    """
    import re
    url = f"{_TRENDING_URL}/{language}?since={since}" if language else f"{_TRENDING_URL}?since={since}"
    try:
        resp = httpx.get(url, headers={"User-Agent": "legitifier/1.0"}, timeout=10)
        resp.raise_for_status()
    except Exception as e:
        yield f"__error__:{e}", 0
        return

    slugs = re.findall(r'href="/([a-zA-Z0-9_.\-]+/[a-zA-Z0-9_.\-]+)"', resp.text)
    seen: set[str] = set()
    index = 0
    for slug in slugs:
        parts = slug.split("/")
        if len(parts) != 2:
            continue
        owner, repo = parts
        if owner.lower() in _EXCLUDED_SLUGS or repo.lower() in _EXCLUDED_SLUGS:
            continue
        if slug in seen:
            continue
        seen.add(slug)
        yield f"https://github.com/{slug}", index
        index += 1
        if index >= limit:
            break


def search_repos(
    query: str,
    token: str | None,
    limit: int = 20,
    start_offset: int = 0,
) -> Iterator[tuple[str, int]]:
    """Yield (repo_url, global_index) matching the GitHub search query."""
    import time

    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    # GitHub API: page is 1-indexed, 30 results per page
    start_page = (start_offset // 30) + 1
    skip_in_page = start_offset % 30
    page = start_page
    yielded = 0
    global_index = start_offset

    while yielded < limit:
        per_page = 30
        try:
            resp = httpx.get(
                _SEARCH_API,
                params={"q": query, "sort": "stars", "order": "desc",
                        "per_page": per_page, "page": page},
                headers=headers,
                timeout=15,
            )
            if resp.status_code == 403:
                retry_after = int(resp.headers.get("Retry-After", 60))
                yield f"__rate_limit__:{retry_after}", global_index
                time.sleep(retry_after)
                continue
            resp.raise_for_status()
            items = resp.json().get("items", [])
            if not items:
                break
            # Skip items already seen in the first page
            if skip_in_page and page == start_page:
                items = items[skip_in_page:]
                skip_in_page = 0
            for item in items:
                if yielded >= limit:
                    break
                yield item["html_url"], global_index
                yielded += 1
                global_index += 1
            page += 1
            time.sleep(_RATE_LIMIT_PAUSE)
        except Exception as e:
            yield f"__error__:{e}", global_index
            break


_STARSCOUT_URLS = [
    # Most recent run first
    "https://raw.githubusercontent.com/hehao98/StarScout/main/data/250101/fake_star_repos.csv",
    "https://raw.githubusercontent.com/hehao98/StarScout/main/data/250101/low_activity_repos.csv",
    "https://raw.githubusercontent.com/hehao98/StarScout/main/data/241001/fake_star_repos.csv",
    "https://raw.githubusercontent.com/hehao98/StarScout/main/data/241001/low_activity_repos.csv",
    "https://raw.githubusercontent.com/hehao98/StarScout/main/data/240701/fake_star_repos.csv",
]


def starscout_repos(limit: int = 100) -> Iterator[tuple[str, int]]:
    """
    Yield (repo_url, global_index) from the CMU StarScout dataset.
    Known repos with suspected fake stars — no API key required.
    Source: He et al., ICSE 2026 — https://arxiv.org/abs/2412.13459
    Tries multiple dataset versions automatically.
    """
    import csv

    resp = None
    for url in _STARSCOUT_URLS:
        try:
            r = httpx.get(url, timeout=30)
            if r.status_code == 200:
                resp = r
                break
        except Exception:
            continue

    if resp is None:
        yield "__error__:StarScout dataset not found — all URLs returned 404", 0
        return

    reader = csv.DictReader(resp.text.splitlines())
    index = 0
    for row in reader:
        if index >= limit:
            break
        slug = row.get("repo_name") or row.get("name") or row.get("full_name") or row.get("repository")
        if slug:
            slug = slug.strip()
            if not slug.startswith("http"):
                yield f"https://github.com/{slug}", index
            else:
                yield slug, index
            index += 1


def file_repos(path: str, limit: int = 1000) -> Iterator[tuple[str, int]]:
    """
    Yield (repo_url, global_index) from a text file (one URL or owner/repo per line).
    Lines starting with # are ignored.
    """
    from pathlib import Path as P
    p = P(path)
    if not p.exists():
        yield f"__error__:File not found: {path}", 0
        return

    index = 0
    for line in p.read_text().splitlines():
        if index >= limit:
            break
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        url = line if line.startswith("http") else f"https://github.com/{line}"
        yield url, index
        index += 1
