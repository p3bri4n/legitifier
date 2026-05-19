from __future__ import annotations

import base64
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from legitifier_pkg.cache import FetchCache
from legitifier_pkg.fetchers.graphql import GraphQLStargazerFetcher

_API = "https://api.github.com"
_TIMEOUT = httpx.Timeout(15.0)


class RateLimitError(Exception):
    def __init__(self, reset_at: datetime | None, message: str) -> None:
        self.reset_at = reset_at
        super().__init__(message)


class GitHubFetcher:
    def __init__(
        self, token: str | None = None, cache: FetchCache | None = None
    ) -> None:
        self._token = token
        self._cache = cache or FetchCache()
        self._gql = GraphQLStargazerFetcher(token) if token else None
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._http = httpx.Client(
            headers=headers, timeout=_TIMEOUT, follow_redirects=True
        )

    def _request(
        self,
        path: str,
        params: dict | None = None,
        headers: dict | None = None,
    ) -> httpx.Response:
        """GET with rate-limit detection and single auto-retry for short waits."""
        import time as _time

        resp = self._http.get(f"{_API}{path}", params=params, headers=headers)

        if resp.status_code == 429:
            retry_after = int(resp.headers.get("Retry-After", "61"))
            if retry_after <= 10:
                _time.sleep(retry_after)
                return self._http.get(f"{_API}{path}", params=params, headers=headers)
            raise RateLimitError(
                None,
                f"Rate limit hit (429). Retry-After: {retry_after}s. "
                "Set GITHUB_TOKEN or wait.",
            )

        if resp.status_code == 403 and resp.headers.get("X-RateLimit-Remaining") == "0":
            reset_ts = resp.headers.get("X-RateLimit-Reset")
            reset_at: datetime | None = None
            wait_secs = 61.0
            if reset_ts:
                reset_at = datetime.fromtimestamp(int(reset_ts), UTC)
                wait_secs = (reset_at - datetime.now(UTC)).total_seconds()
            if wait_secs < 60:
                _time.sleep(max(0.0, wait_secs) + 1.0)
                return self._http.get(f"{_API}{path}", params=params, headers=headers)
            raise RateLimitError(
                reset_at,
                f"Rate limit hit. Set GITHUB_TOKEN or wait until {reset_at}.",
            )

        return resp

    def _get(self, path: str, params: dict | None = None) -> Any:
        resp = self._request(path, params=params)
        if resp.status_code == 404:
            raise FileNotFoundError(f"404: {path}")
        resp.raise_for_status()
        return resp.json()

    def fetch(self, repo_url: str) -> dict[str, Any]:
        slug = self._slug(repo_url)

        cached = self._cache.get(slug)
        if cached:
            return cached

        repo = self._get(f"/repos/{slug}")
        owner_login = repo["owner"]["login"]

        with ThreadPoolExecutor(max_workers=6) as pool:
            f_owner = pool.submit(self._owner, owner_login)
            f_readme = pool.submit(self._readme, slug)
            f_topics = pool.submit(self._topics, slug)
            f_stars = pool.submit(
                self._stargazers_sample, slug, repo["stargazers_count"]
            )
            f_prs = pool.submit(self._recent_prs, slug)
            f_commits = pool.submit(self._recent_commit_count, slug)
            f_timeline = pool.submit(self._commit_timeline, slug)
            f_snippets = pool.submit(
                self._code_snippets,
                slug,
                [".py", ".js", ".ts", ".go", ".rs", ".java", ".txt", ".toml"],
            )

        owner = f_owner.result()

        data = {
            "slug": slug,
            "stars": repo["stargazers_count"],
            "forks": repo["forks_count"],
            "open_issues": repo["open_issues_count"],
            "watchers": repo["subscribers_count"],
            "created_at": _parse_dt(repo["created_at"]),
            "pushed_at": _parse_dt(repo["pushed_at"]),
            "owner_created_at": _parse_dt(owner.get("created_at")),
            "owner_public_repos": owner.get("public_repos", 0),
            "owner_followers": owner.get("followers", 0),
            "readme": f_readme.result(),
            "topics": f_topics.result(),
            "license": (repo.get("license") or {}).get("name"),
            "default_branch": repo.get("default_branch", "main"),
            "commit_count": f_commits.result(),
            "stargazers_sample": f_stars.result(),
            "code_snippets": f_snippets.result(),
            "recent_prs": f_prs.result(),
            "commit_timeline": f_timeline.result(),
        }

        self._cache.set(slug, data)
        return data

    def _owner(self, login: str) -> dict:
        try:
            return self._get(f"/users/{login}")
        except Exception:
            return {}

    def _readme(self, slug: str) -> str:
        try:
            data = self._get(f"/repos/{slug}/readme")
            return base64.b64decode(data["content"].replace("\n", "")).decode(
                "utf-8", errors="replace"
            )
        except Exception:
            return ""

    def _topics(self, slug: str) -> list[str]:
        try:
            data = self._get(f"/repos/{slug}/topics")
            return data.get("names", [])
        except Exception:
            return []

    def _recent_commit_count(self, slug: str, days: int = 30) -> int:
        import re

        since = (datetime.now(UTC) - timedelta(days=days)).isoformat()
        try:
            resp = self._request(
                f"/repos/{slug}/commits",
                params={"since": since, "per_page": 1},
            )
            if resp.status_code != 200:
                return 0
            link = resp.headers.get("Link", "")
            if 'rel="last"' in link:
                m = re.search(r'page=(\d+)>; rel="last"', link)
                return int(m.group(1)) if m else len(resp.json())
            return len(resp.json())
        except Exception:
            return 0

    def _stargazers_sample(self, slug: str, total_stars: int) -> list[dict[str, Any]]:
        owner, name = slug.split("/", 1)

        if total_stars < 500:
            limit = min(total_stars, 100)
        elif total_stars < 10_000:
            limit = 100
        else:
            limit = 60

        if limit == 0:
            return []

        if self._gql:
            result = self._gql.fetch(owner, name, total_stars, target=limit)
            if result:
                return result

        # REST fallback: stratified sampling
        step = max(1, total_stars // limit)
        per_page = 100
        raw = []
        page = 1
        count = 0
        try:
            while len(raw) < limit:
                resp = self._request(
                    f"/repos/{slug}/stargazers",
                    params={"per_page": per_page, "page": page},
                    headers={"Accept": "application/vnd.github.star+json"},
                )
                if resp.status_code != 200:
                    break
                items = resp.json()
                if not items:
                    break
                for item in items:
                    if count % step == 0:
                        raw.append(item)
                    count += 1
                    if len(raw) >= limit:
                        break
                page += 1
        except Exception:
            pass

        def _enrich(item: dict) -> dict[str, Any] | None:
            try:
                user = item.get("user", {})
                login = user.get("login", "")
                if not login:
                    return None
                profile = self._get(f"/users/{login}")
                return {
                    "login": login,
                    "starred_at": _parse_dt(item.get("starred_at")),
                    "followers": profile.get("followers", 0),
                    "public_repos": profile.get("public_repos", 0),
                    "created_at": _parse_dt(profile.get("created_at")),
                }
            except Exception:
                return None

        sample = []
        with ThreadPoolExecutor(max_workers=8) as pool:
            for result in pool.map(_enrich, raw):
                if result:
                    sample.append(result)
        return sample

    def _recent_prs(self, slug: str, limit: int = 20) -> list[dict[str, Any]]:
        try:
            items = self._get(
                f"/repos/{slug}/pulls",
                params={
                    "state": "all",
                    "sort": "created",
                    "direction": "desc",
                    "per_page": limit,
                },
            )
            return [
                {
                    "number": pr["number"],
                    "title": pr["title"],
                    "created_at": _parse_dt(pr.get("created_at")),
                    "merged": pr.get("merged_at") is not None,
                    "comments": pr.get("comments", 0),
                    "user_login": (pr.get("user") or {}).get("login", ""),
                    "user_followers": 0,
                    "user_public_repos": 0,
                    "user_created_at": None,
                }
                for pr in items
            ]
        except Exception:
            return []

    def _commit_timeline(self, slug: str, limit: int = 50) -> list[dict[str, Any]]:
        counts: Counter = Counter()
        try:
            items = self._get(f"/repos/{slug}/commits", params={"per_page": limit})
            for commit in items:
                raw_date = (commit.get("commit", {}).get("author") or {}).get("date")
                if raw_date:
                    dt = _parse_dt(raw_date)
                    if dt:
                        counts[dt.strftime("%Y-%m")] += 1
        except Exception:
            pass
        return [{"month": k, "count": v} for k, v in sorted(counts.items())]

    def _code_snippets(
        self, slug: str, extensions: list[str], max_files: int = 20
    ) -> list[dict[str, str]]:
        snippets = []

        def _check_dir(d: str) -> str | None:
            try:
                resp = self._request(f"/repos/{slug}/contents/{d}")
                return d if resp.status_code == 200 else None
            except Exception:
                return None

        dirs_to_scan = [""]
        with ThreadPoolExecutor(max_workers=4) as pool:
            extras = list(pool.map(_check_dir, ["src", "app", "lib", "core"]))
        dirs_to_scan += [d for d in extras if d]

        for dir_path in dirs_to_scan:
            if len(snippets) >= max_files:
                break
            try:
                path = (
                    f"/repos/{slug}/contents/{dir_path}"
                    if dir_path
                    else f"/repos/{slug}/contents"
                )
                items = self._get(path)
                if not isinstance(items, list):
                    continue
                for item in items:
                    if len(snippets) >= max_files:
                        break
                    if item.get("type") == "file" and any(
                        item["name"].endswith(ext) for ext in extensions
                    ):
                        try:
                            file_data = self._get(
                                f"/repos/{slug}/contents/{item['path']}"
                            )
                            content = base64.b64decode(
                                file_data["content"].replace("\n", "")
                            ).decode("utf-8", errors="replace")
                            snippets.append({"path": item["path"], "content": content})
                        except Exception:
                            pass
            except Exception:
                pass
        return snippets

    @staticmethod
    def _slug(url: str) -> str:
        url = url.rstrip("/")
        if "github.com/" in url:
            return url.split("github.com/")[-1]
        return url


def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
