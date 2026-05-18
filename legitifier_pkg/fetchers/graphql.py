from __future__ import annotations

from typing import Any

import httpx

_GQL_ENDPOINT = "https://api.github.com/graphql"

_QUERY = """
query($owner: String!, $repo: String!, $cursor: String) {
  repository(owner: $owner, name: $repo) {
    stargazers(first: 60, after: $cursor, orderBy: {field: STARRED_AT, direction: ASC}) {
      edges {
        starredAt
        node {
          login
          followers { totalCount }
          repositories(isFork: false, privacy: PUBLIC) { totalCount }
          createdAt
        }
      }
      pageInfo { endCursor hasNextPage }
    }
  }
}
"""


class GraphQLStargazerFetcher:
    """
    Fetch a stratified stargazer sample using the GitHub GraphQL API.
    One request returns up to 60 full profiles — vs 1+N REST requests.
    Falls back gracefully if the token is missing or GraphQL fails.
    """

    def __init__(self, token: str) -> None:
        self._token = token
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

    def fetch(self, owner: str, repo: str, total_stars: int, target: int = 60) -> list[dict[str, Any]]:
        """
        Fetch `target` stargazers stratified across the full star timeline.
        Uses cursor-based pagination to skip to different points in the history.
        """
        if total_stars == 0:
            return []

        # How many pages to skip to get a representative spread
        # Each page = 60 stars. We want `target` samples across all pages.
        total_pages = max(1, total_stars // 60)
        pages_to_fetch = max(1, min(target // 10, total_pages))
        step = max(1, total_pages // pages_to_fetch)

        all_edges: list[dict] = []
        cursor: str | None = None
        page = 0

        while len(all_edges) < target:
            # Skip `step` pages by fetching and discarding intermediate cursors
            if step > 1 and page > 0:
                cursor = self._skip_to_cursor(owner, repo, cursor, step - 1)
                if cursor is None:
                    break

            result = self._fetch_page(owner, repo, cursor)
            if result is None:
                break

            edges = result.get("edges", [])
            all_edges.extend(edges)
            page_info = result.get("pageInfo", {})

            if not page_info.get("hasNextPage"):
                break
            cursor = page_info.get("endCursor")
            page += 1

        return [self._parse_edge(e) for e in all_edges[:target] if e.get("node")]

    def _fetch_page(self, owner: str, repo: str, cursor: str | None) -> dict | None:
        variables = {"owner": owner, "repo": repo}
        if cursor:
            variables["cursor"] = cursor
        try:
            resp = httpx.post(
                _GQL_ENDPOINT,
                headers=self._headers,
                json={"query": _QUERY, "variables": variables},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
            if "errors" in data:
                return None
            return data["data"]["repository"]["stargazers"]
        except Exception:
            return None

    def _skip_to_cursor(self, owner: str, repo: str, cursor: str | None, pages: int) -> str | None:
        """Advance the cursor by `pages` pages without fetching full profile data."""
        _skip_query = """
        query($owner: String!, $repo: String!, $cursor: String) {
          repository(owner: $owner, name: $repo) {
            stargazers(first: 60, after: $cursor) {
              pageInfo { endCursor hasNextPage }
            }
          }
        }
        """
        current = cursor
        for _ in range(pages):
            try:
                variables = {"owner": owner, "repo": repo}
                if current:
                    variables["cursor"] = current
                resp = httpx.post(
                    _GQL_ENDPOINT,
                    headers=self._headers,
                    json={"query": _skip_query, "variables": variables},
                    timeout=10,
                )
                resp.raise_for_status()
                data = resp.json()
                page_info = data["data"]["repository"]["stargazers"]["pageInfo"]
                if not page_info.get("hasNextPage"):
                    return None
                current = page_info["endCursor"]
            except Exception:
                return None
        return current

    @staticmethod
    def _parse_edge(edge: dict) -> dict[str, Any]:
        from datetime import datetime
        node = edge.get("node", {})
        starred_raw = edge.get("starredAt")
        starred_at = None
        if starred_raw:
            try:
                starred_at = datetime.fromisoformat(starred_raw.replace("Z", "+00:00"))
            except ValueError:
                pass
        created_raw = node.get("createdAt")
        created_at = None
        if created_raw:
            try:
                created_at = datetime.fromisoformat(created_raw.replace("Z", "+00:00"))
            except ValueError:
                pass
        return {
            "login": node.get("login"),
            "starred_at": starred_at,
            "followers": (node.get("followers") or {}).get("totalCount", 0),
            "public_repos": (node.get("repositories") or {}).get("totalCount", 0),
            "created_at": created_at,
        }
