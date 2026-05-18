from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from legitifier_pkg.fetchers.graphql import GraphQLStargazerFetcher


def _make_edge(login: str, days_ago: int, followers: int = 5, repos: int = 10) -> dict:
    from datetime import timedelta
    ts = (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()
    return {
        "starredAt": ts,
        "node": {
            "login": login,
            "followers": {"totalCount": followers},
            "repositories": {"totalCount": repos},
            "createdAt": (datetime.now(timezone.utc) - timedelta(days=365)).isoformat(),
        }
    }


def _mock_response(edges: list[dict], has_next: bool = False, cursor: str = "abc") -> dict:
    return {
        "data": {
            "repository": {
                "stargazers": {
                    "edges": edges,
                    "pageInfo": {"endCursor": cursor, "hasNextPage": has_next}
                }
            }
        }
    }


class TestGraphQLStargazerFetcher:
    def setup_method(self):
        self.fetcher = GraphQLStargazerFetcher(token="test-token")

    def test_parse_edge(self):
        edge = _make_edge("user1", 30, followers=10, repos=5)
        result = self.fetcher._parse_edge(edge)
        assert result["login"] == "user1"
        assert result["followers"] == 10
        assert result["public_repos"] == 5
        assert isinstance(result["starred_at"], datetime)

    def test_fetch_returns_empty_for_zero_stars(self):
        result = self.fetcher.fetch("owner", "repo", total_stars=0)
        assert result == []

    @patch("httpx.post")
    def test_fetch_single_page(self, mock_post):
        edges = [_make_edge(f"user{i}", i * 10) for i in range(5)]
        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: _mock_response(edges, has_next=False),
            raise_for_status=lambda: None,
        )
        result = self.fetcher.fetch("owner", "repo", total_stars=5, target=5)
        assert len(result) == 5
        assert result[0]["login"] == "user0"

    @patch("httpx.post")
    def test_fetch_handles_graphql_error(self, mock_post):
        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: {"errors": [{"message": "Not found"}]},
            raise_for_status=lambda: None,
        )
        result = self.fetcher.fetch("owner", "repo", total_stars=100, target=10)
        assert result == []

    @patch("httpx.post")
    def test_fetch_handles_network_error(self, mock_post):
        mock_post.side_effect = Exception("timeout")
        result = self.fetcher.fetch("owner", "repo", total_stars=100, target=10)
        assert result == []

    def test_parse_edge_missing_node(self):
        result = self.fetcher._parse_edge({"starredAt": None, "node": {}})
        assert result["login"] is None
        assert result["followers"] == 0
