"""Unit tests for GitHubFetcher (httpx-based)."""
from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from legitifier_pkg.fetchers.github import GitHubFetcher, _parse_dt


@pytest.fixture
def fetcher():
    with patch("httpx.Client"):
        f = GitHubFetcher(token=None)
        f._gql = None
        f._http = MagicMock()
        return f


def _mock_resp(data, status=200, headers=None):
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = data
    resp.headers = headers or {}
    resp.raise_for_status = MagicMock()
    return resp


class TestSlug:
    def test_full_url(self):
        assert GitHubFetcher._slug("https://github.com/owner/repo") == "owner/repo"
    def test_without_protocol(self):
        assert GitHubFetcher._slug("github.com/owner/repo") == "owner/repo"
    def test_trailing_slash(self):
        assert GitHubFetcher._slug("https://github.com/owner/repo/") == "owner/repo"
    def test_slug_passthrough(self):
        assert GitHubFetcher._slug("owner/repo") == "owner/repo"


class TestParseDate:
    def test_iso_format(self):
        dt = _parse_dt("2024-01-15T10:30:00Z")
        assert isinstance(dt, datetime) and dt.tzinfo is not None
    def test_none_input(self):
        assert _parse_dt(None) is None
    def test_empty_string(self):
        assert _parse_dt("") is None
    def test_invalid_format(self):
        assert _parse_dt("not-a-date") is None


class TestReadme:
    def test_returns_decoded_content(self, fetcher):
        import base64
        content = base64.b64encode(b"# Hello World").decode()
        fetcher._get = MagicMock(return_value={"content": content})
        assert "Hello World" in fetcher._readme("owner/repo")

    def test_returns_empty_on_error(self, fetcher):
        fetcher._get = MagicMock(side_effect=FileNotFoundError("404"))
        assert fetcher._readme("owner/repo") == ""


class TestTopics:
    def test_returns_list(self, fetcher):
        fetcher._get = MagicMock(return_value={"names": ["ai", "python"]})
        assert fetcher._topics("owner/repo") == ["ai", "python"]

    def test_returns_empty_on_error(self, fetcher):
        fetcher._get = MagicMock(side_effect=Exception("error"))
        assert fetcher._topics("owner/repo") == []


class TestRecentCommitCount:
    def test_uses_link_header(self, fetcher):
        resp = _mock_resp([{"sha": "abc"}],
                          headers={"Link": '<https://api.github.com/repos/o/r/commits?page=42>; rel="last"'})
        fetcher._http.get.return_value = resp
        assert fetcher._recent_commit_count("owner/repo") == 42

    def test_no_link_header(self, fetcher):
        fetcher._http.get.return_value = _mock_resp([{"sha": "a"}, {"sha": "b"}])
        assert fetcher._recent_commit_count("owner/repo") == 2

    def test_timedelta_not_missing(self, fetcher):
        """Regression: timedelta must be imported."""
        fetcher._http.get.return_value = _mock_resp([])
        result = fetcher._recent_commit_count("owner/repo")
        assert result >= 0  # no NameError

    def test_returns_zero_on_error(self, fetcher):
        fetcher._http.get.side_effect = Exception("timeout")
        assert fetcher._recent_commit_count("owner/repo") == 0


class TestRecentPRs:
    def test_returns_list(self, fetcher):
        fetcher._get = MagicMock(return_value=[
            {"number": 1, "title": "Fix", "created_at": "2024-01-01T00:00:00Z",
             "merged_at": "2024-01-02T00:00:00Z", "comments": 3, "user": {"login": "dev"}},
        ])
        result = fetcher._recent_prs("owner/repo")
        assert len(result) == 1 and result[0]["merged"] is True

    def test_returns_empty_on_error(self, fetcher):
        fetcher._get = MagicMock(side_effect=Exception("error"))
        assert fetcher._recent_prs("owner/repo") == []


class TestCommitTimeline:
    def test_groups_by_month(self, fetcher):
        fetcher._get = MagicMock(return_value=[
            {"commit": {"author": {"date": "2024-01-15T10:00:00Z"}}},
            {"commit": {"author": {"date": "2024-01-20T10:00:00Z"}}},
            {"commit": {"author": {"date": "2024-02-05T10:00:00Z"}}},
        ])
        result = fetcher._commit_timeline("owner/repo")
        months = {r["month"]: r["count"] for r in result}
        assert months.get("2024-01") == 2 and months.get("2024-02") == 1

    def test_returns_empty_on_error(self, fetcher):
        fetcher._get = MagicMock(side_effect=Exception)
        assert fetcher._commit_timeline("owner/repo") == []


class TestCodeSnippets:
    def test_filters_by_extension(self, fetcher):
        import base64

        def mock_get(path, params=None):
            if path.endswith("/contents"):
                return [
                    {"type": "file", "name": "main.py", "path": "main.py"},
                    {"type": "file", "name": "readme.txt", "path": "readme.txt"},
                ]
            if "main.py" in path:
                return {"content": base64.b64encode(b"print()").decode()}
            return {"content": base64.b64encode(b"hello").decode()}

        fetcher._get = MagicMock(side_effect=mock_get)
        fetcher._http.get.side_effect = lambda url, **kw: _mock_resp({}, status=404)
        result = fetcher._code_snippets("owner/repo", [".py"])
        paths = [r["path"] for r in result]
        assert "main.py" in paths and "readme.txt" not in paths
