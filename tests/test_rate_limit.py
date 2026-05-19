from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import httpx
import pytest

from legitifier_pkg.fetchers.github import GitHubFetcher, RateLimitError


def _make_fetcher() -> GitHubFetcher:
    return GitHubFetcher(token=None)


def _mock_response(status_code: int, headers: dict | None = None, json_body=None):
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.headers = headers or {}
    resp.json.return_value = json_body or {}
    return resp


def test_403_with_remaining_zero_raises_rate_limit_error():
    fetcher = _make_fetcher()
    future_ts = str(int(datetime.now(UTC).timestamp()) + 3600)
    resp = _mock_response(
        403,
        headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": future_ts},
    )
    with patch.object(fetcher._http, "get", return_value=resp):
        with pytest.raises(RateLimitError) as exc_info:
            fetcher._request("/repos/foo/bar")
    assert exc_info.value.reset_at is not None


def test_403_with_short_reset_retries_and_succeeds():
    fetcher = _make_fetcher()
    near_ts = str(int(datetime.now(UTC).timestamp()) + 5)
    rate_limited = _mock_response(
        403,
        headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": near_ts},
    )
    success = _mock_response(200, json_body={"name": "bar"})
    with patch.object(fetcher._http, "get", side_effect=[rate_limited, success]):
        with patch("time.sleep"):
            resp = fetcher._request("/repos/foo/bar")
    assert resp.status_code == 200


def test_429_with_short_retry_after_retries():
    fetcher = _make_fetcher()
    rate_limited = _mock_response(429, headers={"Retry-After": "2"})
    success = _mock_response(200, json_body={"name": "bar"})
    with patch.object(fetcher._http, "get", side_effect=[rate_limited, success]):
        with patch("time.sleep") as mock_sleep:
            resp = fetcher._request("/repos/foo/bar")
    mock_sleep.assert_called_once_with(2)
    assert resp.status_code == 200


def test_429_with_long_retry_after_raises():
    fetcher = _make_fetcher()
    resp = _mock_response(429, headers={"Retry-After": "300"})
    with patch.object(fetcher._http, "get", return_value=resp):
        with pytest.raises(RateLimitError) as exc_info:
            fetcher._request("/repos/foo/bar")
    assert "429" in str(exc_info.value)


def test_403_authorization_error_not_rate_limit():
    """403 with remaining tokens is an auth error, not a rate limit."""
    fetcher = _make_fetcher()
    resp = _mock_response(403, headers={"X-RateLimit-Remaining": "100"})
    resp.raise_for_status.side_effect = httpx.HTTPStatusError(
        "403", request=MagicMock(), response=resp
    )
    with patch.object(fetcher._http, "get", return_value=resp):
        # Should NOT raise RateLimitError — falls through to raise_for_status
        with pytest.raises(httpx.HTTPStatusError):
            fetcher._get("/repos/foo/bar")


def test_pipeline_rate_limit_returns_unknown_verdict(tmp_path):
    from legitifier_pkg.core.models import Verdict
    from legitifier_pkg.feedback.store import FeedbackStore
    from legitifier_pkg.pipeline import Pipeline

    store = FeedbackStore(db_path=tmp_path / "scans.db")
    pipeline = Pipeline(store=store, silent=True)

    with patch.object(
        pipeline._github,
        "fetch",
        side_effect=RateLimitError(None, "Rate limit hit. Set GITHUB_TOKEN or wait."),
    ):
        report, _ = pipeline.run("github.com/foo/bar")

    assert report.verdict == Verdict.UNKNOWN
    assert any("Rate limit" in e for e in report.errors)
