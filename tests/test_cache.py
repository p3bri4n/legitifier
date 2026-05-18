import time
from datetime import UTC

import pytest

from legitifier_pkg.cache import FetchCache


@pytest.fixture
def cache(tmp_path) -> FetchCache:
    return FetchCache(path=tmp_path / "cache.db", ttl=60)


class TestFetchCache:
    def test_set_and_get(self, cache):
        cache.set("owner/repo", {"stars": 100})
        result = cache.get("owner/repo")
        assert result == {"stars": 100}

    def test_datetime_serialization(self, cache):
        from datetime import datetime
        now = datetime.now(UTC)
        cache.set("owner/repo", {"created_at": now, "stars": 42})
        result = cache.get("owner/repo")
        assert isinstance(result["created_at"], datetime)
        assert result["created_at"].tzinfo is not None
        assert result["stars"] == 42

    def test_date_serialization(self, cache):
        from datetime import date
        d = date(2024, 5, 16)
        cache.set("owner/repo", {"added": d})
        result = cache.get("owner/repo")
        assert isinstance(result["added"], date)
        assert result["added"] == d

    def test_miss_returns_none(self, cache):
        assert cache.get("unknown/repo") is None

    def test_expired_returns_none(self, tmp_path):
        short_cache = FetchCache(path=tmp_path / "short.db", ttl=1)
        short_cache.set("owner/repo", {"stars": 50})
        time.sleep(1.1)
        assert short_cache.get("owner/repo") is None

    def test_delete(self, cache):
        cache.set("owner/repo", {"stars": 42})
        cache.delete("owner/repo")
        assert cache.get("owner/repo") is None

    def test_purge_expired(self, tmp_path):
        short_cache = FetchCache(path=tmp_path / "purge.db", ttl=1)
        short_cache.set("a/b", {"x": 1})
        short_cache.set("c/d", {"x": 2})
        time.sleep(1.1)
        n = short_cache.purge_expired()
        assert n == 2

    def test_overwrite(self, cache):
        cache.set("owner/repo", {"stars": 1})
        cache.set("owner/repo", {"stars": 99})
        assert cache.get("owner/repo") == {"stars": 99}


class TestScanVersionInvalidation:
    """Test that get_recent_scan respects version and pushed_at."""

    def _make_store(self, tmp_path):
        from legitifier_pkg.feedback.store import FeedbackStore
        return FeedbackStore(db_path=tmp_path / "scans.db")

    def _save_scan(self, store, version="1.0.0", pushed_at=None):
        from unittest.mock import MagicMock

        from legitifier_pkg.core.models import ScanReport, Verdict
        report = MagicMock(spec=ScanReport)
        report.repo_url = "github.com/owner/repo"
        report.risk_score = 0.0
        report.verdict = Verdict.CLEAN
        report.results = []
        report.errors = []
        report.scan_duration_seconds = 1.0
        report.scanner_version = version
        report.scanned_at = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
        report.model_dump_json = lambda **_: __import__("json").dumps({
            "repo_url": report.repo_url,
            "risk_score": 0.0,
            "verdict": "CLEAN",
            "results": [],
            "errors": [],
            "scan_duration_seconds": 1.0,
            "scanner_version": version,
            "scanned_at": report.scanned_at.isoformat(),
        })
        store.save_scan(report)

    def test_returns_scan_same_version(self, tmp_path):
        store = self._make_store(tmp_path)
        self._save_scan(store, version="1.0.0")
        result = store.get_recent_scan(
            "github.com/owner/repo", max_age_seconds=3600, current_version="1.0.0"
        )
        assert result is not None

    def test_invalidates_older_version(self, tmp_path):
        store = self._make_store(tmp_path)
        self._save_scan(store, version="1.0.0")
        result = store.get_recent_scan(
            "github.com/owner/repo", max_age_seconds=3600, current_version="2.0.0"
        )
        assert result is None

    def test_invalidates_if_repo_pushed_after_scan(self, tmp_path):
        from datetime import datetime, timedelta
        store = self._make_store(tmp_path)
        self._save_scan(store, version="1.0.0")
        future_push = datetime.now(UTC) + timedelta(hours=1)
        result = store.get_recent_scan(
            "github.com/owner/repo", max_age_seconds=3600,
            repo_pushed_at=future_push
        )
        assert result is None

    def test_valid_if_repo_pushed_before_scan(self, tmp_path):
        from datetime import datetime, timedelta
        store = self._make_store(tmp_path)
        self._save_scan(store, version="1.0.0")
        old_push = datetime.now(UTC) - timedelta(days=30)
        result = store.get_recent_scan(
            "github.com/owner/repo", max_age_seconds=3600,
            repo_pushed_at=old_push
        )
        assert result is not None
