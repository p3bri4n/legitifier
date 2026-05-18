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
