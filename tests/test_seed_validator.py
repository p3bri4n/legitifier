import json
from pathlib import Path

from scripts.validate_seed import validate_entry, validate_file


def _write_seed(tmp_path: Path, entries: list[dict]) -> Path:
    path = tmp_path / "seed.jsonl"
    path.write_text("\n".join(json.dumps(e) for e in entries))
    return path


def _valid_entry(**overrides) -> dict:
    base = {
        "type": "owner",
        "login": "bad-actor",
        "verdict": "SCAM",
        "confidence": "probable",
        "source": "manual",
        "note": "known scammer",
        "added": "2026-05-16",
    }
    return {**base, **overrides}


class TestValidateEntry:
    def test_valid_owner(self):
        entry, errors = validate_entry(1, json.dumps(_valid_entry()))
        assert errors == []

    def test_valid_repo(self):
        entry, errors = validate_entry(
            1, json.dumps(_valid_entry(type="repo", slug="bad-actor/scam", login=None))
        )
        assert errors == []

    def test_missing_fields(self):
        _, errors = validate_entry(1, json.dumps({"type": "owner"}))
        assert any("missing" in e for e in errors)

    def test_invalid_json(self):
        _, errors = validate_entry(1, "not json {")
        assert any("invalid JSON" in e for e in errors)

    def test_certain_without_external_source(self):
        _, errors = validate_entry(
            1,
            json.dumps(
                _valid_entry(confidence="certain", source="manual", verdict="SCAM")
            ),
        )
        assert any("certain" in e for e in errors)

    def test_certain_manual_allowed_for_clean(self):
        # Whitelist entries may use certain+manual
        _, errors = validate_entry(
            1,
            json.dumps(
                _valid_entry(confidence="certain", source="manual", verdict="CLEAN")
            ),
        )
        assert errors == []

    def test_certain_with_external_source(self):
        _, errors = validate_entry(
            1, json.dumps(_valid_entry(confidence="certain", source="wall-of-shames"))
        )
        assert errors == []

    def test_invalid_verdict(self):
        _, errors = validate_entry(1, json.dumps(_valid_entry(verdict="MAYBE")))
        assert any("verdict" in e for e in errors)

    def test_invalid_date(self):
        _, errors = validate_entry(1, json.dumps(_valid_entry(added="not-a-date")))
        assert any("date" in e for e in errors)

    def test_empty_note(self):
        _, errors = validate_entry(1, json.dumps(_valid_entry(note="")))
        assert any("note" in e for e in errors)

    def test_repo_without_slug(self):
        _, errors = validate_entry(
            1, json.dumps(_valid_entry(type="repo", slug=None, login=None))
        )
        assert any("slug" in e for e in errors)

    def test_slug_without_slash(self):
        _, errors = validate_entry(
            1, json.dumps(_valid_entry(type="repo", slug="noslash", login=None))
        )
        assert any("owner/repo" in e for e in errors)


class TestValidateFile:
    def test_valid_file(self, tmp_path):
        path = _write_seed(tmp_path, [_valid_entry(), _valid_entry(login="other-bad")])
        _, errors = validate_file(path)
        assert errors == []

    def test_comments_and_blanks_ignored(self, tmp_path):
        path = tmp_path / "seed.jsonl"
        path.write_text("# comment\n\n" + json.dumps(_valid_entry()))
        _, errors = validate_file(path)
        assert errors == []

    def test_duplicate_key_detected(self, tmp_path):
        path = _write_seed(tmp_path, [_valid_entry(), _valid_entry()])
        _, errors = validate_file(path)
        assert any("duplicate" in e for e in errors)

    def test_current_seed_is_valid(self):
        seed = Path(__file__).parents[1] / "data" / "seed.jsonl"
        _, errors = validate_file(seed)
        assert errors == [], f"Seed validation failed: {errors}"
