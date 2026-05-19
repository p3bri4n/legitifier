import tomllib
from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_security_md_exists():
    assert (ROOT / "SECURITY.md").exists()


def test_dependencies_have_upper_bounds():
    data = tomllib.loads((ROOT / "pyproject.toml").read_text())
    for dep in data["project"]["dependencies"]:
        assert "<" in dep or "==" in dep, f"Dependency {dep!r} lacks upper bound"


def test_lockfile_exists():
    assert (ROOT / "requirements.lock").exists()
