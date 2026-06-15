"""Tests for bundled demo setup helpers."""

from pathlib import Path


def test_repo_root_detects_checkout_root():
    """The demo command should derive paths from the checkout, not CWD."""
    import cerno

    repo_root = cerno._repo_root()  # type: ignore[attr-defined]

    assert (repo_root / "pyproject.toml").is_file()
    assert (repo_root / "cerno.py").is_file()
    assert (repo_root / "cerno_pkg").is_dir()


def test_demo_assets_dir_is_independent_of_cwd(monkeypatch, tmp_path: Path):
    """Changing directories should not affect where demo assets are found."""
    import cerno

    monkeypatch.chdir(tmp_path)

    assets_dir = cerno._demo_assets_dir()  # type: ignore[attr-defined]

    assert assets_dir == cerno._repo_root() / "docs" / "demo"  # type: ignore[attr-defined]
    assert (assets_dir / "cerno-demo-initial.nessus").is_file()
    assert (assets_dir / "cerno-demo-expanded.nessus").is_file()


def test_demo_assets_dir_falls_back_to_packaged_assets(monkeypatch, tmp_path: Path):
    """Installed commands should find demo assets even without repository docs."""
    import cerno

    monkeypatch.setattr(cerno, "_repo_root", lambda: tmp_path)

    assets_dir = cerno._demo_assets_dir()  # type: ignore[attr-defined]

    assert "cerno_pkg" in assets_dir.parts
    assert (assets_dir / "cerno-demo-initial.nessus").is_file()
    assert (assets_dir / "cerno-demo-expanded.nessus").is_file()
    assert (assets_dir / "nxc-workspace" / "smb.db").is_file()
