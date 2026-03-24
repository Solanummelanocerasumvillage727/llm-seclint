"""Tests for file discovery module."""

from __future__ import annotations

from pathlib import Path

from llm_seclint.core.file_discovery import discover_files


class TestDiscoverFiles:
    """Tests for discover_files function."""

    def test_discovers_py_files(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("print('hello')")
        (tmp_path / "utils.py").write_text("x = 1")
        (tmp_path / "readme.txt").write_text("docs")

        result = discover_files([tmp_path])

        names = [p.name for p in result]
        assert "app.py" in names
        assert "utils.py" in names
        assert "readme.txt" not in names

    def test_excludes_default_dirs(self, tmp_path: Path) -> None:
        for dirname in ("node_modules", ".git", "__pycache__", ".venv"):
            d = tmp_path / dirname
            d.mkdir()
            (d / "secret.py").write_text("x = 1")

        (tmp_path / "main.py").write_text("print(1)")

        result = discover_files([tmp_path])

        assert len(result) == 1
        assert result[0].name == "main.py"

    def test_custom_include_patterns(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("x")
        (tmp_path / "config.yml").write_text("key: val")

        result = discover_files([tmp_path], include_patterns=["*.yml"])

        names = [p.name for p in result]
        assert "config.yml" in names
        assert "app.py" not in names

    def test_custom_exclude_patterns(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("x")
        (tmp_path / "test_app.py").write_text("x")

        result = discover_files([tmp_path], exclude_patterns=["test_*.py"])

        names = [p.name for p in result]
        assert "app.py" in names
        assert "test_app.py" not in names

    def test_empty_directory(self, tmp_path: Path) -> None:
        result = discover_files([tmp_path])
        assert result == []

    def test_nonexistent_directory(self, tmp_path: Path) -> None:
        missing = tmp_path / "does_not_exist"
        result = discover_files([missing])
        assert result == []
