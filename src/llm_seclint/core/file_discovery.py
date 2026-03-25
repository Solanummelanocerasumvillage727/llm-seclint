"""File discovery for scanning targets."""

from __future__ import annotations

import fnmatch
from pathlib import Path


DEFAULT_EXCLUDE_DIRS: frozenset[str] = frozenset({
    "__pycache__",
    ".git",
    ".hg",
    ".svn",
    ".tox",
    ".venv",
    "venv",
    "env",
    ".eggs",
    "node_modules",
    "dist",
    "build",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "*.egg-info",
})

DEFAULT_INCLUDE_PATTERNS: list[str] = ["*.py"]

DEPENDENCY_FILE_NAMES: frozenset[str] = frozenset({
    "requirements.txt",
    "pyproject.toml",
    "setup.cfg",
})


def _is_dependency_filename(name: str) -> bool:
    """Check if a filename is a dependency file we should scan."""
    if name in DEPENDENCY_FILE_NAMES:
        return True
    # Also match requirements-dev.txt, requirements_prod.txt, etc.
    if name.startswith("requirements") and name.endswith(".txt"):
        return True
    return False


def discover_files(
    paths: list[Path],
    include_patterns: list[str] | None = None,
    exclude_patterns: list[str] | None = None,
    exclude_dirs: set[str] | None = None,
) -> list[Path]:
    """Discover files to scan from given paths.

    Args:
        paths: List of files or directories to scan.
        include_patterns: Glob patterns for files to include (default: *.py).
        exclude_patterns: Glob patterns for files to exclude.
        exclude_dirs: Directory names to skip.

    Returns:
        Sorted list of file paths to scan.
    """
    if include_patterns is None:
        include_patterns = DEFAULT_INCLUDE_PATTERNS
    if exclude_dirs is None:
        exclude_dirs = set(DEFAULT_EXCLUDE_DIRS)

    files: set[Path] = set()

    for path in paths:
        path = path.resolve()
        if path.is_file():
            if _matches_any(path.name, include_patterns):
                files.add(path)
        elif path.is_dir():
            for child in path.rglob("*"):
                if child.is_file() and _should_include(
                    child, include_patterns, exclude_patterns, exclude_dirs
                ):
                    files.add(child)

    return sorted(files)


def _should_include(
    path: Path,
    include_patterns: list[str],
    exclude_patterns: list[str] | None,
    exclude_dirs: set[str],
) -> bool:
    """Check whether a file should be included in the scan."""
    # Check if any parent directory is excluded
    for parent in path.parents:
        if parent.name in exclude_dirs:
            return False
        # Handle glob-style dir exclusions like *.egg-info
        for exc in exclude_dirs:
            if "*" in exc and fnmatch.fnmatch(parent.name, exc):
                return False

    # Check include patterns
    if not _matches_any(path.name, include_patterns):
        return False

    # Check exclude patterns
    if exclude_patterns and _matches_any(path.name, exclude_patterns):
        return False

    return True


def _matches_any(name: str, patterns: list[str]) -> bool:
    """Check if a filename matches any of the given glob patterns."""
    return any(fnmatch.fnmatch(name, pat) for pat in patterns)


def discover_dependency_files(
    paths: list[Path],
    exclude_dirs: set[str] | None = None,
) -> list[Path]:
    """Discover dependency files (requirements*.txt, pyproject.toml, setup.cfg).

    Args:
        paths: List of files or directories to scan.
        exclude_dirs: Directory names to skip.

    Returns:
        Sorted list of dependency file paths.
    """
    if exclude_dirs is None:
        exclude_dirs = set(DEFAULT_EXCLUDE_DIRS)

    files: set[Path] = set()

    for path in paths:
        path = path.resolve()
        if path.is_file():
            if _is_dependency_filename(path.name):
                files.add(path)
        elif path.is_dir():
            for child in path.rglob("*"):
                if child.is_file() and _is_dependency_filename(child.name):
                    # Check excluded dirs
                    skip = False
                    for parent in child.parents:
                        if parent.name in exclude_dirs:
                            skip = True
                            break
                        for exc in exclude_dirs:
                            if "*" in exc and fnmatch.fnmatch(parent.name, exc):
                                skip = True
                                break
                        if skip:
                            break
                    if not skip:
                        files.add(child)

    return sorted(files)
