"""Tests for LS010: Unpinned LLM dependency detection."""

from __future__ import annotations

from pathlib import Path

from llm_seclint.rules.python.dependency_pinning import UnpinnedLlmDependencyRule


def _rule() -> UnpinnedLlmDependencyRule:
    return UnpinnedLlmDependencyRule()


def _check(source: str, filename: str = "requirements.txt") -> list:
    rule = _rule()
    return rule.check_text(source, Path(filename))


class TestRequirementsTxt:
    """Tests for requirements.txt parsing."""

    def test_unpinned_litellm_triggers(self) -> None:
        source = "litellm>=1.64.0\n"
        findings = _check(source)
        assert len(findings) == 1
        assert findings[0].rule_id == "LS010"
        assert "litellm" in findings[0].message
        assert findings[0].line == 1

    def test_unpinned_openai_triggers(self) -> None:
        source = "openai>=1.0\n"
        findings = _check(source)
        assert len(findings) == 1
        assert findings[0].rule_id == "LS010"

    def test_unpinned_langchain_triggers(self) -> None:
        source = "langchain>=0.1\n"
        findings = _check(source)
        assert len(findings) == 1

    def test_exact_pin_safe(self) -> None:
        source = "litellm==1.82.2\n"
        findings = _check(source)
        assert len(findings) == 0

    def test_upper_bound_safe(self) -> None:
        source = "litellm>=1.64.0,<1.83\n"
        findings = _check(source)
        assert len(findings) == 0

    def test_compatible_release_safe(self) -> None:
        source = "litellm~=1.64.0\n"
        findings = _check(source)
        assert len(findings) == 0

    def test_non_llm_package_ignored(self) -> None:
        source = "requests>=2.0\n"
        findings = _check(source)
        assert len(findings) == 0

    def test_non_llm_package_flask_ignored(self) -> None:
        source = "flask>=2.0\ndjango>=4.0\n"
        findings = _check(source)
        assert len(findings) == 0

    def test_comment_lines_ignored(self) -> None:
        source = "# litellm>=1.64.0\n"
        findings = _check(source)
        assert len(findings) == 0

    def test_empty_lines_ignored(self) -> None:
        source = "\n\n\n"
        findings = _check(source)
        assert len(findings) == 0

    def test_multiple_deps_mixed(self) -> None:
        source = (
            "litellm>=1.64.0\n"
            "openai==1.30.0\n"
            "anthropic>=0.20\n"
            "requests>=2.0\n"
            "langchain>=0.1,<0.2\n"
        )
        findings = _check(source)
        # litellm and anthropic should trigger; openai is pinned,
        # requests is not LLM, langchain has upper bound
        assert len(findings) == 2
        pkg_names = [f.message for f in findings]
        assert any("litellm" in m for m in pkg_names)
        assert any("anthropic" in m for m in pkg_names)

    def test_extras_in_package_name(self) -> None:
        source = "litellm[proxy]>=1.64.0\n"
        findings = _check(source)
        assert len(findings) == 1

    def test_dspy_unpinned_triggers(self) -> None:
        """The actual attack vector: dspy used litellm>=1.64.0."""
        source = "dspy>=2.0\n"
        findings = _check(source)
        assert len(findings) == 1

    def test_option_flags_ignored(self) -> None:
        source = "-r base.txt\n--index-url https://pypi.org/simple\nlitellm>=1.0\n"
        findings = _check(source)
        assert len(findings) == 1
        assert findings[0].line == 3

    def test_requirements_dev_txt(self) -> None:
        """Should also work for requirements-dev.txt."""
        source = "litellm>=1.64.0\n"
        findings = _check(source, "requirements-dev.txt")
        assert len(findings) == 1

    def test_underscore_package_name(self) -> None:
        """Package names with underscores should match (PEP 503 normalisation)."""
        source = "langchain_core>=0.1\n"
        findings = _check(source)
        assert len(findings) == 1

    def test_inline_comment_preserved(self) -> None:
        source = "litellm>=1.64.0  # latest version\n"
        findings = _check(source)
        assert len(findings) == 1


class TestPyprojectToml:
    """Tests for pyproject.toml parsing."""

    def test_pep621_unpinned_triggers(self) -> None:
        source = (
            "[project]\n"
            "name = \"myproject\"\n"
            "dependencies = [\n"
            '    "litellm>=1.64.0",\n'
            "]\n"
        )
        findings = _check(source, "pyproject.toml")
        assert len(findings) == 1
        assert findings[0].rule_id == "LS010"
        assert "litellm" in findings[0].message

    def test_pep621_pinned_safe(self) -> None:
        source = (
            "[project]\n"
            "name = \"myproject\"\n"
            "dependencies = [\n"
            '    "litellm==1.82.2",\n'
            "]\n"
        )
        findings = _check(source, "pyproject.toml")
        assert len(findings) == 0

    def test_pep621_upper_bound_safe(self) -> None:
        source = (
            "[project]\n"
            "name = \"myproject\"\n"
            "dependencies = [\n"
            '    "litellm>=1.64.0,<1.83",\n'
            "]\n"
        )
        findings = _check(source, "pyproject.toml")
        assert len(findings) == 0

    def test_pep621_non_llm_ignored(self) -> None:
        source = (
            "[project]\n"
            "dependencies = [\n"
            '    "requests>=2.0",\n'
            "]\n"
        )
        findings = _check(source, "pyproject.toml")
        assert len(findings) == 0

    def test_poetry_style_unpinned_triggers(self) -> None:
        source = (
            "[tool.poetry.dependencies]\n"
            'litellm = ">=1.64.0"\n'
        )
        findings = _check(source, "pyproject.toml")
        assert len(findings) == 1
        assert "litellm" in findings[0].message

    def test_poetry_style_pinned_safe(self) -> None:
        source = (
            "[tool.poetry.dependencies]\n"
            'litellm = "==1.82.2"\n'
        )
        findings = _check(source, "pyproject.toml")
        assert len(findings) == 0

    def test_non_dependency_section_ignored(self) -> None:
        source = (
            "[tool.pytest.ini_options]\n"
            'litellm = ">=1.64.0"\n'
        )
        findings = _check(source, "pyproject.toml")
        assert len(findings) == 0

    def test_optional_dependencies_triggers(self) -> None:
        source = (
            "[project.optional-dependencies]\n"
            "llm = [\n"
            '    "openai>=1.0",\n'
            "]\n"
        )
        findings = _check(source, "pyproject.toml")
        assert len(findings) == 1

    def test_multiple_packages_in_pyproject(self) -> None:
        source = (
            "[project]\n"
            "dependencies = [\n"
            '    "litellm>=1.64.0",\n'
            '    "openai==1.30.0",\n'
            '    "anthropic>=0.20",\n'
            '    "flask>=2.0",\n'
            "]\n"
        )
        findings = _check(source, "pyproject.toml")
        # litellm and anthropic trigger; openai is pinned, flask is not LLM
        assert len(findings) == 2


class TestRuleMetadata:
    """Tests for rule metadata."""

    def test_rule_id(self) -> None:
        assert _rule().rule_id == "LS010"

    def test_rule_name(self) -> None:
        assert _rule().rule_name == "unpinned-llm-dependency"

    def test_severity(self) -> None:
        from llm_seclint.core.severity import Severity
        assert _rule().severity == Severity.HIGH

    def test_cwe_id(self) -> None:
        assert _rule().cwe_id == "CWE-1357"

    def test_description(self) -> None:
        assert "supply chain" in _rule().description.lower()
