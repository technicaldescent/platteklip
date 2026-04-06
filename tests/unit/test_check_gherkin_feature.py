# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

"""Tests for pre_commit_hooks.check_gherkin_feature.

Covers the custom exception hierarchy, data-class
construction, dialect loading, every diagnostic rule
(A1.4 through B2.1), the ``--fix`` indentation rewriter,
module-level helper functions, report formatting,
feature-file collection, and the CLI entry point.
"""

import json
import tempfile
import textwrap
import unittest
from io import StringIO
from pathlib import Path
from unittest import mock

import pytest

from pre_commit_hooks.check_gherkin_feature import (
    Block,
    DialectLoadError,
    DialectMatchers,
    DialectSchemaError,
    FileReadError,
    GherkinProLinter,
    Issue,
    LinterError,
    Scope,
    _collect_feature_paths,
    _indent_spaces,
    _languages_from_file,
    _LintState,
    _print_diagnostics,
    _read_feature_file,
    _report_results,
    _split_by_severity,
    main,
)

# ------------------------------------------------------------------
# Minimal English dialect for test fixtures
# ------------------------------------------------------------------

_EN_DIALECT: dict[str, list[str] | str] = {
    "feature": ["Feature"],
    "rule": ["Rule"],
    "background": ["Background"],
    "scenario": ["Scenario", "Example"],
    "scenarioOutline": [
        "Scenario Outline",
        "Scenario Template",
    ],
    "examples": ["Examples", "Scenarios"],
    "given": ["Given "],
    "when": ["When "],
    "then": ["Then "],
    "and": ["And "],
    "but": ["But "],
    "name": "English",
    "native": "English",
}


class _FeatureFileFixture:
    """Context manager providing a feature file and languages JSON."""

    def __init__(
        self,
        feature_text: str,
        *,
        dialects: dict[str, object] | None = None,
    ) -> None:
        """Initialize with feature text and optional dialects."""
        self._feature_text = textwrap.dedent(
            feature_text,
        )
        self._dialects = dialects or {
            "en": _EN_DIALECT,
        }
        self._tmpdir: tempfile.TemporaryDirectory[str] | None = None

    def __enter__(self) -> tuple[str, str]:
        """Create temp directory with fixture files."""
        self._tmpdir = tempfile.TemporaryDirectory()
        base = Path(self._tmpdir.name)

        lang_path = base / "gherkin-languages.json"
        lang_path.write_text(
            json.dumps(self._dialects),
            encoding="utf-8",
        )

        feat_path = base / "test.feature"
        feat_path.write_text(
            self._feature_text,
            encoding="utf-8",
        )

        return str(feat_path), str(lang_path)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        """Clean up temp directory."""
        if self._tmpdir is not None:
            self._tmpdir.cleanup()


def _lint(
    feature_text: str,
    *,
    strict: bool = False,
    fix: bool = False,
    dialects: dict[str, object] | None = None,
) -> tuple[list[Issue], GherkinProLinter]:
    """Lint *feature_text* and return (issues, linter)."""
    with _FeatureFileFixture(
        feature_text,
        dialects=dialects,
    ) as (feat_path, lang_path):
        linter = GherkinProLinter(
            lang_path,
            strict=strict,
            fix=fix,
        )
        linter.lint_file(feat_path)
        return list(linter.issues), linter


def _codes(issues: list[Issue]) -> list[str]:
    """Extract diagnostic codes from issues."""
    return [i.code for i in issues]


def _errors(issues: list[Issue]) -> list[Issue]:
    """Filter to error-level issues."""
    return [i for i in issues if i.kind == "ERR"]


def _warnings(issues: list[Issue]) -> list[Issue]:
    """Filter to warning-level issues."""
    return [i for i in issues if i.kind == "WARN"]


# ==================================================================
# Exception hierarchy
# ==================================================================


class TestExceptionHierarchy(unittest.TestCase):
    """Verify the custom exception class relationships."""

    def test_linter_error_is_base(self) -> None:
        """LinterError inherits from Exception."""
        assert issubclass(LinterError, Exception)

    def test_load_error_derives_from_base(self) -> None:
        """DialectLoadError inherits from LinterError."""
        assert issubclass(
            DialectLoadError,
            LinterError,
        )

    def test_dialect_schema_error_inherits(
        self,
    ) -> None:
        """DialectSchemaError inherits from LinterError."""
        assert issubclass(
            DialectSchemaError,
            LinterError,
        )

    def test_file_read_error_inherits(self) -> None:
        """FileReadError inherits from LinterError."""
        assert issubclass(
            FileReadError,
            LinterError,
        )

    def test_linter_error_catchall(self) -> None:
        """All custom exceptions caught by LinterError."""
        for cls in (
            DialectLoadError,
            DialectSchemaError,
            FileReadError,
        ):
            with pytest.raises(LinterError):
                raise cls("test")


# ==================================================================
# Data classes
# ==================================================================


class TestIssue(unittest.TestCase):
    """Verify Issue construction and rendering."""

    def test_render_error(self) -> None:
        """Error-level issue renders with ERR prefix."""
        issue = Issue(
            "ERR",
            "a.feature",
            "10",
            "A2.1",
            "msg",
        )
        assert issue.render() == ("ERR: a.feature:10: A2.1 msg")

    def test_render_warning_at_eof(self) -> None:
        """Warning at EOF renders with WARN prefix."""
        issue = Issue(
            "WARN",
            "b.feature",
            "EOF",
            "B2.1",
            "detail",
        )
        assert "WARN" in issue.render()
        assert "EOF" in issue.render()

    def test_slots(self) -> None:
        """Issue uses __slots__."""
        issue = Issue("ERR", "x", "1", "A1.4", "m")
        with pytest.raises(AttributeError):
            issue.extra = True  # type: ignore[attr-defined]


class TestScope(unittest.TestCase):
    """Verify Scope defaults."""

    def test_defaults(self) -> None:
        """New Scope has sensible defaults."""
        scope = Scope("feature", indent=0)
        assert not scope.background_defined
        assert scope.background_steps == set()
        assert not scope.scenarios_seen


class TestBlock(unittest.TestCase):
    """Verify Block defaults."""

    def test_defaults(self) -> None:
        """New Block has sensible defaults."""
        block = Block(kind="scenario", indent=2)
        assert not block.examples_seen
        assert block.step_count == 0
        assert block.step_texts == set()


class TestLintState(unittest.TestCase):
    """Verify _LintState scope resolution."""

    def test_resolve_scope_drops_rule(self) -> None:
        """Clear Rule scope when indent returns to zero."""
        state = _LintState()
        state.feature_scope = Scope(
            "feature",
            indent=0,
        )
        state.rule_scope = Scope("rule", indent=2)
        state.resolve_scope(indent=0)
        assert state.rule_scope is None

    def test_resolve_scope_keeps_rule(self) -> None:
        """Retain Rule scope when indent is deeper."""
        state = _LintState()
        state.rule_scope = Scope("rule", indent=2)
        state.resolve_scope(indent=4)
        assert state.rule_scope is not None

    def test_active_scope_prefers_rule(self) -> None:
        """Return Rule when both scopes exist."""
        state = _LintState()
        state.feature_scope = Scope(
            "feature",
            indent=0,
        )
        state.rule_scope = Scope("rule", indent=2)
        assert state.active_scope() == state.rule_scope

    def test_active_scope_falls_back(self) -> None:
        """Return Feature when no Rule exists."""
        state = _LintState()
        state.feature_scope = Scope(
            "feature",
            indent=0,
        )
        assert state.active_scope() == state.feature_scope

    def test_active_scope_none(self) -> None:
        """Return None when no scopes exist."""
        state = _LintState()
        assert state.active_scope() is None

    def test_resolve_scope_no_rule(self) -> None:
        """Do nothing when no Rule scope exists."""
        state = _LintState()
        state.resolve_scope(indent=0)
        assert state.rule_scope is None


# ==================================================================
# DialectMatchers
# ==================================================================


class TestDialectMatchers(unittest.TestCase):
    """Verify DialectMatchers construction."""

    def test_from_valid_dialect(self) -> None:
        """Valid dialect produces keyword lists."""
        matchers = DialectMatchers.from_dialect(
            _EN_DIALECT,
        )
        assert "Feature" in matchers.feature
        assert "Given " in matchers.given

    def test_keywords_sorted_longest_first(
        self,
    ) -> None:
        """Keywords sorted longest-first for matching."""
        matchers = DialectMatchers.from_dialect(
            _EN_DIALECT,
        )
        for kw_list in (
            matchers.feature,
            matchers.scenario,
            matchers.outline,
            matchers.examples,
        ):
            lengths = [len(k) for k in kw_list]
            assert lengths == sorted(
                lengths,
                reverse=True,
            )

    def test_missing_key_raises(self) -> None:
        """Missing dialect key raises DialectSchemaError."""
        broken: dict[str, object] = dict(
            _EN_DIALECT,
        )
        del broken["feature"]
        with pytest.raises(DialectSchemaError):
            DialectMatchers.from_dialect(broken)

    def test_non_list_value_raises(self) -> None:
        """Non-list value raises DialectSchemaError."""
        broken: dict[str, object] = dict(
            _EN_DIALECT,
        )
        broken["feature"] = "Feature"
        with pytest.raises(DialectSchemaError):
            DialectMatchers.from_dialect(broken)

    def test_empty_strings_discarded(self) -> None:
        """Empty strings in keyword lists are discarded."""
        dialect: dict[str, list[str] | str] = dict(
            _EN_DIALECT,
        )
        dialect["feature"] = ["Feature", "", "  "]
        matchers = DialectMatchers.from_dialect(
            dialect,
        )
        assert "" not in matchers.feature


# ==================================================================
# Module-level helpers
# ==================================================================


class TestIndentSpaces(unittest.TestCase):
    """Verify _indent_spaces."""

    def test_positive(self) -> None:
        """Positive argument produces spaces."""
        assert _indent_spaces(4) == "    "

    def test_zero(self) -> None:
        """Zero argument produces empty string."""
        assert _indent_spaces(0) == ""

    def test_negative_floors_to_zero(self) -> None:
        """Negative argument floored to zero."""
        assert _indent_spaces(-3) == ""


class TestLanguagesFromFile(unittest.TestCase):
    """Verify _languages_from_file directly."""

    def test_valid_file(self) -> None:
        """Load a valid languages file."""
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            delete=False,
        ) as tmp:
            json.dump({"en": _EN_DIALECT}, tmp)
            tmp.flush()
            result = _languages_from_file(tmp.name)
            assert "en" in result
            Path(tmp.name).unlink()

    def test_missing_file_raises(self) -> None:
        """Missing file raises DialectLoadError."""
        with pytest.raises(DialectLoadError):
            _languages_from_file("/nonexistent.json")

    def test_invalid_json_raises(self) -> None:
        """Malformed JSON raises DialectLoadError."""
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            delete=False,
        ) as tmp:
            tmp.write("{not valid")
            tmp.flush()
            with pytest.raises(DialectLoadError):
                _languages_from_file(tmp.name)
            Path(tmp.name).unlink()

    def test_missing_en_raises(self) -> None:
        """Missing en key raises DialectSchemaError."""
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            delete=False,
        ) as tmp:
            json.dump({"fr": _EN_DIALECT}, tmp)
            tmp.flush()
            with pytest.raises(DialectSchemaError):
                _languages_from_file(tmp.name)
            Path(tmp.name).unlink()


class TestReadFeatureFile(unittest.TestCase):
    """Verify _read_feature_file directly."""

    def test_reads_lines(self) -> None:
        """Return lines from a valid file."""
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".feature",
            delete=False,
        ) as tmp:
            tmp.write("Feature: Test\n")
            tmp.flush()
            lines = _read_feature_file(tmp.name)
            assert len(lines) == 1
            assert "Feature" in lines[0]
            Path(tmp.name).unlink()

    def test_missing_file_raises(self) -> None:
        """Missing file raises FileReadError."""
        with pytest.raises(FileReadError):
            _read_feature_file("/nonexistent.feature")


class TestCollectFeaturePaths(unittest.TestCase):
    """Verify _collect_feature_paths."""

    def test_directory_recursion(self) -> None:
        """Recursively find .feature files."""
        with tempfile.TemporaryDirectory() as d:
            sub = Path(d) / "sub"
            sub.mkdir()
            (sub / "a.feature").write_text(
                "Feature: A\n",
            )
            (sub / "b.txt").write_text("not a feature")
            result = _collect_feature_paths([d])
            assert len(result) == 1
            assert result[0].endswith(".feature")

    def test_single_file(self) -> None:
        """Accept a single .feature file."""
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "test.feature"
            f.write_text("Feature: T\n")
            result = _collect_feature_paths([str(f)])
            assert len(result) == 1

    def test_nonexistent_skipped(self) -> None:
        """Skip nonexistent paths silently."""
        result = _collect_feature_paths(
            ["/nonexistent/test.feature"],
        )
        assert result == []

    def test_non_feature_file_skipped(self) -> None:
        """Skip non-.feature files."""
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "test.txt"
            f.write_text("not a feature")
            result = _collect_feature_paths([str(f)])
            assert result == []

    def test_empty_targets(self) -> None:
        """Return empty list for no targets."""
        assert _collect_feature_paths([]) == []


class TestSplitBySeverity(unittest.TestCase):
    """Verify _split_by_severity."""

    def test_splits_correctly(self) -> None:
        """Separate errors from warnings."""
        issues = [
            Issue(
                "ERR",
                "f",
                "1",
                "A1",
                "err",
            ),
            Issue(
                "WARN",
                "f",
                "2",
                "B1",
                "warn",
            ),
            Issue(
                "ERR",
                "f",
                "3",
                "A2",
                "err2",
            ),
        ]
        errs, warns = _split_by_severity(issues)
        assert len(errs) == 2
        assert len(warns) == 1

    def test_empty_list(self) -> None:
        """Handle empty issue list."""
        errs, warns = _split_by_severity([])
        assert errs == []
        assert warns == []


class TestPrintDiagnostics(unittest.TestCase):
    """Verify _print_diagnostics output."""

    def test_prints_to_stdout(self) -> None:
        """Print all diagnostics to stdout."""
        errs = [
            Issue(
                "ERR",
                "f",
                "1",
                "A1",
                "error",
            ),
        ]
        warns = [
            Issue(
                "WARN",
                "f",
                "2",
                "B1",
                "warning",
            ),
        ]
        with mock.patch(
            "sys.stdout",
            new_callable=StringIO,
        ) as out:
            _print_diagnostics(errs, warns)
            output = out.getvalue()
        assert "ERR" in output
        assert "WARN" in output


class TestReportResults(unittest.TestCase):
    """Verify _report_results exit codes."""

    def _make_linter(self) -> GherkinProLinter:
        """Build a linter with valid languages."""
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            delete=False,
        ) as tmp:
            json.dump({"en": _EN_DIALECT}, tmp)
            tmp.flush()
            linter = GherkinProLinter(tmp.name)
            Path(tmp.name).unlink()
            return linter

    def test_success_returns_zero(self) -> None:
        """Return 0 with no issues."""
        linter = self._make_linter()
        with mock.patch(
            "sys.stdout",
            new_callable=StringIO,
        ):
            code = _report_results(
                linter,
                1,
                strict=False,
            )
        assert code == 0

    def test_errors_return_one(self) -> None:
        """Return 1 with errors."""
        linter = self._make_linter()
        linter.issues.append(
            Issue("ERR", "f", "1", "A1", "err"),
        )
        with mock.patch(
            "sys.stdout",
            new_callable=StringIO,
        ):
            code = _report_results(
                linter,
                1,
                strict=False,
            )
        assert code == 1

    def test_strict_promotes_warnings(self) -> None:
        """Return 1 when strict and only warnings."""
        linter = self._make_linter()
        linter.issues.append(
            Issue("WARN", "f", "1", "B1", "warn"),
        )
        with mock.patch(
            "sys.stdout",
            new_callable=StringIO,
        ):
            code = _report_results(
                linter,
                1,
                strict=True,
            )
        assert code == 1

    def test_warnings_without_strict_pass(
        self,
    ) -> None:
        """Return 0 when not strict and only warnings."""
        linter = self._make_linter()
        linter.issues.append(
            Issue("WARN", "f", "1", "B1", "warn"),
        )
        with mock.patch(
            "sys.stdout",
            new_callable=StringIO,
        ):
            code = _report_results(
                linter,
                1,
                strict=False,
            )
        assert code == 0


# ==================================================================
# lint_file return value
# ==================================================================


class TestLintFileReturnValue(unittest.TestCase):
    """Verify lint_file returns True/False correctly."""

    def test_returns_true_on_clean(self) -> None:
        """Return True for an error-free file."""
        with _FeatureFileFixture("""\
            Feature: Clean
              Scenario: A
                Given a step
        """) as (feat_path, lang_path):
            linter = GherkinProLinter(lang_path)
            result = linter.lint_file(feat_path)
        assert result is True

    def test_returns_false_on_error(self) -> None:
        """Return False when errors are found."""
        with _FeatureFileFixture("""\
            Feature: Bad
              Feature: Duplicate
        """) as (feat_path, lang_path):
            linter = GherkinProLinter(lang_path)
            result = linter.lint_file(feat_path)
        assert result is False


# ==================================================================
# Linter initialisation
# ==================================================================


class TestLinterInit(unittest.TestCase):
    """Verify GherkinProLinter construction."""

    def test_valid_init(self) -> None:
        """Valid languages file initialises cleanly."""
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            delete=False,
        ) as tmp:
            json.dump({"en": _EN_DIALECT}, tmp)
            tmp.flush()
            linter = GherkinProLinter(tmp.name)
            assert "en" in linter.all_languages
            Path(tmp.name).unlink()

    def test_missing_file_raises(self) -> None:
        """Missing file raises DialectLoadError."""
        with pytest.raises(DialectLoadError):
            GherkinProLinter("/nonexistent/path.json")

    def test_invalid_json_raises(self) -> None:
        """Malformed JSON raises DialectLoadError."""
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            delete=False,
        ) as tmp:
            tmp.write("{not valid json")
            tmp.flush()
            with pytest.raises(DialectLoadError):
                GherkinProLinter(tmp.name)
            Path(tmp.name).unlink()

    def test_missing_en_dialect_raises(self) -> None:
        """Missing en key raises DialectSchemaError."""
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            delete=False,
        ) as tmp:
            json.dump({"fr": _EN_DIALECT}, tmp)
            tmp.flush()
            with pytest.raises(DialectSchemaError):
                GherkinProLinter(tmp.name)
            Path(tmp.name).unlink()


class TestLintFileReadError(unittest.TestCase):
    """Verify unreadable files raise FileReadError."""

    def test_nonexistent_feature_file(self) -> None:
        """Missing feature file raises FileReadError."""
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            delete=False,
        ) as tmp:
            json.dump({"en": _EN_DIALECT}, tmp)
            tmp.flush()
            linter = GherkinProLinter(tmp.name)
            with pytest.raises(FileReadError):
                linter.lint_file(
                    "/nonexistent/test.feature",
                )
            Path(tmp.name).unlink()


# ==================================================================
# Diagnostic rules — errors
# ==================================================================


class TestRuleA1_4(unittest.TestCase):
    """A1.4: Non-blank line must start with a keyword."""

    def test_unrecognised_line(self) -> None:
        """Unrecognised line triggers A1.4."""
        issues, _ = _lint("""\
            Feature: Login
              Scenario: Valid
                Given a user exists
                This is not a keyword line
        """)
        assert "A1.4" in _codes(issues)

    def test_valid_lines_pass(self) -> None:
        """All-keyword file produces no A1.4."""
        issues, _ = _lint("""\
            Feature: Login
              Scenario: Valid
                Given a user exists
                When the user logs in
                Then the dashboard loads
        """)
        assert "A1.4" not in _codes(issues)


class TestRuleA1_5(unittest.TestCase):
    """A1.5: Step keywords must not use a colon."""

    def test_given_with_colon(self) -> None:
        """Given with colon triggers A1.5."""
        issues, _ = _lint("""\
            Feature: Login
              Scenario: Bad
                Given: a user exists
        """)
        assert "A1.5" in _codes(issues)

    def test_when_with_colon(self) -> None:
        """When with colon triggers A1.5."""
        issues, _ = _lint("""\
            Feature: Login
              Scenario: Bad
                When: the user logs in
        """)
        assert "A1.5" in _codes(issues)

    def test_then_with_colon(self) -> None:
        """Then with colon triggers A1.5."""
        issues, _ = _lint("""\
            Feature: Login
              Scenario: Bad
                Then: the user sees home
        """)
        assert "A1.5" in _codes(issues)

    def test_star_with_colon(self) -> None:
        """Star with colon triggers A1.5."""
        issues, _ = _lint("""\
            Feature: Login
              Scenario: Bad
                Given a user exists
                *: something
        """)
        assert "A1.5" in _codes(issues)


class TestRuleA2_1(unittest.TestCase):
    """A2.1: Feature must be first with text."""

    def test_scenario_before_feature(self) -> None:
        """Scenario before Feature triggers A2.1."""
        issues, _ = _lint("""\
            Scenario: Orphan
              Given something
        """)
        assert "A2.1" in _codes(issues)

    def test_feature_without_name(self) -> None:
        """Empty Feature name triggers A2.1."""
        issues, _ = _lint("""\
            Feature:
              Scenario: Valid
                Given something
        """)
        assert "A2.1" in _codes(issues)

    def test_step_before_feature(self) -> None:
        """Step before Feature triggers A2.1."""
        issues, _ = _lint("""\
            Given something
            Feature: Late
        """)
        assert "A2.1" in _codes(issues)


class TestRuleA2_2(unittest.TestCase):
    """A2.2: Only one Feature per file."""

    def test_two_features(self) -> None:
        """Second Feature triggers A2.2."""
        issues, _ = _lint("""\
            Feature: First
              Scenario: A
                Given a step
            Feature: Second
              Scenario: B
                Given a step
        """)
        assert "A2.2" in _codes(issues)


class TestRuleA4_0(unittest.TestCase):
    """A4.0: Scenario inside Feature or Rule."""

    def test_scenario_before_feature_scope(
        self,
    ) -> None:
        """Scenario outside Feature triggers error."""
        issues, _ = _lint("""\
            Scenario: Orphan
              Given a step
        """)
        assert len(_errors(issues)) > 0


class TestRuleA4_1(unittest.TestCase):
    """A4.1: Step outside Scenario or Background."""

    def test_step_directly_under_feature(self) -> None:
        """Step outside any block triggers A4.1."""
        issues, _ = _lint("""\
            Feature: Dangling step
              Given a step outside any scenario
        """)
        assert "A4.1" in _codes(issues)


class TestRuleA4_5(unittest.TestCase):
    """A4.5: Duplicate step text."""

    def test_duplicate_step(self) -> None:
        """Repeated step text triggers A4.5."""
        issues, _ = _lint("""\
            Feature: Dups
              Scenario: Dup steps
                Given a user exists
                When the user logs in
                Then a user exists
        """)
        assert "A4.5" in _codes(issues)

    def test_unique_steps_pass(self) -> None:
        """Unique steps produce no A4.5."""
        issues, _ = _lint("""\
            Feature: Unique
              Scenario: All different
                Given a user exists
                When the user logs in
                Then the dashboard loads
        """)
        assert "A4.5" not in _codes(issues)


class TestRuleA5(unittest.TestCase):
    """A5.*: Background rules."""

    def test_background_before_feature(self) -> None:
        """Background outside Feature triggers error."""
        issues, _ = _lint("""\
            Background: Orphan
              Given a step
        """)
        assert len(_errors(issues)) > 0

    def test_background_after_scenario(self) -> None:
        """Background after Scenario triggers A5.1."""
        issues, _ = _lint("""\
            Feature: Late background
              Scenario: First
                Given a step
              Background: Too late
                Given another step
        """)
        assert "A5.1" in _codes(issues)

    def test_when_in_background(self) -> None:
        """When in Background triggers A5.2."""
        issues, _ = _lint("""\
            Feature: Bad
              Background: Setup
                Given a user exists
                When the user acts
        """)
        assert "A5.2" in _codes(issues)

    def test_given_like_allowed(self) -> None:
        """Given/And/But/* are valid in Background."""
        issues, _ = _lint("""\
            Feature: Good
              Background: Setup
                Given a user exists
                And the user is active
                But the user is not admin
                * the user has a profile
              Scenario: Test
                When the user logs in
                Then success
        """)
        assert "A5.2" not in _codes(issues)

    def test_two_backgrounds(self) -> None:
        """Second Background triggers A5.3."""
        issues, _ = _lint("""\
            Feature: Double
              Background: First
                Given a step
              Background: Second
                Given another step
        """)
        assert "A5.3" in _codes(issues)


class TestRuleA6(unittest.TestCase):
    """A6.*: Outline and Examples rules."""

    def test_outline_without_examples(self) -> None:
        """Outline without Examples triggers A6.3."""
        issues, _ = _lint("""\
            Feature: Missing
              Scenario Outline: No table
                Given a <thing>
        """)
        assert "A6.3" in _codes(issues)

    def test_examples_outside_outline(self) -> None:
        """Examples under Scenario triggers A6.3."""
        issues, _ = _lint("""\
            Feature: Misplaced
              Scenario: Not an outline
                Given a step
              Examples: Orphan
                | col |
                | val |
        """)
        assert "A6.3" in _codes(issues)

    def test_outline_with_examples_passes(
        self,
    ) -> None:
        """Outline with Examples produces no A6.3."""
        issues, _ = _lint("""\
            Feature: Valid
              Scenario Outline: With table
                Given a <thing>
              Examples:
                | thing |
                | apple |
        """)
        assert "A6.3" not in _codes(issues)

    def test_empty_examples(self) -> None:
        """Empty Examples triggers A6.4 warning."""
        issues, _ = _lint("""\
            Feature: Empty
              Scenario Outline: Outline
                Given a <thing>
              Examples:
        """)
        assert "A6.4" in _codes(_warnings(issues))

    def test_examples_end_at_next_heading(
        self,
    ) -> None:
        """Empty Examples detected at next heading."""
        issues, _ = _lint("""\
            Feature: Boundary
              Scenario Outline: First
                Given a <thing>
              Examples:
              Scenario: Next
                Given a step
        """)
        assert "A6.4" in _codes(_warnings(issues))


class TestRuleA7(unittest.TestCase):
    """A7.*: Doc Strings and Data Tables."""

    def test_docstring_not_under_step(self) -> None:
        """Orphan doc string triggers A7.1."""
        issues, _ = _lint("""\
            Feature: Bad
              Scenario: Test
                Given a step
                \"\"\"
                content
                \"\"\"
                \"\"\"
                orphan docstring
                \"\"\"
        """)
        assert "A7.1" in _codes(issues)

    def test_docstring_under_step_passes(
        self,
    ) -> None:
        """Doc string under a step produces no A7.1."""
        issues, _ = _lint("""\
            Feature: Good
              Scenario: Test
                Given a step
                \"\"\"
                some content
                \"\"\"
                When another step
                Then a result
        """)
        assert "A7.1" not in _codes(issues)

    def test_backtick_docstring(self) -> None:
        """Backtick doc string under a step is valid."""
        issues, _ = _lint("""\
            Feature: Backtick
              Scenario: Test
                Given a step
                ```json
                {"key": "value"}
                ```
                When another step
                Then a result
        """)
        assert "A7.1" not in _codes(issues)

    def test_table_not_under_step(self) -> None:
        """Orphan table row triggers A7.4."""
        issues, _ = _lint("""\
            Feature: Bad
              Scenario: Test
                | orphan | table |
        """)
        assert "A7.4" in _codes(issues)

    def test_table_under_step_passes(self) -> None:
        """Data table under a step produces no A7.4."""
        issues, _ = _lint("""\
            Feature: Good
              Scenario: Test
                Given the following users
                  | name  | role  |
                  | Alice | admin |
                When something
                Then result
        """)
        assert "A7.4" not in _codes(issues)

    def test_multi_row_data_table(self) -> None:
        """Multiple data table rows are valid."""
        issues, _ = _lint("""\
            Feature: Multi-row
              Scenario: Test
                Given users exist
                  | name  | role    |
                  | Alice | admin   |
                  | Bob   | viewer  |
                  | Carol | editor  |
                When something
                Then result
        """)
        assert "A7.4" not in _codes(issues)

    def test_docstring_interior_preserved(
        self,
    ) -> None:
        """Non-delimiter interior lines are consumed."""
        issues, _ = _lint("""\
            Feature: Interior
              Scenario: Test
                Given a step
                \"\"\"
                line one
                line two
                not a keyword
                \"\"\"
                When another step
                Then a result
        """)
        assert "A1.4" not in _codes(issues)


class TestRuleA8_1(unittest.TestCase):
    """A8.1: Language header on first line only."""

    def test_language_on_second_line(self) -> None:
        """Language on line two triggers A8.1."""
        issues, _ = _lint("""\
            # some comment
            # language: en
            Feature: Test
              Scenario: A
                Given a step
        """)
        assert "A8.1" in _codes(issues)

    def test_language_on_first_line_passes(
        self,
    ) -> None:
        """Language on line one produces no A8.1."""
        issues, _ = _lint("""\
            # language: en
            Feature: Test
              Scenario: A
                Given a step
        """)
        assert "A8.1" not in _codes(issues)


class TestRuleB2_1(unittest.TestCase):
    """B2.1: Scenario step count warning."""

    def test_six_steps_warns(self) -> None:
        """Six steps triggers B2.1 warning."""
        issues, _ = _lint("""\
            Feature: Long
              Scenario: Six steps
                Given step one
                And step two
                And step three
                When step four
                And step five
                Then step six
        """)
        assert "B2.1" in _codes(_warnings(issues))

    def test_five_steps_no_warning(self) -> None:
        """Five steps produces no B2.1."""
        issues, _ = _lint("""\
            Feature: OK
              Scenario: Five steps
                Given step one
                And step two
                When step three
                Then step four
                And step five
        """)
        assert "B2.1" not in _codes(issues)


# ==================================================================
# Passing features
# ==================================================================


class TestWellFormedFeatures(unittest.TestCase):
    """Ensure well-formed files produce zero errors."""

    def test_minimal_feature(self) -> None:
        """Minimal valid feature produces no errors."""
        issues, _ = _lint("""\
            Feature: Minimal
              Scenario: One step
                Given a step
        """)
        assert _errors(issues) == []

    def test_full_feature(self) -> None:
        """Complete feature with all constructs passes."""
        issues, _ = _lint("""\
            Feature: Complete example
              As a user I want to test everything.

              Background: Common setup
                Given a database is running
                And a user exists

              Scenario: Login
                Given the login page is open
                When the user submits credentials
                Then the dashboard is shown

              Scenario Outline: Search
                Given a query <query>
                When the user searches
                Then <count> results appear
              Examples:
                | query  | count |
                | apple  | 5     |
                | banana | 3     |
        """)
        assert _errors(issues) == []

    def test_feature_with_rule(self) -> None:
        """Feature with Rule passes."""
        issues, _ = _lint("""\
            Feature: With Rule
              Rule: Business rule A
                Scenario: Under rule
                  Given a step
                  When an action
                  Then a result
        """)
        assert _errors(issues) == []

    def test_empty_file_passes(self) -> None:
        """Empty file produces no issues."""
        issues, _ = _lint("")
        assert issues == []

    def test_bom_handling(self) -> None:
        """UTF-8 BOM does not break parsing."""
        issues, _ = _lint("""\
            \ufeffFeature: BOM test
              Scenario: A
                Given a step
        """)
        assert _errors(issues) == []

    def test_description_lines(self) -> None:
        """Free-form description under Feature passes."""
        issues, _ = _lint("""\
            Feature: Description test
              This is the feature description.
              It can span multiple lines.

              Scenario: Also described
                This describes the scenario.
                Given a step
                When an action
                Then a result
        """)
        assert _errors(issues) == []

    def test_multiple_scenarios(self) -> None:
        """Multiple scenarios in one feature are valid."""
        issues, _ = _lint("""\
            Feature: Multiple
              Scenario: First
                Given step a
                When action a
                Then result a
              Scenario: Second
                Given step b
                When action b
                Then result b
        """)
        assert _errors(issues) == []


# ==================================================================
# Background duplicate detection
# ==================================================================


class TestBackgroundDuplicateDetection(
    unittest.TestCase,
):
    """Background steps count for duplicate detection."""

    def test_scenario_repeating_background(
        self,
    ) -> None:
        """Step from Background triggers A4.5."""
        issues, _ = _lint("""\
            Feature: Dup across background
              Background: Setup
                Given a user exists
              Scenario: Test
                Given a user exists
                When action
                Then result
        """)
        assert "A4.5" in _codes(issues)

    def test_different_steps_pass(self) -> None:
        """Distinct steps across Background pass."""
        issues, _ = _lint("""\
            Feature: No dups
              Background: Setup
                Given a database is running
              Scenario: Test
                Given a user exists
                When action
                Then result
        """)
        assert "A4.5" not in _codes(issues)


# ==================================================================
# Fix mode
# ==================================================================


class TestFixMode(unittest.TestCase):
    """Verify --fix rewrites indentation correctly."""

    def test_feature_reindented_to_zero(self) -> None:
        """Feature heading at column zero."""
        with _FeatureFileFixture("""\
                Feature: Indented
                  Scenario: Test
                    Given a step
        """) as (feat_path, lang_path):
            linter = GherkinProLinter(
                lang_path,
                fix=True,
            )
            linter.lint_file(feat_path)
            result = Path(feat_path).read_text(
                encoding="utf-8",
            )
            assert result.startswith("Feature:")

    def test_scenario_indented_to_two(self) -> None:
        """Scenario heading at column two."""
        with _FeatureFileFixture("""\
            Feature: Test
                    Scenario: Misindented
                      Given a step
        """) as (feat_path, lang_path):
            linter = GherkinProLinter(
                lang_path,
                fix=True,
            )
            linter.lint_file(feat_path)
            lines = (
                Path(feat_path)
                .read_text(
                    encoding="utf-8",
                )
                .splitlines()
            )
            scenario = next(ln for ln in lines if "Scenario:" in ln)
            indent = len(scenario) - len(
                scenario.lstrip(),
            )
            assert indent == 2

    def test_steps_indented_to_four(self) -> None:
        """Steps at column four."""
        with _FeatureFileFixture("""\
            Feature: Test
              Scenario: Steps
            Given a step
        """) as (feat_path, lang_path):
            linter = GherkinProLinter(
                lang_path,
                fix=True,
            )
            linter.lint_file(feat_path)
            lines = (
                Path(feat_path)
                .read_text(
                    encoding="utf-8",
                )
                .splitlines()
            )
            step = next(ln for ln in lines if "Given" in ln)
            indent = len(step) - len(step.lstrip())
            assert indent == 4

    def test_rule_level_indentation(self) -> None:
        """Under Rule: scenarios at 4, steps at 6."""
        with _FeatureFileFixture("""\
            Feature: Rule indent
              Rule: A rule
                  Scenario: Under rule
                  Given a step
        """) as (feat_path, lang_path):
            linter = GherkinProLinter(
                lang_path,
                fix=True,
            )
            linter.lint_file(feat_path)
            lines = (
                Path(feat_path)
                .read_text(
                    encoding="utf-8",
                )
                .splitlines()
            )
            scenario = next(ln for ln in lines if "Scenario:" in ln)
            step = next(ln for ln in lines if "Given" in ln)
            assert len(scenario) - len(scenario.lstrip()) == 4
            assert len(step) - len(step.lstrip()) == 6

    def test_tag_under_rule(self) -> None:
        """Tags under Rule indented to 4."""
        with _FeatureFileFixture("""\
            Feature: Tag rule
              Rule: A rule
            @smoke
                Scenario: Under rule
                  Given a step
        """) as (feat_path, lang_path):
            linter = GherkinProLinter(
                lang_path,
                fix=True,
            )
            linter.lint_file(feat_path)
            lines = (
                Path(feat_path)
                .read_text(
                    encoding="utf-8",
                )
                .splitlines()
            )
            tag = next(ln for ln in lines if "@smoke" in ln)
            indent = len(tag) - len(tag.lstrip())
            assert indent == 4

    def test_examples_under_rule(self) -> None:
        """Examples under Rule indented to 6."""
        with _FeatureFileFixture("""\
            Feature: Examples rule
              Rule: A rule
                Scenario Outline: Test
                  Given a <thing>
                Examples:
                  | thing |
                  | apple |
        """) as (feat_path, lang_path):
            linter = GherkinProLinter(
                lang_path,
                fix=True,
            )
            linter.lint_file(feat_path)
            lines = (
                Path(feat_path)
                .read_text(
                    encoding="utf-8",
                )
                .splitlines()
            )
            examples = next(ln for ln in lines if "Examples:" in ln)
            indent = len(examples) - len(
                examples.lstrip(),
            )
            assert indent == 6

    def test_docstring_preserved(self) -> None:
        """Doc-string bodies are not reindented."""
        with _FeatureFileFixture("""\
            Feature: Test
              Scenario: DocString
                Given a step
                \"\"\"
                This is doc-string content.
                \"\"\"
                When another step
                Then result
        """) as (feat_path, lang_path):
            linter = GherkinProLinter(
                lang_path,
                fix=True,
            )
            linter.lint_file(feat_path)
            result = Path(feat_path).read_text(
                encoding="utf-8",
            )
            assert "This is doc-string content." in result


# ==================================================================
# Strict mode
# ==================================================================


class TestStrictMode(unittest.TestCase):
    """Verify --strict promotes warnings."""

    def test_strict_fails_on_warning(self) -> None:
        """Strict mode treats warnings as failures."""
        issues, linter = _lint(
            """\
            Feature: Many steps
              Scenario: Long
                Given step one
                And step two
                And step three
                When step four
                And step five
                Then step six
            """,
            strict=True,
        )
        warns = _warnings(issues)
        assert len(warns) > 0
        assert linter.werror


# ==================================================================
# Static helpers
# ==================================================================


class TestStaticHelpers(unittest.TestCase):
    """Verify static methods directly."""

    def test_leading_indent_spaces(self) -> None:
        """Count leading spaces."""
        assert (
            GherkinProLinter._leading_indent(
                "    foo",
            )
            == 4
        )

    def test_leading_indent_tabs(self) -> None:
        """Count leading tabs."""
        assert (
            GherkinProLinter._leading_indent(
                "\t\tfoo",
            )
            == 2
        )

    def test_strip_bom(self) -> None:
        """Strip BOM character."""
        assert (
            GherkinProLinter._strip_bom(
                "\ufeffhello",
            )
            == "hello"
        )

    def test_strip_bom_no_bom(self) -> None:
        """Leave BOM-free strings unchanged."""
        assert GherkinProLinter._strip_bom("hello") == "hello"

    def test_has_comment_prefix(self) -> None:
        """Detect comment lines."""
        assert GherkinProLinter._has_comment_prefix(
            "  # comment",
        )
        assert not GherkinProLinter._has_comment_prefix(
            "  Given # x",
        )

    def test_has_tag_prefix(self) -> None:
        """Detect tag lines."""
        assert GherkinProLinter._has_tag_prefix(
            "  @smoke",
        )
        assert not GherkinProLinter._has_tag_prefix(
            "  Given @x",
        )

    def test_detect_docstring_delim(self) -> None:
        """Detect doc-string delimiters."""
        assert (
            GherkinProLinter._detect_docstring_delim(
                '"""',
            )
            == '"""'
        )
        assert (
            GherkinProLinter._detect_docstring_delim(
                "```",
            )
            == "```"
        )
        assert (
            GherkinProLinter._detect_docstring_delim(
                "Given x",
            )
            is None
        )

    def test_has_heading_colon(self) -> None:
        """Detect heading-with-colon."""
        assert GherkinProLinter._has_heading_colon(
            "Feature: Name",
            "Feature",
        )
        assert not GherkinProLinter._has_heading_colon(
            "Feature Name",
            "Feature",
        )

    def test_extract_heading_text(self) -> None:
        """Extract text after heading colon."""
        assert (
            GherkinProLinter._extract_heading_text(
                "Feature: Login",
                "Feature",
            )
            == "Login"
        )

    def test_has_step_colon(self) -> None:
        """Detect illegal colon after step keyword."""
        assert GherkinProLinter._has_step_colon(
            "Given : stuff",
            "Given ",
        )
        assert not GherkinProLinter._has_step_colon(
            "Given stuff",
            "Given ",
        )

    def test_step_matches(self) -> None:
        """Match step keyword and extract text."""
        assert (
            GherkinProLinter._step_matches(
                "Given a user",
                "Given ",
            )
            == "a user"
        )
        assert (
            GherkinProLinter._step_matches(
                "Givenfoo",
                "Given",
            )
            is None
        )


# ==================================================================
# Edge cases
# ==================================================================


class TestEdgeCases(unittest.TestCase):
    """Miscellaneous edge cases."""

    def test_star_as_step(self) -> None:
        """Star as step keyword is valid."""
        issues, _ = _lint("""\
            Feature: Star
              Scenario: Using star
                * a step
                * another step
        """)
        assert _errors(issues) == []

    def test_star_without_space(self) -> None:
        """Star without space is not a step."""
        issues, _ = _lint("""\
            Feature: Star no space
              Scenario: Test
                Given a step
                *foo
        """)
        assert "A1.4" in _codes(issues)

    def test_star_alone(self) -> None:
        """Bare star with no text is valid."""
        issues, _ = _lint("""\
            Feature: Star bare
              Scenario: Test
                Given a step
                *
        """)
        # The star alone is a valid step with empty text
        assert "A1.4" not in _codes(issues)

    def test_example_synonym(self) -> None:
        """Example is a valid synonym for Scenario."""
        issues, _ = _lint("""\
            Feature: Synonym
              Example: An example
                Given a step
        """)
        assert _errors(issues) == []

    def test_scenario_template_synonym(self) -> None:
        """Scenario Template is a synonym for Outline."""
        issues, _ = _lint("""\
            Feature: Template
              Scenario Template: Param test
                Given a <thing>
              Examples:
                | thing |
                | apple |
        """)
        assert _errors(issues) == []

    def test_unknown_dialect_fallback(self) -> None:
        """Unknown language code falls back to English."""
        issues, _ = _lint("""\
            # language: zz
            Feature: Fallback
              Scenario: Test
                Given a step
        """)
        assert _errors(issues) == []

    def test_scenarios_synonym_for_examples(
        self,
    ) -> None:
        """Scenarios is a synonym for Examples."""
        issues, _ = _lint("""\
            Feature: Synonym
              Scenario Outline: Outline
                Given a <val>
              Scenarios:
                | val   |
                | hello |
        """)
        assert _errors(issues) == []

    def test_rule_background(self) -> None:
        """Background within a Rule is valid."""
        issues, _ = _lint("""\
            Feature: Rule with background
              Rule: A rule
                Background: Rule setup
                  Given a precondition
                Scenario: Under rule
                  When an action
                  Then a result
        """)
        assert _errors(issues) == []


# ==================================================================
# CLI entry point
# ==================================================================


class TestMain(unittest.TestCase):
    """Verify the main() CLI entry point."""

    def test_no_targets_exits_zero(self) -> None:
        """No targets exits with code zero."""
        with (
            mock.patch(
                "sys.argv",
                ["check_gherkin_feature.py"],
            ),
            pytest.raises(SystemExit) as ctx,
        ):
            main()
        assert ctx.value.code == 0

    def test_valid_file_exits_zero(self) -> None:
        """Valid file exits with code zero."""
        with (
            _FeatureFileFixture("""\
            Feature: CLI test
              Scenario: Pass
                Given a step
        """) as (feat_path, lang_path),
            mock.patch(
                "sys.argv",
                [
                    "check_gherkin_feature.py",
                    "--languages",
                    lang_path,
                    feat_path,
                ],
            ),
            pytest.raises(SystemExit) as ctx,
        ):
            main()
        assert ctx.value.code == 0

    def test_invalid_file_exits_one(self) -> None:
        """File with errors exits with code one."""
        with (
            _FeatureFileFixture("""\
            Feature: CLI test
              Feature: Duplicate
        """) as (feat_path, lang_path),
            mock.patch(
                "sys.argv",
                [
                    "check_gherkin_feature.py",
                    "--languages",
                    lang_path,
                    feat_path,
                ],
            ),
            pytest.raises(SystemExit) as ctx,
        ):
            main()
        assert ctx.value.code == 1

    def test_bad_languages_exits_two(self) -> None:
        """Missing languages file exits code two."""
        with (
            mock.patch(
                "sys.argv",
                [
                    "check_gherkin_feature.py",
                    "--languages",
                    "/nonexistent.json",
                    "dummy.feature",
                ],
            ),
            pytest.raises(SystemExit) as ctx,
        ):
            main()
        assert ctx.value.code == 2

    def test_directory_target(self) -> None:
        """Directory target discovers feature files."""
        with (
            _FeatureFileFixture("""\
            Feature: Dir test
              Scenario: A
                Given a step
        """) as (feat_path, lang_path),
            mock.patch(
                "sys.argv",
                [
                    "check_gherkin_feature.py",
                    "--languages",
                    lang_path,
                    str(Path(feat_path).parent),
                ],
            ),
            pytest.raises(SystemExit) as ctx,
        ):
            main()
        assert ctx.value.code == 0

    def test_strict_flag(self) -> None:
        """Strict flag fails on warnings."""
        with (
            _FeatureFileFixture("""\
            Feature: Strict
              Scenario: Six steps
                Given step one
                And step two
                And step three
                When step four
                And step five
                Then step six
        """) as (feat_path, lang_path),
            mock.patch(
                "sys.argv",
                [
                    "check_gherkin_feature.py",
                    "--languages",
                    lang_path,
                    "--strict",
                    feat_path,
                ],
            ),
            pytest.raises(SystemExit) as ctx,
        ):
            main()
        assert ctx.value.code == 1

    def test_fix_flag_via_cli(self) -> None:
        """Fix flag rewrites files via CLI."""
        with _FeatureFileFixture("""\
                Feature: Misindented
                  Scenario: Test
                    Given a step
        """) as (feat_path, lang_path):
            with (
                mock.patch(
                    "sys.argv",
                    [
                        "check_gherkin_feature.py",
                        "--languages",
                        lang_path,
                        "--fix",
                        feat_path,
                    ],
                ),
                pytest.raises(SystemExit) as ctx,
            ):
                main()
            result = Path(feat_path).read_text(
                encoding="utf-8",
            )
            assert result.startswith("Feature:")
            assert ctx.value.code == 0

    def test_file_read_error_during_iteration(
        self,
    ) -> None:
        """FileReadError during iteration is recorded."""
        with (
            _FeatureFileFixture("""\
            Feature: OK
              Scenario: A
                Given a step
        """) as (feat_path, lang_path),
            mock.patch(
                "sys.argv",
                [
                    "check_gherkin_feature.py",
                    "--languages",
                    lang_path,
                    feat_path,
                ],
            ),
            mock.patch(
                "pre_commit_hooks" ".check_gherkin_feature" "._read_feature_file",
                side_effect=FileReadError("boom"),
            ),
            pytest.raises(SystemExit) as ctx,
        ):
            main()
        assert ctx.value.code == 1


if __name__ == "__main__":
    unittest.main()
