# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

"""Tests for pre_commit_hooks.check_gherkin_feature.

Covers the custom exception hierarchy, data-class construction,
dialect loading, every diagnostic rule (A1.4 through B2.1), the
``--fix`` indentation rewriter, and the CLI entry point.
"""

import json
import tempfile
import textwrap
import unittest
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
    _indent_spaces,
    _LintState,
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
    """Context manager for a ``.feature`` file and languages JSON."""

    def __init__(
        self,
        feature_text: str,
        *,
        dialects: dict[str, object] | None = None,
    ) -> None:
        self._feature_text = textwrap.dedent(feature_text)
        self._dialects = dialects or {"en": _EN_DIALECT}
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
    """Lint *feature_text* and return ``(issues, linter)``."""
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
    """Extract diagnostic codes from a list of issues."""
    return [i.code for i in issues]


def _errors(issues: list[Issue]) -> list[Issue]:
    """Filter to error-level issues only."""
    return [i for i in issues if i.kind == "ERR"]


def _warnings(issues: list[Issue]) -> list[Issue]:
    """Filter to warning-level issues only."""
    return [i for i in issues if i.kind == "WARN"]


# ==================================================================
# Exception hierarchy
# ==================================================================


class TestExceptionHierarchy(unittest.TestCase):  # noqa: H601
    """Verify the custom exception class relationships."""

    def test_linter_error_is_base(self) -> None:
        """LinterError inherits from Exception."""
        assert issubclass(LinterError, Exception)

    def test_load_error_derives_from_base(self) -> None:
        """DialectLoadError inherits from LinterError."""
        assert issubclass(DialectLoadError, LinterError)

    def test_dialect_schema_error_inherits(self) -> None:
        """DialectSchemaError inherits from LinterError."""
        assert issubclass(DialectSchemaError, LinterError)

    def test_file_read_error_inherits(self) -> None:
        """FileReadError inherits from LinterError."""
        assert issubclass(FileReadError, LinterError)

    def test_linter_error_catchall(self) -> None:
        """All custom exceptions are caught by LinterError."""
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


class TestIssue(unittest.TestCase):  # noqa: H601
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
        assert issue.render() == "ERR: a.feature:10: A2.1 msg"

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
        """Issue uses __slots__ and rejects extra attributes."""
        issue = Issue("ERR", "x", "1", "A1.4", "m")
        with pytest.raises(AttributeError):
            issue.extra = True  # type: ignore[attr-defined]


class TestScope(unittest.TestCase):  # noqa: H601
    """Verify Scope defaults."""

    def test_defaults(self) -> None:
        """New Scope has sensible defaults."""
        scope = Scope("feature", indent=0)
        assert not scope.background_defined
        assert scope.background_steps == set()
        assert not scope.scenarios_seen


class TestBlock(unittest.TestCase):  # noqa: H601
    """Verify Block defaults."""

    def test_defaults(self) -> None:
        """New Block has sensible defaults."""
        block = Block(kind="scenario", indent=2)
        assert not block.examples_seen
        assert block.step_count == 0
        assert block.step_texts == set()


class TestLintState(unittest.TestCase):  # noqa: H601
    """Verify _LintState scope resolution."""

    def test_resolve_scope_drops_rule(self) -> None:
        """Rule scope is cleared when indent returns to zero."""
        state = _LintState()
        state.feature_scope = Scope("feature", indent=0)
        state.rule_scope = Scope("rule", indent=2)
        state.resolve_scope(indent=0)
        assert state.rule_scope is None

    def test_resolve_scope_keeps_rule(self) -> None:
        """Rule scope is retained when indent is deeper."""
        state = _LintState()
        state.rule_scope = Scope("rule", indent=2)
        state.resolve_scope(indent=4)
        assert state.rule_scope is not None

    def test_active_scope_prefers_rule(self) -> None:
        """Active scope returns rule when both exist."""
        state = _LintState()
        state.feature_scope = Scope("feature", indent=0)
        state.rule_scope = Scope("rule", indent=2)
        assert state.active_scope() == state.rule_scope

    def test_active_scope_falls_back_to_feature(
        self,
    ) -> None:
        """Active scope returns feature when no rule exists."""
        state = _LintState()
        state.feature_scope = Scope("feature", indent=0)
        assert state.active_scope() == state.feature_scope

    def test_active_scope_none(self) -> None:
        """Active scope is None when no scopes exist."""
        state = _LintState()
        assert state.active_scope() is None


# ==================================================================
# DialectMatchers
# ==================================================================


class TestDialectMatchers(unittest.TestCase):  # noqa: H601
    """Verify DialectMatchers construction and validation."""

    def test_from_valid_dialect(self) -> None:
        """Valid dialect produces correct keyword lists."""
        matchers = DialectMatchers.from_dialect(_EN_DIALECT)
        assert "Feature" in matchers.feature
        assert "Given " in matchers.given

    def test_keywords_sorted_longest_first(self) -> None:
        """Keywords are sorted longest-first for matching."""
        matchers = DialectMatchers.from_dialect(_EN_DIALECT)
        assert "Scenario Outline" in matchers.outline
        assert "Scenario Template" in matchers.outline
        for kw_list in (
            matchers.feature,
            matchers.scenario,
            matchers.outline,
            matchers.examples,
        ):
            lengths = [len(k) for k in kw_list]
            assert lengths == sorted(lengths, reverse=True)

    def test_missing_key_raises(self) -> None:
        """Missing dialect key raises DialectSchemaError."""
        broken: dict[str, object] = dict(_EN_DIALECT)
        del broken["feature"]
        with pytest.raises(DialectSchemaError):
            DialectMatchers.from_dialect(broken)

    def test_non_list_value_raises(self) -> None:
        """Non-list dialect value raises DialectSchemaError."""
        broken: dict[str, object] = dict(_EN_DIALECT)
        broken["feature"] = "Feature"
        with pytest.raises(DialectSchemaError):
            DialectMatchers.from_dialect(broken)

    def test_empty_strings_discarded(self) -> None:
        """Empty strings in keyword lists are discarded."""
        dialect: dict[str, list[str] | str] = dict(
            _EN_DIALECT,
        )
        dialect["feature"] = ["Feature", "", "  "]
        matchers = DialectMatchers.from_dialect(dialect)
        assert "" not in matchers.feature


# ==================================================================
# Module-level helper
# ==================================================================


class TestIndentSpaces(unittest.TestCase):  # noqa: H601
    """Verify _indent_spaces."""

    def test_positive(self) -> None:
        """Positive argument produces that many spaces."""
        assert _indent_spaces(4) == "    "

    def test_zero(self) -> None:
        """Zero argument produces empty string."""
        assert _indent_spaces(0) == ""

    def test_negative_floors_to_zero(self) -> None:
        """Negative argument is floored to zero."""
        assert _indent_spaces(-3) == ""


# ==================================================================
# Linter initialisation
# ==================================================================


class TestLinterInit(unittest.TestCase):  # noqa: H601
    """Verify GherkinProLinter construction and error paths."""

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
        """Missing languages file raises DialectLoadError."""
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
        """Missing 'en' key raises DialectSchemaError."""
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


class TestLintFileReadError(unittest.TestCase):  # noqa: H601
    """Verify that unreadable files raise FileReadError."""

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


class TestRuleA1_4(unittest.TestCase):  # noqa: H601
    """A1.4: Non-blank line must start with a Gherkin keyword."""

    def test_unrecognised_line(self) -> None:
        """Unrecognised line triggers A1.4."""
        issues, _ = _lint("""\
            Feature: Login
              Scenario: Valid credentials
                Given a user exists
                This is not a keyword line
        """)
        assert "A1.4" in _codes(issues)

    def test_valid_lines_pass(self) -> None:
        """All-keyword file produces no A1.4."""
        issues, _ = _lint("""\
            Feature: Login
              Scenario: Valid credentials
                Given a user exists
                When the user logs in
                Then the user sees the dashboard
        """)
        assert "A1.4" not in _codes(issues)


class TestRuleA1_5(unittest.TestCase):  # noqa: H601
    """A1.5: Step keywords must not be followed by a colon."""

    def test_given_with_colon(self) -> None:
        """Given followed by colon triggers A1.5."""
        issues, _ = _lint("""\
            Feature: Login
              Scenario: Bad step
                Given: a user exists
        """)
        assert "A1.5" in _codes(issues)

    def test_when_with_colon(self) -> None:
        """When followed by colon triggers A1.5."""
        issues, _ = _lint("""\
            Feature: Login
              Scenario: Bad step
                When: the user logs in
        """)
        assert "A1.5" in _codes(issues)

    def test_then_with_colon(self) -> None:
        """Then followed by colon triggers A1.5."""
        issues, _ = _lint("""\
            Feature: Login
              Scenario: Bad step
                Then: the user sees home
        """)
        assert "A1.5" in _codes(issues)

    def test_star_with_colon(self) -> None:
        """Star step followed by colon triggers A1.5."""
        issues, _ = _lint("""\
            Feature: Login
              Scenario: Bad step
                Given a user exists
                *: something
        """)
        assert "A1.5" in _codes(issues)


class TestRuleA2_1(unittest.TestCase):  # noqa: H601
    """A2.1: Feature must be first primary keyword, with text."""

    def test_scenario_before_feature(self) -> None:
        """Scenario before Feature triggers A2.1."""
        issues, _ = _lint("""\
            Scenario: Orphan
              Given something
        """)
        assert "A2.1" in _codes(issues)

    def test_feature_without_name(self) -> None:
        """Feature with empty name triggers A2.1."""
        issues, _ = _lint("""\
            Feature:
              Scenario: Valid
                Given something
        """)
        assert "A2.1" in _codes(issues)

    def test_feature_with_blank_name(self) -> None:
        """Feature with whitespace-only name triggers A2.1."""
        issues, _ = _lint("""\
            Feature:   \n              Scenario: Valid
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


class TestRuleA2_2(unittest.TestCase):  # noqa: H601
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


class TestRuleA4_0(unittest.TestCase):  # noqa: H601
    """A4.0: Scenario must appear inside a Feature or Rule."""

    def test_scenario_before_feature_scope(self) -> None:
        """Scenario outside Feature scope triggers an error."""
        issues, _ = _lint("""\
            Scenario: Orphan
              Given a step
        """)
        errs = _errors(issues)
        assert len(errs) > 0


class TestRuleA4_1(unittest.TestCase):  # noqa: H601
    """A4.1: Step found outside Scenario or Background."""

    def test_step_directly_under_feature(self) -> None:
        """Step outside any block triggers A4.1."""
        issues, _ = _lint("""\
            Feature: Dangling step
              Given a step outside any scenario
        """)
        assert "A4.1" in _codes(issues)


class TestRuleA4_5(unittest.TestCase):  # noqa: H601
    """A4.5: Duplicate step text within a scenario."""

    def test_duplicate_step(self) -> None:
        """Repeated step text triggers A4.5."""
        issues, _ = _lint("""\
            Feature: Duplicates
              Scenario: Dup steps
                Given a user exists
                When the user logs in
                Then a user exists
        """)
        assert "A4.5" in _codes(issues)

    def test_duplicate_with_different_keywords(self) -> None:
        """Step text comparison ignores keywords."""
        issues, _ = _lint("""\
            Feature: Duplicates
              Scenario: Dup steps
                Given a precondition
                And a precondition
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


class TestRuleA5_0(unittest.TestCase):  # noqa: H601
    """A5.0: Background must appear inside a Feature or Rule."""

    def test_background_before_feature(self) -> None:
        """Background outside Feature triggers an error."""
        issues, _ = _lint("""\
            Background: Orphan
              Given a step
        """)
        errs = _errors(issues)
        assert len(errs) > 0


class TestRuleA5_1(unittest.TestCase):  # noqa: H601
    """A5.1: Background must appear before scenarios."""

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


class TestRuleA5_2(unittest.TestCase):  # noqa: H601
    """A5.2: Background may only contain Given-like steps."""

    def test_when_in_background(self) -> None:
        """When in Background triggers A5.2."""
        issues, _ = _lint("""\
            Feature: Bad background
              Background: Setup
                Given a user exists
                When the user acts
        """)
        assert "A5.2" in _codes(issues)

    def test_then_in_background(self) -> None:
        """Then in Background triggers A5.2."""
        issues, _ = _lint("""\
            Feature: Bad background
              Background: Setup
                Given a user exists
                Then something asserted
        """)
        assert "A5.2" in _codes(issues)

    def test_given_like_keywords_allowed(self) -> None:
        """Given, And, But, and star are valid in Background."""
        issues, _ = _lint("""\
            Feature: Good background
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


class TestRuleA5_3(unittest.TestCase):  # noqa: H601
    """A5.3: Only one Background per scope."""

    def test_two_backgrounds(self) -> None:
        """Second Background triggers A5.3."""
        issues, _ = _lint("""\
            Feature: Double background
              Background: First
                Given a step
              Background: Second
                Given another step
        """)
        assert "A5.3" in _codes(issues)


class TestRuleA6_3(unittest.TestCase):  # noqa: H601
    """A6.3: Scenario Outline requires Examples."""

    def test_outline_without_examples(self) -> None:
        """Outline without Examples triggers A6.3."""
        issues, _ = _lint("""\
            Feature: Missing examples
              Scenario Outline: No table
                Given a <thing>
        """)
        assert "A6.3" in _codes(issues)

    def test_examples_outside_outline(self) -> None:
        """Examples under Scenario triggers A6.3."""
        issues, _ = _lint("""\
            Feature: Misplaced examples
              Scenario: Not an outline
                Given a step
              Examples: Orphan
                | col |
                | val |
        """)
        assert "A6.3" in _codes(issues)

    def test_outline_with_examples_passes(self) -> None:
        """Outline with Examples produces no A6.3."""
        issues, _ = _lint("""\
            Feature: Valid outline
              Scenario Outline: With table
                Given a <thing>
              Examples:
                | thing |
                | apple |
        """)
        assert "A6.3" not in _codes(issues)


class TestRuleA6_4(unittest.TestCase):  # noqa: H601
    """A6.4: Examples section has no table rows."""

    def test_empty_examples(self) -> None:
        """Empty Examples section triggers A6.4 warning."""
        issues, _ = _lint("""\
            Feature: Empty examples
              Scenario Outline: Outline
                Given a <thing>
              Examples:
        """)
        assert "A6.4" in _codes(_warnings(issues))


class TestRuleA7_1(unittest.TestCase):  # noqa: H601
    """A7.1: Doc String must appear directly under a step."""

    def test_docstring_not_under_step(self) -> None:
        """Orphan doc string triggers A7.1."""
        issues, _ = _lint("""\
            Feature: Bad docstring
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

    def test_docstring_under_step_passes(self) -> None:
        """Doc string under a step produces no A7.1."""
        issues, _ = _lint("""\
            Feature: Good docstring
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
            Feature: Backtick docstring
              Scenario: Test
                Given a step
                ```json
                {"key": "value"}
                ```
                When another step
                Then a result
        """)
        assert "A7.1" not in _codes(issues)


class TestRuleA7_4(unittest.TestCase):  # noqa: H601
    """A7.4: Data Table must appear directly under a step."""

    def test_table_not_under_step(self) -> None:
        """Orphan table row triggers A7.4."""
        issues, _ = _lint("""\
            Feature: Bad table
              Scenario: Test
                | orphan | table |
        """)
        assert "A7.4" in _codes(issues)

    def test_table_under_step_passes(self) -> None:
        """Data table under a step produces no A7.4."""
        issues, _ = _lint("""\
            Feature: Good table
              Scenario: Test
                Given the following users
                  | name  | role  |
                  | Alice | admin |
                When something
                Then result
        """)
        assert "A7.4" not in _codes(issues)


class TestRuleA8_1(unittest.TestCase):  # noqa: H601
    """A8.1: Language header only applies on the first line."""

    def test_language_on_second_line(self) -> None:
        """Language header on line two triggers A8.1."""
        issues, _ = _lint("""\
            # some comment
            # language: en
            Feature: Test
              Scenario: A
                Given a step
        """)
        assert "A8.1" in _codes(issues)

    def test_language_on_first_line_passes(self) -> None:
        """Language header on line one produces no A8.1."""
        issues, _ = _lint("""\
            # language: en
            Feature: Test
              Scenario: A
                Given a step
        """)
        assert "A8.1" not in _codes(issues)


class TestRuleB2_1(unittest.TestCase):  # noqa: H601
    """B2.1: Scenario with more than five steps triggers a warning."""

    def test_six_steps_warns(self) -> None:
        """Six steps triggers B2.1 warning."""
        issues, _ = _lint("""\
            Feature: Too many steps
              Scenario: Long scenario
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
            Feature: Acceptable
              Scenario: Five steps
                Given step one
                And step two
                When step three
                Then step four
                And step five
        """)
        assert "B2.1" not in _codes(issues)


# ==================================================================
# Passing (well-formed) features
# ==================================================================


class TestWellFormedFeatures(unittest.TestCase):  # noqa: H601
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
        """Feature containing a Rule passes."""
        issues, _ = _lint("""\
            Feature: With Rule
              Rule: Business rule A
                Scenario: Under rule
                  Given a step
                  When an action
                  Then a result
        """)
        assert _errors(issues) == []

    def test_tags_with_comments(self) -> None:
        """Tags combined with comments pass."""
        issues, _ = _lint("""\
            # A comment
            @smoke
            Feature: Tagged
              @critical
              Scenario: Tagged scenario
                Given a step
        """)
        assert _errors(issues) == []

    def test_empty_file_passes(self) -> None:
        """Empty file produces no issues."""
        issues, _ = _lint("")
        assert issues == []

    def test_bom_handling(self) -> None:
        """UTF-8 BOM on the first line does not break parsing."""
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


# ==================================================================
# Background + Scenario duplicate detection
# ==================================================================


class TestBackgroundDuplicateDetection(  # noqa: H601
    unittest.TestCase,
):
    """Background steps count for duplicate detection."""

    def test_scenario_repeating_background_step(self) -> None:
        """Step duplicated from Background triggers A4.5."""
        issues, _ = _lint("""\
            Feature: Duplicate across background
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
            Feature: No duplicates
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


class TestFixMode(unittest.TestCase):  # noqa: H601
    """Verify ``--fix`` rewrites indentation correctly."""

    def test_feature_reindented_to_zero(self) -> None:
        """Feature heading is reindented to column zero."""
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
            assert result.startswith("Feature:"), (
                f"Expected Feature at column 0," f" got: {result!r}"
            )

    def test_scenario_indented_to_two(self) -> None:
        """Scenario heading is reindented to column two."""
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
            lines = Path(feat_path).read_text(encoding="utf-8").splitlines()
            scenario = next(ln for ln in lines if "Scenario:" in ln)
            indent = len(scenario) - len(scenario.lstrip())
            assert indent == 2

    def test_steps_indented_to_four(self) -> None:
        """Steps are reindented to column four."""
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
            lines = Path(feat_path).read_text(encoding="utf-8").splitlines()
            step = next(ln for ln in lines if "Given" in ln)
            indent = len(step) - len(step.lstrip())
            assert indent == 4

    def test_comments_preserved(self) -> None:
        """Fix mode preserves comment lines."""
        with _FeatureFileFixture("""\
            # Important comment
            Feature: Test
              Scenario: A
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
            assert "# Important comment" in result

    def test_docstring_content_preserved(self) -> None:
        """Fix mode preserves doc-string bodies."""
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

    def test_data_table_preserved(self) -> None:
        """Fix mode preserves data-table rows."""
        with _FeatureFileFixture("""\
            Feature: Test
              Scenario: Table
                Given the following users
                  | name  | role  |
                  | Alice | admin |
                When action
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
            assert "| Alice | admin |" in result

    def test_description_lines_preserved(self) -> None:
        """Fix mode preserves description text."""
        with _FeatureFileFixture("""\
            Feature: Test
              This is a description.

              Scenario: A
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
            assert "This is a description." in result

    def test_rule_level_indentation(self) -> None:
        """Under a Rule, scenarios indent to 4, steps to 6."""
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
            lines = Path(feat_path).read_text(encoding="utf-8").splitlines()
            scenario = next(ln for ln in lines if "Scenario:" in ln)
            step = next(ln for ln in lines if "Given" in ln)
            assert len(scenario) - len(scenario.lstrip()) == 4
            assert len(step) - len(step.lstrip()) == 6


# ==================================================================
# Strict mode
# ==================================================================


class TestStrictMode(unittest.TestCase):  # noqa: H601
    """Verify that ``--strict`` promotes warnings to errors."""

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


class TestStaticHelpers(unittest.TestCase):  # noqa: H601
    """Verify GherkinProLinter's static methods directly."""

    def test_leading_indent_spaces(self) -> None:
        """Leading spaces are counted correctly."""
        assert GherkinProLinter._leading_indent("    foo") == 4

    def test_leading_indent_tabs(self) -> None:
        """Leading tabs are counted correctly."""
        assert GherkinProLinter._leading_indent("\t\tfoo") == 2

    def test_leading_indent_empty(self) -> None:
        """No leading whitespace returns zero."""
        assert GherkinProLinter._leading_indent("foo") == 0

    def test_strip_bom(self) -> None:
        """BOM character is stripped."""
        assert GherkinProLinter._strip_bom("\ufeffhello") == "hello"

    def test_strip_bom_no_bom(self) -> None:
        """String without BOM is unchanged."""
        assert GherkinProLinter._strip_bom("hello") == "hello"

    def test_has_comment_prefix(self) -> None:
        """Comment lines are detected correctly."""
        assert GherkinProLinter._has_comment_prefix(
            "  # comment",
        )
        assert not GherkinProLinter._has_comment_prefix(
            "  Given # x",
        )

    def test_has_tag_prefix(self) -> None:
        """Tag lines are detected correctly."""
        assert GherkinProLinter._has_tag_prefix("  @smoke")
        assert not GherkinProLinter._has_tag_prefix(
            "  Given @x",
        )

    def test_detect_docstring_delim_triple_quote(
        self,
    ) -> None:
        """Triple-quote delimiter is detected."""
        assert GherkinProLinter._detect_docstring_delim('"""') == '"""'

    def test_detect_docstring_delim_backtick(self) -> None:
        """Backtick delimiter is detected."""
        assert GherkinProLinter._detect_docstring_delim("```") == "```"

    def test_detect_docstring_delim_none(self) -> None:
        """Non-delimiter returns None."""
        assert (
            GherkinProLinter._detect_docstring_delim(
                "Given x",
            )
            is None
        )

    def test_has_heading_colon(self) -> None:
        """Heading-with-colon detection works correctly."""
        assert GherkinProLinter._has_heading_colon(
            "Feature: Name",
            "Feature",
        )
        assert GherkinProLinter._has_heading_colon(
            "Feature : Name",
            "Feature",
        )
        assert not GherkinProLinter._has_heading_colon(
            "Feature Name",
            "Feature",
        )

    def test_extract_heading_text(self) -> None:
        """Heading text after the colon is extracted."""
        assert (
            GherkinProLinter._extract_heading_text(
                "Feature: Login system",
                "Feature",
            )
            == "Login system"
        )

    def test_has_step_colon(self) -> None:
        """Illegal colon after step keyword is detected."""
        assert GherkinProLinter._has_step_colon(
            "Given : stuff",
            "Given ",
        )
        assert not GherkinProLinter._has_step_colon(
            "Given stuff",
            "Given ",
        )

    def test_step_matches(self) -> None:
        """Step keyword matching extracts the step text."""
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
# CLI entry point
# ==================================================================


class TestMain(unittest.TestCase):  # noqa: H601
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
        """Valid feature file exits with code zero."""
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
        ):
            with pytest.raises(SystemExit) as ctx:
                main()
            assert ctx.value.code == 0

    def test_invalid_file_exits_one(self) -> None:
        """Feature with errors exits with code one."""
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
        ):
            with pytest.raises(SystemExit) as ctx:
                main()
            assert ctx.value.code == 1

    def test_bad_languages_exits_two(self) -> None:
        """Missing languages file exits with code two."""
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
        ):
            with pytest.raises(SystemExit) as ctx:
                main()
            assert ctx.value.code == 0

    def test_strict_flag_fails_on_warnings(self) -> None:
        """Strict flag treats warnings as failures."""
        with (
            _FeatureFileFixture("""\
            Feature: Strict warn
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
        ):
            with pytest.raises(SystemExit) as ctx:
                main()
            assert ctx.value.code == 1


# ==================================================================
# Edge cases
# ==================================================================


class TestEdgeCases(unittest.TestCase):  # noqa: H601
    """Miscellaneous edge-case coverage."""

    def test_star_as_step(self) -> None:
        """Star used as a step keyword is valid."""
        issues, _ = _lint("""\
            Feature: Star step
              Scenario: Using star
                * a step
                * another step
        """)
        assert _errors(issues) == []

    def test_star_without_space_ignored(self) -> None:
        """Star without trailing space is not a step keyword."""
        issues, _ = _lint("""\
            Feature: Star no space
              Scenario: Test
                Given a step
                *foo
        """)
        assert "A1.4" in _codes(issues)

    def test_example_synonym_for_scenario(self) -> None:
        """Example keyword is a valid synonym for Scenario."""
        issues, _ = _lint("""\
            Feature: Synonym test
              Example: An example
                Given a step
        """)
        assert _errors(issues) == []

    def test_scenario_template_synonym(self) -> None:
        """Scenario Template is a synonym for Scenario Outline."""
        issues, _ = _lint("""\
            Feature: Template
              Scenario Template: Param test
                Given a <thing>
              Examples:
                | thing |
                | apple |
        """)
        assert _errors(issues) == []

    def test_unknown_dialect_falls_back_to_en(self) -> None:
        """Unrecognised language code falls back to English."""
        issues, _ = _lint("""\
            # language: zz
            Feature: Fallback
              Scenario: Test
                Given a step
        """)
        assert _errors(issues) == []

    def test_examples_with_scenarios_synonym(self) -> None:
        """Scenarios keyword is a valid synonym for Examples."""
        issues, _ = _lint("""\
            Feature: Scenarios synonym
              Scenario Outline: Outline
                Given a <val>
              Scenarios:
                | val   |
                | hello |
        """)
        assert _errors(issues) == []

    def test_multiple_scenarios_in_feature(self) -> None:
        """Multiple scenarios in a single feature are valid."""
        issues, _ = _lint("""\
            Feature: Multiple scenarios
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

    def test_rule_background_before_scenario(self) -> None:
        """Background within a Rule scope is valid."""
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


if __name__ == "__main__":
    unittest.main()
