# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

"""
Gherkin Reference Linter.

Enforce the normative rules from the Cucumber Gherkin reference as
errors by default, and emit recommendations as warnings (optionally
promoted to errors via ``--strict``).

Strict behaviours
-----------------
- Exactly one ``Feature`` per file; ``Feature`` is the first primary
  keyword.
- Every non-blank, non-comment line must begin with a keyword, except
  for description lines in allowed description regions.
- Headings that require a colon must have one; step keywords must not
  use a colon.
- ``Background``: at most one per ``Feature``/``Rule``; must appear
  before scenarios in that scope; steps restricted to
  ``Given``/``And``/``But``/``*`` (no ``When``/``Then``).
- ``Scenario Outline``: requires at least one ``Examples`` section.
- Doc Strings and Data Tables are only permitted as step arguments
  (i.e. directly under a step), and doc-string delimiters must match.

Notes
-----
- Indentation rules are treated as recommendations; indentation is
  used only as a heuristic to determine whether a block belongs to a
  ``Rule`` scope.
- ``--fix`` only adjusts indentation of headings, steps, and tags.
  It intentionally does not reindent doc strings, because
  opening-delimiter indentation affects the dedented content passed
  to step definitions.

"""

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Self

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LANG_HEADER_RE: re.Pattern[str] = re.compile(
    r"^\s*#\s*language:\s*([A-Za-z0-9_-]+)\s*$",
)
COMMENT_LINE_RE: re.Pattern[str] = re.compile(r"^[ \t]*#")
TAG_LINE_RE: re.Pattern[str] = re.compile(r"^[ \t]*@")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class LinterError(Exception):
    """Base exception for all linter errors."""


class DialectLoadError(LinterError):
    """Raised when the languages JSON cannot be loaded or parsed."""


class DialectSchemaError(LinterError):
    """Raised when a dialect entry has an unexpected structure."""


class FileReadError(LinterError):
    """Raised when a ``.feature`` file cannot be read."""


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Issue:  # noqa: H601
    """
    A single lint diagnostic.

    Attributes
    ----------
    kind:
        Severity — ``"ERR"`` for errors, ``"WARN"`` for warnings.
    file_path:
        Path to the file that triggered the issue.
    line_no:
        One-indexed line number, or ``"EOF"`` for end-of-file checks.
    code:
        Machine-readable rule identifier (e.g. ``"A2.1"``).
    message:
        Human-readable description of the issue.

    """

    kind: str
    file_path: str
    line_no: str
    code: str
    message: str

    def render(self) -> str:
        """Format the issue for terminal output."""
        return (
            f"{self.kind}: {self.file_path}:{self.line_no}:"
            f" {self.code} {self.message}"
        )


@dataclass(slots=True)
class Scope:  # noqa: H601
    """
    A ``Feature`` or ``Rule`` scope that tracks Background state.

    Attributes
    ----------
    kind:
        ``"feature"`` or ``"rule"``.
    indent:
        Column offset of the keyword that opened this scope.
    background_defined:
        Whether a ``Background`` has already been declared.
    background_steps:
        Step texts collected from the ``Background`` block, used
        for duplicate detection in subsequent scenarios.
    scenarios_seen:
        Whether at least one ``Scenario`` or ``Scenario Outline``
        has been encountered in this scope.

    """

    kind: str
    indent: int
    background_defined: bool = False
    background_steps: set[str] = field(default_factory=set)
    scenarios_seen: bool = False


@dataclass(slots=True)
class Block:  # noqa: H601
    """
    Current executable block (Scenario, Outline, or Background).

    Attributes
    ----------
    kind:
        ``"scenario"``, ``"outline"``, or ``"background"``.
    indent:
        Column offset of the block's keyword line.
    examples_seen:
        Whether an ``Examples`` section has been found (meaningful
        only for ``"outline"`` blocks).
    step_count:
        Number of steps accumulated so far.
    step_texts:
        De-duplicated step texts (keyword-agnostic) for detecting
        duplicate steps within the block.

    """

    kind: str
    indent: int
    examples_seen: bool = False
    step_count: int = 0
    step_texts: set[str] = field(default_factory=set)


@dataclass(slots=True)
class DialectMatchers:  # noqa: H601
    """
    Compiled keyword lists for a single Gherkin dialect.

    Each attribute holds the dialect's localised keywords for the
    corresponding Gherkin concept, sorted longest-first so that
    prefix matching prefers the most specific token.
    """

    feature: list[str]
    rule: list[str]
    background: list[str]
    scenario: list[str]
    outline: list[str]
    examples: list[str]
    given: list[str]
    when: list[str]
    then: list[str]
    and_: list[str]
    but: list[str]

    @classmethod
    def from_dialect(cls, dialect: dict[str, Any]) -> Self:
        """
        Build matchers from a raw dialect dictionary.

        Parameters
        ----------
        dialect:
            A single dialect entry as loaded from
            ``gherkin-languages.json``.

        Raises
        ------
        DialectSchemaError
            If a required key is missing or holds a non-list value.

        """

        def _kw_list(key: str) -> list[str]:
            raw = dialect.get(key)
            if raw is None:
                raise DialectSchemaError(
                    f"Dialect is missing required key '{key}'.",
                )
            if not isinstance(raw, list):
                raise DialectSchemaError(
                    f"Dialect key '{key}' must be a list,"
                    f" got {type(raw).__name__}.",
                )
            tokens: set[str] = set()
            for kw in raw:
                if not isinstance(kw, str) or not kw:
                    continue
                tokens.add(kw)
                tokens.add(kw.rstrip())
            tokens.discard("")
            return sorted(tokens, key=len, reverse=True)

        return cls(
            feature=_kw_list("feature"),
            rule=_kw_list("rule"),
            background=_kw_list("background"),
            scenario=_kw_list("scenario"),
            outline=_kw_list("scenarioOutline"),
            examples=_kw_list("examples"),
            given=_kw_list("given"),
            when=_kw_list("when"),
            then=_kw_list("then"),
            and_=_kw_list("and"),
            but=_kw_list("but"),
        )


# ---------------------------------------------------------------------------
# Linter
# ---------------------------------------------------------------------------


def _indent_spaces(n: int) -> str:
    """Return *n* spaces, floored at zero."""
    return " " * max(n, 0)


class GherkinProLinter:  # noqa: H601
    """
    Linter enforcing strict Gherkin reference rules by default.

    Parameters
    ----------
    languages_path:
        Filesystem path to ``gherkin-languages.json``.
    verbose:
        Enable verbose diagnostic output.
    strict:
        Promote warnings to errors.
    fix:
        Rewrite files in place with corrected indentation for
        headings, steps, and tags.

    Raises
    ------
    DialectLoadError
        If the languages file cannot be opened or parsed.
    DialectSchemaError
        If the ``"en"`` dialect is absent.

    """

    def __init__(
        self,
        languages_path: str,
        *,
        verbose: bool = False,
        strict: bool = False,
        fix: bool = False,
    ) -> None:
        """
        Initialise the linter with a languages file.

        Parameters
        ----------
        languages_path:
            Filesystem path to ``gherkin-languages.json``.
        verbose:
            Enable verbose diagnostic output.
        strict:
            Promote warnings to errors.
        fix:
            Rewrite files in place with corrected indentation.

        Raises
        ------
        DialectLoadError
            If the languages file cannot be read or parsed.
        DialectSchemaError
            If the ``"en"`` dialect is absent.

        """
        self.verbose: bool = verbose
        self.werror: bool = strict
        self.fix: bool = fix
        self.issues: list[Issue] = []

        self.all_languages: dict[str, Any] = _languages_from_file(languages_path)

    # -- Diagnostic helpers -----------------------------------------

    def _record_error(
        self,
        file_path: str,
        line_no: str,
        code: str,
        message: str,
    ) -> None:
        """Record an error-level diagnostic."""
        self.issues.append(
            Issue("ERR", file_path, line_no, code, message),
        )

    def _record_warning(
        self,
        file_path: str,
        line_no: str,
        code: str,
        message: str,
    ) -> None:
        """Record a warning-level diagnostic."""
        self.issues.append(
            Issue("WARN", file_path, line_no, code, message),
        )

    # -- Line-level helpers -----------------------------------------

    @staticmethod
    def _get_dialect(
        first_line: str,
        all_languages: dict[str, Any],
    ) -> tuple[dict[str, Any], str]:
        """
        Detect the spoken-language dialect from the first line.

        Per rule A8, a ``# language: xx`` header on the very first
        line selects the dialect.  Falls back to ``"en"`` when no
        header is present or when the declared language is unknown.

        Parameters
        ----------
        first_line:
            The first line of the file (BOM already stripped).
        all_languages:
            The full languages dictionary loaded from JSON.

        Returns
        -------
        tuple[dict[str, Any], str]
            The dialect dictionary and the resolved language code.

        """
        match = LANG_HEADER_RE.match(first_line)
        lang_code = match.group(1) if match else "en"
        dialect = all_languages.get(
            lang_code,
            all_languages["en"],
        )
        return dialect, lang_code

    @staticmethod
    def _leading_indent(line: str) -> int:
        """Return the number of leading whitespace characters."""
        return len(line) - len(line.lstrip(" \t"))

    @staticmethod
    def _strip_bom(line: str) -> str:
        """Remove a leading UTF-8 BOM if present."""
        return line.lstrip("\ufeff")

    @staticmethod
    def _has_comment_prefix(line: str) -> bool:
        """Return ``True`` if *line* is a Gherkin comment."""
        return COMMENT_LINE_RE.match(line) is not None

    @staticmethod
    def _has_tag_prefix(line: str) -> bool:
        """Return ``True`` if *line* begins with a tag marker."""
        return TAG_LINE_RE.match(line) is not None

    @staticmethod
    def _detect_docstring_delim(
        stripped: str,
    ) -> str | None:
        r"""
        Identify a doc-string delimiter at the start of *stripped*.

        Returns
        -------
        str | None
            ``'\"\"\"'`` or ``'```'`` if a delimiter is found,
            otherwise ``None``.

        """
        if stripped.startswith('"""'):
            return '"""'
        if stripped.startswith("```"):
            return "```"
        return None

    @staticmethod
    def _has_heading_colon(
        content: str,
        keyword: str,
    ) -> bool:
        """
        Check whether *content* starts with *keyword* plus a colon.

        Returns ``True`` when *content* begins with *keyword*
        followed by optional whitespace and a colon character.

        """
        if not content.startswith(keyword):
            return False
        tail = content[len(keyword) :]
        return re.match(r"^\s*:", tail) is not None

    @staticmethod
    def _extract_heading_text(content: str, keyword: str) -> str:
        """
        Return the descriptive text after *keyword* and its colon.

        Assumes :meth:`_has_heading_colon` has already
        confirmed the pattern.

        """
        tail = content[len(keyword) :]
        tail = re.sub(r"^\s*:\s*", "", tail, count=1)
        return tail.rstrip("\n")

    @staticmethod
    def _has_step_colon(
        content: str,
        keyword: str,
    ) -> bool:
        """
        Return ``True`` if a step keyword is followed by a colon.

        Step keywords must *not* use a colon; colons are reserved
        for heading keywords (``Feature:``, ``Scenario:``, etc.).

        """
        if not content.startswith(keyword):
            return False
        tail = content[len(keyword) :]
        return re.match(r"^\s*:", tail) is not None

    @staticmethod
    def _step_matches(
        content: str,
        keyword: str,
    ) -> str | None:
        """
        Match *content* against a step *keyword*.

        Returns the step text (after the keyword) on success, or
        ``None`` if the keyword does not match.  Keywords that
        include trailing whitespace are accepted as-is; otherwise
        a whitespace boundary is required to prevent false prefix
        matches.

        """
        if not content.startswith(keyword):
            return None
        tail = content[len(keyword) :]

        if keyword.endswith((" ", "\t")):
            return tail.lstrip(" \t").rstrip("\n")

        if tail[:1] not in (" ", "\t"):
            return None
        return tail.lstrip(" \t").rstrip("\n")

    # -- Keyword matching -------------------------------------------

    def _match_heading(
        self,
        content: str,
        matchers: DialectMatchers,
    ) -> tuple[str | None, str | None, str | None]:
        """
        Identify a heading keyword in *content*.

        Returns
        -------
        tuple[str | None, str | None, str | None]
            ``(heading_type, matched_keyword, heading_text)`` when
            a heading is found; ``(None, None, None)`` otherwise.

            ``heading_type`` is one of ``"feature"``, ``"rule"``,
            ``"background"``, ``"outline"``, ``"scenario"``, or
            ``"examples"``.

        """
        categories: tuple[tuple[str, list[str]], ...] = (
            ("feature", matchers.feature),
            ("rule", matchers.rule),
            ("background", matchers.background),
            ("outline", matchers.outline),
            ("scenario", matchers.scenario),
            ("examples", matchers.examples),
        )
        for h_type, keywords in categories:
            for kw in keywords:
                if self._has_heading_colon(content, kw):
                    text = self._extract_heading_text(
                        content,
                        kw,
                    )
                    return h_type, kw, text
        return None, None, None

    def _match_step(
        self,
        content: str,
        matchers: DialectMatchers,
    ) -> tuple[str | None, str | None, str | None]:
        """
        Identify a step keyword in *content*.

        Returns
        -------
        tuple[str | None, str | None, str | None]
            ``(canonical_kind, matched_keyword, step_text)`` when
            a step is found; ``(None, None, None)`` otherwise.

            When the step keyword is followed by an illegal colon,
            ``step_text`` is ``None`` (signalling the caller to
            emit rule A1.5).

            ``canonical_kind`` is one of ``"given"``, ``"when"``,
            ``"then"``, ``"and"``, ``"but"``, or ``"star"``.

        """
        star_result = self._match_star_step(content)
        if star_result is not None:
            return star_result

        return self._match_keyword_step(content, matchers)

    @staticmethod
    def _match_star_step(
        content: str,
    ) -> tuple[str, str, str | None] | None:
        """
        Match a ``*`` wildcard step keyword.

        Returns
        -------
        tuple[str, str, str | None] | None
            ``("star", "*", step_text)`` on match, or ``None``
            if no wildcard is found.

        """
        if not content.startswith("*"):
            return None
        if re.match(r"^\*\s*:", content):
            return "star", "*", None
        if len(content) == 1:
            return "star", "*", ""
        if content[1] not in (" ", "\t"):
            return None
        text = content[1:].lstrip(" \t").rstrip("\n")
        return "star", "*", text

    def _match_keyword_step(
        self,
        content: str,
        matchers: DialectMatchers,
    ) -> tuple[str | None, str | None, str | None]:
        """
        Match *content* against localised step keywords.

        Checks for illegal colons first, then for valid step
        matches.  A single pass over categories avoids the
        duplication of the original two-loop approach.

        Returns
        -------
        tuple[str | None, str | None, str | None]
            ``(canonical_kind, matched_keyword, step_text)`` or
            ``(None, None, None)`` when no match is found.

        """
        step_categories: tuple[tuple[str, list[str]], ...] = (
            ("given", matchers.given),
            ("when", matchers.when),
            ("then", matchers.then),
            ("and", matchers.and_),
            ("but", matchers.but),
        )

        # First pass: check for illegal colons.
        for kind, keywords in step_categories:
            for kw in keywords:
                if self._has_step_colon(content, kw):
                    return kind, kw, None

        # Second pass: match valid step text.
        for kind, keywords in step_categories:
            for kw in keywords:
                text = self._step_matches(content, kw)
                if text is not None:
                    return kind, kw, text

        return None, None, None

    # -- File linting -----------------------------------------------

    def lint_file(  # noqa: FNE005
        self,
        file_path: str,
    ) -> bool:
        """
        Lint a single ``.feature`` file.

        Diagnostics are appended to :attr:`issues`.  When
        ``--fix`` is active, the file is rewritten in place with
        corrected indentation for headings, steps, and tags.

        Parameters
        ----------
        file_path:
            Path to the ``.feature`` file.

        Returns
        -------
        bool
            ``True`` if no errors were recorded for this file.

        Raises
        ------
        FileReadError
            If the file cannot be read.

        """
        text = _read_feature_file(file_path)

        if not text:
            return True

        # Strip UTF-8 BOM from the first line so that keyword
        # matching is not disrupted.
        text[0] = self._strip_bom(text[0])

        dialect, _lang_code = self._get_dialect(
            text[0],
            self.all_languages,
        )
        matchers = DialectMatchers.from_dialect(dialect)

        state = _LintState()
        fixed_lines: list[str] = []
        error_baseline = len(self.issues)

        for idx, raw in enumerate(text, start=1):
            self._process_line(
                idx,
                raw,
                file_path,
                matchers,
                state,
                fixed_lines,
            )

        # End-of-file finalisation.  Capture the examples-table
        # state before _finalise_block resets it.
        eof_in_examples = state.in_examples_table
        eof_examples_empty = not state.examples_rows_seen
        self._finalise_block(file_path, "EOF", state)
        if eof_in_examples and eof_examples_empty:
            self._record_warning(
                file_path,
                "EOF",
                "A6.4",
                "Examples section has no table rows.",
            )

        if self.fix:
            Path(file_path).write_text(
                "\n".join(fixed_lines) + "\n",
                encoding="utf-8",
            )

        return not any(i.kind == "ERR" for i in self.issues[error_baseline:])

    # -- Per-line processing ----------------------------------------

    def _process_line(
        self,
        idx: int,
        raw: str,
        file_path: str,
        matchers: DialectMatchers,
        state: _LintState,
        fixed_lines: list[str],
    ) -> None:
        """
        Process a single source line.

        This is the inner loop of :meth:`lint_file`.  Processing
        is delegated to specialised helpers for each line category
        to keep cyclomatic complexity manageable.

        Parameters
        ----------
        idx:
            One-indexed line number.
        raw:
            The raw line including its newline character.
        file_path:
            Path string used in diagnostics.
        matchers:
            Keyword matchers for the active dialect.
        state:
            Mutable lint state for the current file.
        fixed_lines:
            Accumulator for reindented output lines.

        """
        line = raw.rstrip("\n")
        stripped = line.strip()

        # Blank lines are always permitted.
        if stripped == "":
            fixed_lines.append("")
            return

        # Comments are always permitted.
        if self._has_comment_prefix(line):
            self._check_language_header(
                idx,
                line,
                file_path,
            )
            fixed_lines.append(line)
            return

        # Reset step-argument expectation when the next line is
        # neither a table row nor a doc-string delimiter.
        self._reset_step_argument(stripped, state)

        # Doc-string state.
        if self._is_docstring_consumed(
            stripped,
            state,
            line,
            file_path,
            idx,
            fixed_lines,
        ):
            return

        # Tag lines.
        if self._is_tag_line_emitted(line, state, fixed_lines):
            return

        # Table rows (examples or data tables).
        if self._is_table_row_consumed(
            idx,
            line,
            stripped,
            file_path,
            state,
            fixed_lines,
        ):
            return

        if state.in_data_table:
            state.in_data_table = False
            state.expecting_step_argument = False

        # Determine active scope based on indentation.
        indent = self._leading_indent(line)
        state.resolve_scope(indent)

        self._process_keyword_or_description(
            idx,
            line,
            indent,
            file_path,
            matchers,
            state,
            fixed_lines,
        )

    def _check_language_header(
        self,
        idx: int,
        line: str,
        file_path: str,
    ) -> None:
        """Warn when a language header appears after line one."""
        if idx != 1 and LANG_HEADER_RE.match(
            line.lstrip("\ufeff"),
        ):
            self._record_warning(
                file_path,
                str(idx),
                "A8.1",
                "# language header only applies on the" " first line.",
            )

    def _reset_step_argument(
        self,
        stripped: str,
        state: _LintState,
    ) -> None:
        """Clear step-argument expectation when inapplicable.

        Resets the flag when the current line is neither a table
        row nor a doc-string delimiter.
        """
        if not state.expecting_step_argument:
            return
        if stripped.startswith("|"):
            return
        if self._detect_docstring_delim(stripped) is not None:
            return
        state.expecting_step_argument = False

    def _is_tag_line_emitted(
        self,
        line: str,
        state: _LintState,
        fixed_lines: list[str],
    ) -> bool:
        """Handle a tag line, returning ``True`` if consumed."""
        if not self._has_tag_prefix(line):
            return False
        state.in_description = None
        fixed_lines.append(
            self._reindent(
                line,
                "tag",
                state.block,
                state.rule_scope,
                state.feature_scope,
            )
            if self.fix
            else line
        )
        return True

    def _is_docstring_consumed(
        self,
        stripped: str,
        state: _LintState,
        line: str,
        file_path: str,
        idx: int,
        fixed_lines: list[str],
    ) -> bool:
        """
        Handle doc-string interior and opening-delimiter lines.

        Returns ``True`` when the line has been consumed.

        """
        # Interior line of an open doc-string.
        if state.in_docstring:
            if state.docstring_delim is not None and stripped == state.docstring_delim:
                state.in_docstring = False
                state.docstring_delim = None
                state.expecting_step_argument = False
            fixed_lines.append(line)
            return True

        # Opening delimiter.
        delim = self._detect_docstring_delim(stripped)
        if delim is not None:
            if not state.expecting_step_argument:
                self._record_error(
                    file_path,
                    str(idx),
                    "A7.1",
                    "Doc String delimiter must appear" " directly under a step.",
                )
            state.in_docstring = True
            state.docstring_delim = delim
            fixed_lines.append(line)
            return True

        return False

    def _is_table_row_consumed(
        self,
        idx: int,
        line: str,
        stripped: str,
        file_path: str,
        state: _LintState,
        fixed_lines: list[str],
    ) -> bool:
        """
        Handle examples-table continuation and data-table rows.

        Returns ``True`` when the line has been consumed.

        """
        # Examples-table continuation rows.
        if state.in_examples_table:
            if stripped.startswith("|"):
                state.examples_rows_seen = True
                fixed_lines.append(line)
                return True
            state.in_examples_table = False
            if not state.examples_rows_seen:
                self._record_warning(
                    file_path,
                    str(idx - 1),
                    "A6.4",
                    "Examples section has no table rows.",
                )
            state.examples_rows_seen = False

        # Data-table rows.
        if stripped.startswith("|"):
            if state.in_data_table or state.expecting_step_argument:
                state.in_data_table = True
                state.expecting_step_argument = True
                fixed_lines.append(line)
                return True
            self._record_error(
                file_path,
                str(idx),
                "A7.4",
                "Data Table row must appear directly"
                " under a step (or inside Examples).",
            )
            fixed_lines.append(line)
            return True

        return False

    def _process_keyword_or_description(
        self,
        idx: int,
        line: str,
        indent: int,
        file_path: str,
        matchers: DialectMatchers,
        state: _LintState,
        fixed_lines: list[str],
    ) -> None:
        """
        Match the line as a heading, step, or description.

        Emits A1.4 when no keyword is recognised and the line
        falls outside an allowed description region.

        """
        content = line.lstrip(" \t")
        h_type, h_kw, h_text = self._match_heading(
            content,
            matchers,
        )
        s_kind, _s_kw, s_text = self._match_step(
            content,
            matchers,
        )

        # Description continuation.
        if state.in_description is not None and h_type is None and s_kind is None:
            fixed_lines.append(line)
            return

        # Strict: every non-blank, non-comment line must begin
        # with a recognised keyword.
        if h_type is None and s_kind is None:
            self._record_error(
                file_path,
                str(idx),
                "A1.4",
                "Non-blank line must start with a Gherkin"
                " keyword (unless inside an allowed"
                " description or step argument).",
            )
            fixed_lines.append(line)
            return

        state.in_description = None

        if h_type is not None:
            self._handle_heading(
                idx,
                line,
                indent,
                file_path,
                h_type,
                h_kw,
                h_text,
                state,
                fixed_lines,
            )
        elif s_kind is not None:
            self._handle_step(
                idx,
                line,
                indent,
                file_path,
                s_kind,
                s_text,
                state,
                fixed_lines,
            )

    # -- Heading dispatch -------------------------------------------

    def _handle_heading(
        self,
        idx: int,
        line: str,
        indent: int,
        file_path: str,
        h_type: str,
        h_kw: str | None,
        h_text: str | None,
        state: _LintState,
        fixed_lines: list[str],
    ) -> None:
        """
        Process a heading keyword line.

        Parameters
        ----------
        idx:
            One-indexed line number.
        line:
            The original source line.
        indent:
            Leading whitespace width.
        file_path:
            Path string for diagnostics.
        h_type:
            Heading type (``"feature"``, ``"rule"``, etc.).
        h_kw:
            The matched keyword token.
        h_text:
            Descriptive text after the colon, if any.
        state:
            Mutable lint state.
        fixed_lines:
            Accumulator for output lines.

        """
        if h_type != "examples":
            self._finalise_block(file_path, str(idx), state)

        if h_type == "feature":
            self._handle_feature(
                idx,
                line,
                indent,
                file_path,
                h_text,
                state,
                fixed_lines,
            )
            return

        if not state.feature_seen:
            self._record_error(
                file_path,
                str(idx),
                "A2.1",
                "Feature must be the first primary" " keyword in the document.",
            )
            fixed_lines.append(line)
            return

        scope = state.active_scope()

        if h_type == "rule":
            state.rule_scope = Scope(
                "rule",
                indent=indent,
            )
            state.in_description = "rule"
            fixed_lines.append(
                self._reindent(
                    line,
                    "rule",
                    state.block,
                    state.rule_scope,
                    state.feature_scope,
                )
                if self.fix
                else line
            )
            return

        if h_type == "background":
            self._handle_background(
                idx,
                line,
                indent,
                file_path,
                scope,
                state,
                fixed_lines,
            )
            return

        if h_type in {"scenario", "outline"}:
            self._handle_scenario(
                idx,
                line,
                indent,
                file_path,
                h_type,
                scope,
                state,
                fixed_lines,
            )
            return

        if h_type == "examples":
            self._handle_examples(
                idx,
                line,
                file_path,
                state,
                fixed_lines,
            )
            return

        fixed_lines.append(line)

    def _handle_feature(
        self,
        idx: int,
        line: str,
        indent: int,
        file_path: str,
        h_text: str | None,
        state: _LintState,
        fixed_lines: list[str],
    ) -> None:
        """Process a ``Feature`` heading."""
        if state.feature_seen:
            self._record_error(
                file_path,
                str(idx),
                "A2.2",
                "Only one Feature is allowed per" " .feature file.",
            )
        state.feature_seen = True
        state.feature_scope = Scope(
            "feature",
            indent=indent,
        )
        state.rule_scope = None
        if h_text is None or h_text.strip() == "":
            self._record_error(
                file_path,
                str(idx),
                "A2.1",
                "Feature must be followed by ':' and a" " short descriptive text.",
            )
        state.in_description = "feature"
        fixed_lines.append(
            self._reindent(
                line,
                "feature",
                state.block,
                state.rule_scope,
                state.feature_scope,
            )
            if self.fix
            else line
        )

    def _handle_background(
        self,
        idx: int,
        line: str,
        indent: int,
        file_path: str,
        scope: Scope | None,
        state: _LintState,
        fixed_lines: list[str],
    ) -> None:
        """Process a ``Background`` heading."""
        if scope is None:
            self._record_error(
                file_path,
                str(idx),
                "A5.0",
                "Background must appear inside a Feature" " or Rule.",
            )
            fixed_lines.append(line)
            return
        if scope.background_defined:
            self._record_error(
                file_path,
                str(idx),
                "A5.3",
                "Only one Background is allowed per" " Feature or per Rule scope.",
            )
        if scope.scenarios_seen:
            self._record_error(
                file_path,
                str(idx),
                "A5.1",
                "Background must appear before the first"
                " Scenario/Example in the same scope.",
            )
        scope.background_defined = True
        state.block = Block(kind="background", indent=indent)
        state.in_description = "background"
        fixed_lines.append(
            self._reindent(
                line,
                "background",
                state.block,
                state.rule_scope,
                state.feature_scope,
            )
            if self.fix
            else line
        )

    def _handle_scenario(
        self,
        idx: int,
        line: str,
        indent: int,
        file_path: str,
        h_type: str,
        scope: Scope | None,
        state: _LintState,
        fixed_lines: list[str],
    ) -> None:
        """Process a ``Scenario`` or ``Scenario Outline`` heading."""
        if scope is None:
            self._record_error(
                file_path,
                str(idx),
                "A4.0",
                "Scenario must appear inside a Feature" " or Rule.",
            )
            fixed_lines.append(line)
            return
        scope.scenarios_seen = True
        kind = "outline" if h_type == "outline" else "scenario"
        state.block = Block(kind=kind, indent=indent)
        state.block.step_texts = set(scope.background_steps)
        state.block.step_count = 0
        state.in_description = kind
        fixed_lines.append(
            self._reindent(
                line,
                h_type,
                state.block,
                state.rule_scope,
                state.feature_scope,
            )
            if self.fix
            else line
        )

    def _handle_examples(
        self,
        idx: int,
        line: str,
        file_path: str,
        state: _LintState,
        fixed_lines: list[str],
    ) -> None:
        """Process an ``Examples`` heading."""
        if state.block is None or state.block.kind != "outline":
            self._record_error(
                file_path,
                str(idx),
                "A6.3",
                "Examples section is only valid under a" " Scenario Outline.",
            )
            fixed_lines.append(line)
            return
        state.block.examples_seen = True
        state.in_examples_table = True
        state.examples_rows_seen = False
        fixed_lines.append(
            self._reindent(
                line,
                "examples",
                state.block,
                state.rule_scope,
                state.feature_scope,
            )
            if self.fix
            else line
        )

    # -- Step dispatch ----------------------------------------------

    def _handle_step(
        self,
        idx: int,
        line: str,
        indent: int,
        file_path: str,
        s_kind: str,
        s_text: str | None,
        state: _LintState,
        fixed_lines: list[str],
    ) -> None:
        """
        Process a step keyword line.

        Parameters
        ----------
        idx:
            One-indexed line number.
        line:
            The original source line.
        indent:
            Leading whitespace width.
        file_path:
            Path string for diagnostics.
        s_kind:
            Canonical step kind (``"given"``, ``"when"``, etc.).
        s_text:
            Step body text, or ``None`` when the keyword is
            followed by an illegal colon.
        state:
            Mutable lint state.
        fixed_lines:
            Accumulator for output lines.

        """
        if not state.feature_seen:
            self._record_error(
                file_path,
                str(idx),
                "A2.1",
                "Step encountered before Feature.",
            )
            fixed_lines.append(line)
            return

        if s_text is None:
            self._record_error(
                file_path,
                str(idx),
                "A1.5",
                "Step keywords must not be followed" " by ':'.",
            )
            fixed_lines.append(line)
            return

        if state.block is None:
            self._record_error(
                file_path,
                str(idx),
                "A4.1",
                "Step found outside a Scenario/Example" " or Background.",
            )
            fixed_lines.append(line)
            return

        if state.block.kind == "background" and s_kind in {
            "when",
            "then",
        }:
            self._record_error(
                file_path,
                str(idx),
                "A5.2",
                "Background may only contain Given-like" " steps (Given/And/But/*).",
            )

        step_text = s_text.strip()
        if step_text in state.block.step_texts:
            self._record_error(
                file_path,
                str(idx),
                "A4.5",
                "Duplicate step text (step keywords" f" ignored): '{step_text}'.",
            )
        state.block.step_texts.add(step_text)
        state.block.step_count += 1

        scope = state.active_scope()
        if scope is not None and state.block.kind == "background":
            scope.background_steps.add(step_text)

        state.expecting_step_argument = True
        fixed_lines.append(
            self._reindent(
                line,
                "step",
                state.block,
                state.rule_scope,
                state.feature_scope,
            )
            if self.fix
            else line
        )

    # -- Block finalisation -----------------------------------------

    def _finalise_block(
        self,
        file_path: str,
        at_line_no: str,
        state: _LintState,
    ) -> None:
        """
        Finalise the current block and emit deferred diagnostics.

        Called when a new heading is encountered or at end-of-file.

        Parameters
        ----------
        file_path:
            Path string for diagnostics.
        at_line_no:
            Line number triggering the finalisation.
        state:
            Mutable lint state.

        """
        if state.block is None:
            return

        if state.block.kind == "outline" and not state.block.examples_seen:
            self._record_error(
                file_path,
                at_line_no,
                "A6.3",
                "Scenario Outline missing required" " Examples section.",
            )

        if state.block.kind in {"scenario", "outline"} and state.block.step_count > 5:
            self._record_warning(
                file_path,
                at_line_no,
                "B2.1",
                f"Scenario has {state.block.step_count}"
                " steps (recommended 3\u20135).",
            )

        state.block = None
        state.in_examples_table = False
        state.examples_rows_seen = False
        state.in_data_table = False
        state.expecting_step_argument = False

    # -- Indentation fix --------------------------------------------

    @staticmethod
    def _reindent(
        original_line: str,
        token_type: str,
        block: Block | None,
        rule_scope: Scope | None,
        feature_scope: Scope | None,
    ) -> str:
        """
        Return *original_line* with recommended indentation applied.

        Only applied to headings, steps, and tags.  The heuristic
        is:

        ====================================  =====
        Token                                 Indent
        ====================================  =====
        ``Feature``                           0
        ``Rule``                              2
        Feature-level Scenario / Background   2
        Rule-level Scenario / Background      4
        Steps                                 block + 2
        ``Examples``                          block + 2
        Tags                                  aligned to block
        ====================================  =====

        Parameters
        ----------
        original_line:
            The raw source line.
        token_type:
            One of ``"feature"``, ``"rule"``, ``"scenario"``,
            ``"outline"``, ``"background"``, ``"examples"``,
            ``"step"``, or ``"tag"``.
        block:
            The current executable block, if any.
        rule_scope:
            The current ``Rule`` scope, if any.
        feature_scope:
            The current ``Feature`` scope, if any.

        Returns
        -------
        str
            The line with corrected leading whitespace.

        """
        content = original_line.lstrip(" \t")
        is_in_rule = rule_scope is not None

        if token_type == "feature":
            return f"{_indent_spaces(0)}{content}"
        if token_type == "rule":
            return f"{_indent_spaces(2)}{content}"

        base = 4 if is_in_rule else 2

        if token_type in {
            "scenario",
            "outline",
            "background",
        }:
            return f"{_indent_spaces(base)}{content}"
        if token_type in {"examples", "step"}:
            return f"{_indent_spaces(base + 2)}{content}"
        if token_type == "tag":
            return f"{_indent_spaces(base)}{content}"

        return original_line


# ---------------------------------------------------------------------------
# Module-level helpers (extracted to reduce class/method complexity)
# ---------------------------------------------------------------------------


def _languages_from_file(languages_path: str) -> dict[str, Any]:
    """
    Load and validate the Gherkin languages JSON file.

    Parameters
    ----------
    languages_path:
        Filesystem path to ``gherkin-languages.json``.

    Returns
    -------
    dict[str, Any]
        The parsed languages dictionary.

    Raises
    ------
    DialectLoadError
        If the file cannot be read or contains invalid JSON.
    DialectSchemaError
        If the ``"en"`` dialect is missing.

    """
    path = Path(languages_path)
    try:
        raw = path.read_text(encoding="utf-8")
        all_languages: dict[str, Any] = json.loads(raw)
    except OSError as exc:
        raise DialectLoadError(
            f"Cannot read languages file" f" '{languages_path}': {exc}",
        ) from exc
    except (json.JSONDecodeError, ValueError) as exc:
        raise DialectLoadError(
            f"Invalid JSON in '{languages_path}': {exc}",
        ) from exc

    if "en" not in all_languages:
        raise DialectSchemaError(
            "Languages JSON must contain an 'en' dialect.",
        )
    return all_languages


def _read_feature_file(file_path: str) -> list[str]:
    """
    Read a ``.feature`` file and return its lines.

    Parameters
    ----------
    file_path:
        Path to the ``.feature`` file.

    Returns
    -------
    list[str]
        Lines with newline characters preserved.

    Raises
    ------
    FileReadError
        If the file cannot be read or decoded.

    """
    path = Path(file_path)
    try:
        return path.read_text(
            encoding="utf-8",
        ).splitlines(keepends=True)
    except OSError as exc:
        raise FileReadError(
            f"Cannot read '{file_path}': {exc}",
        ) from exc
    except UnicodeDecodeError as exc:
        raise FileReadError(
            f"Encoding error in '{file_path}': {exc}",
        ) from exc


def _collect_feature_paths(targets: list[str]) -> list[str]:
    """
    Expand CLI targets into a sorted list of ``.feature`` paths.

    Parameters
    ----------
    targets:
        File paths or directory paths from the command line.

    Returns
    -------
    list[str]
        Resolved ``.feature`` file paths.

    """
    files: list[str] = []
    for target in targets:
        path = Path(target)
        if path.is_dir():
            files.extend(str(fp) for fp in path.rglob("*.feature"))
        elif path.suffix == ".feature" and path.exists():
            files.append(str(path))
    return files


def _report_results(
    linter: GherkinProLinter,
    file_count: int,
    *,
    strict: bool,
) -> int:
    """
    Print diagnostics and return the appropriate exit code.

    Parameters
    ----------
    linter:
        The linter instance with accumulated issues.
    file_count:
        Number of files that were linted.
    strict:
        Whether warnings are promoted to errors.

    Returns
    -------
    int
        ``0`` for success, ``1`` for failure.

    """
    errors, warns = _split_by_severity(linter.issues)
    _print_diagnostics(errors, warns)

    fail_count = len(errors) + (len(warns) if strict else 0)
    if fail_count > 0:
        print(
            f"\nFailed with {fail_count} error(s)" f" and {len(warns)} warning(s).",
        )
        return 1

    print(f"\nSuccessfully linted {file_count} file(s).")
    return 0


def _split_by_severity(
    issues: list[Issue],
) -> tuple[list[Issue], list[Issue]]:
    """Split issues into errors and warnings."""
    errors = [i for i in issues if i.kind == "ERR"]
    warns = [i for i in issues if i.kind == "WARN"]
    return errors, warns


def _print_diagnostics(
    errors: list[Issue],
    warns: list[Issue],
) -> None:
    """Print all diagnostic messages to stdout."""
    for issue in warns:
        print(issue.render())
    for issue in errors:
        print(issue.render())


# ---------------------------------------------------------------------------
# Internal mutable state for a single file lint pass
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _LintState:
    """
    Mutable state tracked across lines within a single file.

    Encapsulates every piece of state that :meth:`lint_file` and
    its helpers need to share, avoiding a large number of
    ``nonlocal`` declarations.
    """

    feature_seen: bool = False
    feature_scope: Scope | None = None
    rule_scope: Scope | None = None

    block: Block | None = None

    in_docstring: bool = False
    docstring_delim: str | None = None

    in_data_table: bool = False
    in_examples_table: bool = False
    examples_rows_seen: bool = False

    expecting_step_argument: bool = False
    in_description: str | None = None

    def resolve_scope(self, indent: int) -> None:
        """
        Drop the ``Rule`` scope when indentation returns above it.

        Clears :attr:`rule_scope` when the current line's
        indentation is at or above the ``Rule`` keyword's column.

        """
        if self.rule_scope is not None and indent <= self.rule_scope.indent:
            self.rule_scope = None

    def active_scope(self) -> Scope | None:
        """
        Return the innermost active scope.

        Returns the ``Rule`` scope if one exists, otherwise the
        ``Feature`` scope.

        """
        if self.rule_scope is not None:
            return self.rule_scope
        return self.feature_scope


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """
    Run the linter from the command line.

    Exit codes
    ----------
    0
        All files passed (no errors; no warnings if ``--strict``).
    1
        One or more errors (or warnings in ``--strict`` mode).

    """
    args = _parse_cli_args()

    if not args.targets:
        raise SystemExit(0)

    try:
        linter = GherkinProLinter(
            args.languages,
            verbose=args.verbose,
            strict=args.strict,
            fix=args.fix,
        )
    except LinterError as exc:
        print(
            f"Configuration error: {exc}",
            file=sys.stderr,
        )
        raise SystemExit(2) from exc

    files = _collect_feature_paths(args.targets)

    if not files:
        raise SystemExit(0)

    for filepath in files:
        try:
            linter.lint_file(filepath)
        except FileReadError as exc:
            print(f"File error: {exc}", file=sys.stderr)
            linter._record_error(
                filepath,
                "EOF",
                "IO",
                str(exc),
            )

    raise SystemExit(
        _report_results(
            linter,
            len(files),
            strict=args.strict,
        ),
    )


def _parse_cli_args() -> argparse.Namespace:
    """
    Parse command-line arguments for the Gherkin linter.

    Returns
    -------
    argparse.Namespace
        The parsed arguments.

    """
    parser = argparse.ArgumentParser(
        description=("Gherkin Reference Linter" " (strict rules by default)."),
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help="One or more .feature files (or directories).",
    )
    parser.add_argument(
        "--languages",
        default="gherkin-languages.json",
        help="Path to gherkin-languages.json.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output.",
    )
    parser.add_argument(
        "-s",
        "--strict",
        action="store_true",
        help=("Treat recommendations (warnings) as errors."),
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help=("Apply indentation fixes to headings, steps," " and tags."),
    )
    return parser.parse_args()


if __name__ == "__main__":
    main()
