# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

r"""Gemara evidence collector.

Reads evidence from multiple sources, maps results to
Layer 2 assessment requirement IDs, and produces a
schema-valid Gemara Layer 5 EvaluationLog and a
traceability matrix.

Evidence sources
----------------
1. Static evaluation (evaluate_controls.py YAML output)
2. JUnit XML (pytest with ``@pytest.mark.control``)
3. Cucumber JSON (Gherkin with ``@PK-*`` tags)
4. OPA JSON (violations referencing PK-* IDs)

Usage::

    python collect_evidence.py \\
        --catalog gemara/platteklip-controls.yaml \\
        --guidance gemara/iec-62443-3-3.yaml \\
        --static-eval gemara/platteklip-eval.yaml \\
        --junit tests/test-results.xml \\
        --cucumber tests/cucumber.json \\
        --opa-json policy/opa-results.json \\
        --output gemara/evaluation-log.yaml \\
        --matrix gemara/traceability.yaml

All flags except ``--catalog`` are optional.  Missing
sources are skipped without error.

Validate the output::

    cue vet -c -d '#EvaluationLog' \\
        github.com/gemaraproj/gemara@latest \\
        gemara/evaluation-log.yaml
"""

import argparse
import datetime
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

import defusedxml.ElementTree as ET
import yaml

# ------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------

PASS: Final[str] = "Pass"
FAIL: Final[str] = "Fail"
NOT_APPLICABLE: Final[str] = "Not Applicable"
ERROR: Final[str] = "Error"
UNTESTED: Final[str] = "Untested"

CATALOG_REF: Final[str] = "PK.EDGE"

_PK_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^PK-[\w.-]+$",
)
_PK_AR_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^(PK-[\w-]+\.\d+)",
)


# ------------------------------------------------------------------
# Evidence record
# ------------------------------------------------------------------


@dataclass(slots=True)
class EvidenceRecord:
    """A single piece of evidence for an AR."""

    source: str
    result: str
    message: str
    steps: list[str] = field(default_factory=list)
    confidence: str = ""


# ------------------------------------------------------------------
# Catalog loader
# ------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AssessmentReq:
    """Parsed assessment requirement from the catalog."""

    ar_id: str
    control_id: str
    control_title: str
    text: str
    applicability: list[str]
    state: str
    l1_guidelines: list[str]


def read_catalog(
    catalog_path: Path,
    guidance_path: Path | None = None,
) -> dict[str, AssessmentReq]:
    """Load the L2 catalog and resolve L1 references.

    Returns a dict keyed by AR ID.
    """
    with catalog_path.open() as f:
        catalog = yaml.safe_load(f)

    if guidance_path and guidance_path.is_file():
        with guidance_path.open() as f:
            yaml.safe_load(f)

    ars: dict[str, AssessmentReq] = {}

    for ctrl in catalog.get("controls", []):
        _parse_control(ctrl, ars)

    return ars


def _parse_control(
    ctrl: dict,
    ars: dict[str, AssessmentReq],
) -> None:
    """Parse a single control into AR entries."""
    ctrl_id = ctrl["id"]
    ctrl_title = ctrl["title"]

    l1_refs: list[str] = []
    for gmap in ctrl.get("guidelines", []):
        for entry in gmap.get("entries", []):
            ref = entry.get("reference-id", "")
            if ref:
                l1_refs.append(ref)

    for ar in ctrl.get(
        "assessment-requirements",
        [],
    ):
        ar_id = ar["id"]
        ars[ar_id] = AssessmentReq(
            ar_id=ar_id,
            control_id=ctrl_id,
            control_title=ctrl_title,
            text=ar.get("text", "").strip(),
            applicability=ar.get(
                "applicability",
                [],
            ),
            state=ar.get("state", "Active"),
            l1_guidelines=l1_refs,
        )


# ------------------------------------------------------------------
# Evidence parsers
# ------------------------------------------------------------------


def parse_static_eval(
    path: Path,
) -> dict[str, list[EvidenceRecord]]:
    """Parse evaluate_controls.py YAML output."""
    evidence: dict[str, list[EvidenceRecord]] = defaultdict(list)

    if not path.is_file():
        return evidence

    with path.open() as f:
        log = yaml.safe_load(f)

    if not log:
        return evidence

    for ctrl_eval in log.get("evaluations", []):
        for alog in ctrl_eval.get(
            "assessment-logs",
            [],
        ):
            req = alog.get("requirement", {})
            ar_id = req.get("entry-id", "")
            if not ar_id:
                continue

            evidence[ar_id].append(
                EvidenceRecord(
                    source="static-eval",
                    result=alog.get("result", ERROR),
                    message=alog.get("message", ""),
                    steps=alog.get("steps", []),
                ),
            )

    return evidence


# -- JUnit XML ----------------------------------------------------


def _find_testcases(
    root: ET.Element,
) -> list[ET.Element]:
    """Collect testcase elements from JUnit XML."""
    if root.tag == "testsuites":
        cases: list[ET.Element] = []
        for suite in root.iter("testsuite"):
            cases.extend(
                suite.findall("testcase"),
            )
        return cases
    if root.tag == "testsuite":
        return root.findall("testcase")
    return list(root.iter("testcase"))


def _tc_result(
    tc: ET.Element,
    full_name: str,
) -> tuple[str, str]:
    """Determine result and message for a testcase."""
    failure = tc.find("failure")
    if failure is not None:
        msg = failure.get("message", "") or failure.text or "Test failed"
        return FAIL, msg

    error = tc.find("error")
    if error is not None:
        msg = error.get("message", "") or error.text or "Test error"
        return ERROR, msg

    skipped = tc.find("skipped")
    if skipped is not None:
        msg = skipped.get("message", "") or "Skipped"
        return NOT_APPLICABLE, msg

    return PASS, f"Test passed: {full_name}"


def _tc_ar_ids(tc: ET.Element) -> list[str]:
    """Extract AR IDs from testcase properties."""
    ar_ids: list[str] = []
    props = tc.find("properties")
    if props is not None:
        for prop in props.findall("property"):
            if prop.get("name") == "control":
                ar_ids.append(
                    prop.get("value", ""),
                )
    return ar_ids


def parse_junit_xml(
    path: Path,
) -> dict[str, list[EvidenceRecord]]:
    """Parse JUnit XML with control properties."""
    evidence: dict[str, list[EvidenceRecord]] = defaultdict(list)

    if not path.is_file():
        return evidence

    tree = ET.parse(path)
    testcases = _find_testcases(tree.getroot())

    for tc in testcases:
        name = tc.get("name", "")
        classname = tc.get("classname", "")
        full_name = f"{classname}::{name}"

        ar_ids = _tc_ar_ids(tc)
        if not ar_ids:
            continue

        result, msg = _tc_result(tc, full_name)

        for ar_id in ar_ids:
            if ar_id:
                evidence[ar_id].append(
                    EvidenceRecord(
                        source="pytest",
                        result=result,
                        message=msg,
                        steps=[full_name],
                    ),
                )

    return evidence


# -- Cucumber JSON -------------------------------------------------


def _extract_pk_tags(
    element: dict,
) -> list[str]:
    """Extract PK-* tags from a Cucumber element."""
    tags: list[str] = [t.get("name", "").lstrip("@") for t in element.get("tags", [])]
    return [t for t in tags if _PK_PATTERN.match(t)]


def _scenario_result(
    element: dict,
) -> tuple[bool, list[str]]:
    """Determine pass/fail and step names for a scenario."""
    steps = element.get("steps", [])
    step_names: list[str] = []
    passed = True

    for step in steps:
        step_name = f"{step.get('keyword', '').strip()}" f" {step.get('name', '')}"
        step_names.append(step_name)
        status = step.get("result", {}).get("status", "")
        if status in ("failed", "undefined"):
            passed = False

    return passed, step_names


def parse_cucumber_json(
    path: Path,
) -> dict[str, list[EvidenceRecord]]:
    """Parse Cucumber JSON with @PK-* tags."""
    evidence: dict[str, list[EvidenceRecord]] = defaultdict(list)

    if not path.is_file():
        return evidence

    with path.open() as f:
        data = json.load(f)

    for feature in data:
        feature_pks = _extract_pk_tags(feature)

        for element in feature.get("elements", []):
            if element.get("type") != "scenario":
                continue

            scenario_pks = _extract_pk_tags(element)
            all_pks = scenario_pks or feature_pks
            if not all_pks:
                continue

            name = element.get("name", "")
            passed, step_names = _scenario_result(
                element,
            )
            result = PASS if passed else FAIL
            msg = f"Scenario: {name}" if passed else f"Scenario failed: {name}"

            for pk_id in all_pks:
                evidence[pk_id].append(
                    EvidenceRecord(
                        source="gherkin",
                        result=result,
                        message=msg,
                        steps=step_names,
                    ),
                )

    return evidence


# -- OPA JSON ------------------------------------------------------


def _extract_opa_violations(
    data: object,
) -> list[str]:
    """Extract violation strings from OPA output."""
    violations: list[str] = []

    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                result = item.get("result", [])
                if isinstance(result, list):
                    violations.extend(str(v) for v in result)
        return violations

    if not isinstance(data, dict):
        return violations

    for item in data.get("result", []):
        if isinstance(item, str):
            violations.append(item)
        elif isinstance(item, dict):
            _extract_nested_violations(
                item,
                violations,
            )

    return violations


def _extract_nested_violations(
    item: dict,
    violations: list[str],
) -> None:
    """Extract violations from nested OPA expressions."""
    for expr in item.get("expressions", []):
        val = expr.get("value", [])
        if isinstance(val, list):
            violations.extend(str(v) for v in val)


def parse_opa_json(
    path: Path,
) -> dict[str, list[EvidenceRecord]]:
    """Parse OPA JSON output for PK-* violations."""
    evidence: dict[str, list[EvidenceRecord]] = defaultdict(list)

    if not path.is_file():
        return evidence

    with path.open() as f:
        data = json.load(f)

    for violation in _extract_opa_violations(data):
        m = _PK_AR_PATTERN.match(violation)
        if m:
            evidence[m.group(1)].append(
                EvidenceRecord(
                    source="opa",
                    result=FAIL,
                    message=violation,
                    steps=["OPA policy violation detected"],
                ),
            )

    return evidence


# ------------------------------------------------------------------
# Evidence merging
# ------------------------------------------------------------------


def merge_evidence(
    *sources: dict[str, list[EvidenceRecord]],
) -> dict[str, list[EvidenceRecord]]:
    """Merge multiple evidence dicts by AR ID."""
    merged: dict[str, list[EvidenceRecord]] = defaultdict(list)
    for source in sources:
        for ar_id, records in source.items():
            merged[ar_id].extend(records)
    return merged


def resolve_ar_result(
    records: list[EvidenceRecord],
) -> str:
    """Determine aggregate result for an AR.

    Any FAIL from any source means FAIL.
    Any ERROR with no FAIL means ERROR.
    All PASS or NOT_APPLICABLE means PASS.
    No records means UNTESTED.
    """
    if not records:
        return UNTESTED

    results = {r.result for r in records}

    if FAIL in results:
        return FAIL
    if ERROR in results:
        return ERROR
    if results <= {PASS, NOT_APPLICABLE}:
        return PASS
    return ERROR


# ------------------------------------------------------------------
# Evaluation log builder
# ------------------------------------------------------------------


def _build_ar_entry(
    ar: AssessmentReq,
    records: list[EvidenceRecord],
    ts: str,
) -> tuple[dict, str]:
    """Build an assessment log entry for one AR.

    Returns the entry dict and the resolved result.
    """
    ar_result = resolve_ar_result(records)

    source_msgs: list[str] = []
    all_steps: list[str] = []
    for rec in records:
        source_msgs.append(
            f"[{rec.source}] {rec.message}",
        )
        all_steps.extend(rec.steps)

    if not source_msgs:
        source_msgs = ["No evidence collected for " "this requirement."]
        all_steps = ["No checks executed"]
        ar_result = FAIL

    entry = {
        "requirement": {
            "entry-id": ar.ar_id,
            "reference-id": CATALOG_REF,
        },
        "applicability": ar.applicability,
        "description": ar.text,
        "message": "; ".join(source_msgs),
        "result": ar_result,
        "start": ts,
        "steps": all_steps or ["No steps recorded"],
    }

    return entry, ar_result


def build_evaluation_log(
    ars: dict[str, AssessmentReq],
    evidence: dict[str, list[EvidenceRecord]],
    ts: str,
) -> dict:
    """Build a Gemara L5 EvaluationLog."""
    controls: dict[str, list[AssessmentReq]] = defaultdict(list)
    for ar in ars.values():
        controls[ar.control_id].append(ar)

    evaluations: list[dict] = []
    total_fail = 0

    for ctrl_id, ctrl_ars in sorted(
        controls.items(),
    ):
        ctrl_title = ctrl_ars[0].control_title
        assessment_logs: list[dict] = []
        ctrl_pass = True

        for ar in sorted(
            ctrl_ars,
            key=lambda a: a.ar_id,
        ):
            records = evidence.get(ar.ar_id, [])
            entry, ar_result = _build_ar_entry(
                ar,
                records,
                ts,
            )
            assessment_logs.append(entry)

            if ar_result in (FAIL, ERROR, UNTESTED):
                ctrl_pass = False
            if ar_result == FAIL:
                total_fail += 1

        ctrl_result = PASS if ctrl_pass else FAIL
        evaluations.append(
            {
                "control": {
                    "entry-id": ctrl_id,
                    "reference-id": CATALOG_REF,
                },
                "name": ctrl_title,
                "message": (
                    f"{ctrl_result}: "
                    f"{len(assessment_logs)} "
                    f"requirements evaluated"
                ),
                "result": ctrl_result,
                "assessment-logs": assessment_logs,
            },
        )

    aggregate = PASS if total_fail == 0 else FAIL
    return {
        "result": aggregate,
        "evaluations": evaluations,
    }


# ------------------------------------------------------------------
# Traceability matrix builder
# ------------------------------------------------------------------


def build_traceability(
    ars: dict[str, AssessmentReq],
    evidence: dict[str, list[EvidenceRecord]],
) -> list[dict]:
    """Build a traceability matrix.

    Each entry maps an AR to its L1 guidelines,
    evidence sources, and aggregate result.
    """
    matrix: list[dict] = []

    for ar_id in sorted(ars):
        ar = ars[ar_id]
        records = evidence.get(ar_id, [])
        result = resolve_ar_result(records)

        sources = _worst_result_per_source(records)

        matrix.append(
            {
                "ar-id": ar_id,
                "control-id": ar.control_id,
                "control-title": ar.control_title,
                "l1-guidelines": ar.l1_guidelines,
                "state": ar.state,
                "evidence": (
                    sources
                    or {
                        "none": UNTESTED,
                    }
                ),
                "result": result,
            },
        )

    return matrix


def _worst_result_per_source(
    records: list[EvidenceRecord],
) -> dict[str, str]:
    """Aggregate worst result per evidence source."""
    sources: dict[str, str] = {}
    for rec in records:
        existing = sources.get(rec.source, PASS)
        if rec.result == FAIL:
            sources[rec.source] = FAIL
        elif rec.result == ERROR and existing != FAIL:
            sources[rec.source] = ERROR
        elif rec.source not in sources:
            sources[rec.source] = rec.result
    return sources


# ------------------------------------------------------------------
# Summary stats
# ------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _ResultCounts:
    """Aggregated result counts from a matrix."""

    total: int
    passed: int
    failed: int
    errors: int
    untested: int
    not_applicable: int
    sources: set[str]


def _count_results(
    matrix: list[dict],
) -> _ResultCounts:
    """Count results by category."""
    counts: dict[str, int] = {
        PASS: 0,
        FAIL: 0,
        ERROR: 0,
        UNTESTED: 0,
        NOT_APPLICABLE: 0,
    }
    sources: set[str] = set()
    for m in matrix:
        counts[m["result"]] = counts.get(m["result"], 0) + 1
        sources.update(m["evidence"].keys())
    sources.discard("none")

    return _ResultCounts(
        total=len(matrix),
        passed=counts[PASS],
        failed=counts[FAIL],
        errors=counts[ERROR],
        untested=counts[UNTESTED],
        not_applicable=counts[NOT_APPLICABLE],
        sources=sources,
    )


def _print_items(
    label: str,
    matrix: list[dict],
    result_filter: str,
    out: object,
) -> None:
    """Print a filtered list of AR results."""
    items = [m for m in matrix if m["result"] == result_filter]
    if not items:
        return
    print(f"  {label}:", file=out)
    for m in items:
        print(
            f"    {m['ar-id']:16s} " f"{m['control-title']}",
            file=out,
        )
    print(file=out)


def print_summary(
    matrix: list[dict],
    out: object = sys.stderr,
) -> None:
    """Print a human-readable summary to stderr."""
    c = _count_results(matrix)

    w = 56
    src_str = ", ".join(sorted(c.sources)) or "none"
    coverage = (c.passed + c.not_applicable) / c.total * 100 if c.total > 0 else 0
    aggregate = PASS if c.failed == 0 else FAIL

    print(f"\n{'=' * w}", file=out)
    print(
        "  Gemara Evidence Collection Summary",
        file=out,
    )
    print(f"{'=' * w}", file=out)
    print(
        f"  Assessment requirements : {c.total}",
        file=out,
    )
    print(
        f"  Evidence sources        : {src_str}",
        file=out,
    )
    print(f"{'─' * w}", file=out)
    print(f"  Pass            : {c.passed}", file=out)
    print(f"  Fail            : {c.failed}", file=out)
    print(f"  Error           : {c.errors}", file=out)
    print(
        f"  Not applicable  : {c.not_applicable}",
        file=out,
    )
    print(
        f"  Untested        : {c.untested}",
        file=out,
    )
    print(f"{'─' * w}", file=out)
    print(
        f"  Coverage        : {coverage:.1f}%",
        file=out,
    )
    print(
        f"  Aggregate       : {aggregate}",
        file=out,
    )
    print(f"{'=' * w}\n", file=out)

    _print_items(
        "Failed requirements",
        matrix,
        FAIL,
        out,
    )
    _print_items(
        "Untested requirements",
        matrix,
        UNTESTED,
        out,
    )


# ------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------


def parse_args(
    argv: list[str] | None = None,
) -> argparse.Namespace:
    """Parse command-line arguments."""
    p = argparse.ArgumentParser(
        description=(
            "Collect evidence from multiple sources "
            "and produce a Gemara L5 EvaluationLog."
        ),
    )
    p.add_argument(
        "--catalog",
        type=Path,
        required=True,
        help="Path to platteklip-controls.yaml",
    )
    p.add_argument(
        "--guidance",
        type=Path,
        default=None,
        help=("Path to iec-62443-3-3.yaml (optional)"),
    )
    p.add_argument(
        "--static-eval",
        type=Path,
        default=None,
        help=("Path to evaluate_controls.py YAML output"),
    )
    p.add_argument(
        "--junit",
        type=Path,
        default=None,
        help="Path to JUnit XML (pytest output)",
    )
    p.add_argument(
        "--cucumber",
        type=Path,
        default=None,
        help=("Path to Cucumber JSON (Gherkin output)"),
    )
    p.add_argument(
        "--opa-json",
        type=Path,
        default=None,
        help="Path to OPA JSON output",
    )
    p.add_argument(
        "--output",
        type=Path,
        default=None,
        help=("Write EvaluationLog YAML to file " "(default: stdout)"),
    )
    p.add_argument(
        "--matrix",
        type=Path,
        default=None,
        help="Write traceability matrix YAML to file",
    )
    return p.parse_args(argv)


# ------------------------------------------------------------------
# Evidence gathering
# ------------------------------------------------------------------

_YAML_OPTS: Final[dict] = {
    "default_flow_style": False,
    "sort_keys": False,
    "allow_unicode": True,
    "width": 72,
}


def _gather_sources(
    args: argparse.Namespace,
) -> list[dict[str, list[EvidenceRecord]]]:
    """Collect evidence from each configured source."""
    sources: list[dict[str, list[EvidenceRecord]]] = []
    if args.static_eval:
        sources.append(
            parse_static_eval(args.static_eval),
        )
    if args.junit:
        sources.append(
            parse_junit_xml(args.junit),
        )
    if args.cucumber:
        sources.append(
            parse_cucumber_json(args.cucumber),
        )
    if args.opa_json:
        sources.append(
            parse_opa_json(args.opa_json),
        )
    return sources


def _expand_to_child_ars(
    evidence: dict[str, list[EvidenceRecord]],
    ars: dict[str, AssessmentReq],
) -> dict[str, list[EvidenceRecord]]:
    """Expand control-level evidence to all child ARs.

    For example, evidence tagged ``@PK-IA-01`` is
    expanded to PK-IA-01.01, PK-IA-01.02, etc.
    """
    expanded: dict[str, list[EvidenceRecord]] = defaultdict(list)
    for key, records in evidence.items():
        if key in ars:
            expanded[key].extend(records)
        else:
            matching = [ar_id for ar_id in ars if ar_id.startswith(f"{key}.")]
            for ar_id in matching:
                expanded[ar_id].extend(records)
    return expanded


def _emit_yaml(data: object, path: Path) -> None:
    """Write YAML data to a file."""
    with path.open("w") as f:
        yaml.dump(data, f, **_YAML_OPTS)


def main(
    argv: list[str] | None = None,
) -> int:
    """CLI entry point. Returns 0 on PASS, 1 on FAIL."""
    args = parse_args(argv)

    ars = read_catalog(args.catalog, args.guidance)
    if not ars:
        sys.stderr.write(
            "No assessment requirements found in " "catalog.\n",
        )
        return 1

    sources = _gather_sources(args)
    evidence = merge_evidence(*sources)
    expanded = _expand_to_child_ars(evidence, ars)

    ts = datetime.datetime.now(
        tz=datetime.UTC,
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    eval_log = build_evaluation_log(
        ars,
        expanded,
        ts,
    )
    matrix = build_traceability(ars, expanded)

    if args.output:
        _emit_yaml(eval_log, args.output)
    else:
        yaml.dump(eval_log, sys.stdout, **_YAML_OPTS)

    if args.matrix:
        _emit_yaml(
            {"traceability": matrix},
            args.matrix,
        )

    print_summary(matrix)

    failures = sum(1 for m in matrix if m["result"] == FAIL)
    return 1 if failures > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
