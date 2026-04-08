# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

"""Step implementations for PK.RA features.

Background steps and shared inspection steps are in
requirements/security/steps/test_shared_steps.py.
"""

import re

from behave import then, when

# ----------------------------------------------------------------
# PK-RA-01: Container resource limits
# ----------------------------------------------------------------


@when(
    "each service's deploy.resources.limits is" " inspected",
)
def step_inspect_limits(context: object) -> None:
    """Collect resource limits for every service."""
    context.limit_results = {}
    for name, svc in context.compose["services"].items():
        limits = svc.get("deploy", {}).get("resources", {}).get("limits", {})
        context.limit_results[name] = limits


@then('every service MUST define a "{field}" limit')
def step_check_limit_field(
    context: object,
    field: str,
) -> None:
    """Assert every service defines the given limit."""
    missing = [
        name for name, limits in context.limit_results.items() if field not in limits
    ]
    assert not missing, f"Services missing '{field}' limit: " f"{', '.join(missing)}"


# ----------------------------------------------------------------
# PK-RA-02: OTel Collector memory limiter
# ----------------------------------------------------------------


@then('the first processor MUST be "{processor}"')
def step_check_first_processor(
    context: object,
    processor: str,
) -> None:
    """Assert the named processor is first in each pipeline."""
    failures = []
    for name, procs in context.pipeline_processors.items():
        first = procs[0] if procs else "none"
        if not procs or processor not in first:
            failures.append(f"{name}: first is '{first}'")
    assert not failures, (
        f"Pipelines where {processor} is not first: " f"{'; '.join(failures)}"
    )


@then(
    "this MUST hold for metrics, logs, and traces" " pipelines",
)
def step_check_all_signal_types(
    context: object,
) -> None:
    """Assert metrics, logs, and traces pipelines exist."""
    expected = {"metrics", "logs", "traces"}
    present = set(context.pipeline_processors.keys())
    missing = expected - present
    assert not missing, f"Missing pipelines: {', '.join(missing)}"


@when("the memory_limiter limit_mib is inspected")
def step_inspect_limiter_config(
    context: object,
) -> None:
    """Read the memory_limiter limit_mib value."""
    processors = context.otel_config.get(
        "processors",
        {},
    )
    limiter = processors.get("memory_limiter", {})
    context.limit_mib = limiter.get("limit_mib", 0)


@then(
    "limit_mib MUST be at most 75% of the container" " memory limit",
)
def step_check_limiter_calibration(
    context: object,
) -> None:
    """Assert limit_mib does not exceed 75% of container."""
    max_allowed = int(
        context.collector_memory_mib * 0.75,
    )
    assert context.limit_mib <= max_allowed, (
        f"limit_mib={context.limit_mib} exceeds 75% "
        f"of container limit "
        f"({context.collector_memory_mib} MiB = "
        f"{max_allowed} MiB max)"
    )


# ----------------------------------------------------------------
# PK-RA-03: Volume UID alignment
# ----------------------------------------------------------------


@when("the UID_PROMETHEUS value is inspected")
def step_inspect_uid_prometheus(
    context: object,
) -> None:
    """Read UID_PROMETHEUS from the environment."""
    context.uid_prometheus = context.env_vars.get("UID_PROMETHEUS")


@then('UID_PROMETHEUS MUST be "{expected}"')
def step_check_uid_prometheus(
    context: object,
    expected: str,
) -> None:
    """Assert UID_PROMETHEUS matches the expected value."""
    assert context.uid_prometheus is not None, "UID_PROMETHEUS not found in .env"
    assert context.uid_prometheus == expected, (
        f"UID_PROMETHEUS={context.uid_prometheus}, " f"expected {expected}"
    )


@when("each UID_* variable is inspected")
def step_inspect_uid_vars(context: object) -> None:
    """Collect UID_* variables and their documentation."""
    context.uid_lines = []
    lines = context.env_text.splitlines()
    for i, line in enumerate(lines):
        stripped = line.split("#")[0].strip()
        if stripped.startswith("UID_") and "=" in stripped:
            has_comment = "#" in line
            if not has_comment and i > 0:
                prev = lines[i - 1].strip()
                has_comment = prev.startswith("#")
            context.uid_lines.append(
                (stripped.split("=")[0], has_comment),
            )


@then(
    "every UID_* variable MUST have a comment" " documenting the source",
)
def step_check_uid_comments(context: object) -> None:
    """Assert every UID_* variable is documented."""
    undocumented = [name for name, has_comment in context.uid_lines if not has_comment]
    assert not undocumented, (
        f"UID variables without documentation: " f"{', '.join(undocumented)}"
    )


# ----------------------------------------------------------------
# PK-RA-04: Deterministic OTel service identity
# ----------------------------------------------------------------


@when(
    "the service.telemetry.resource block is inspected",
)
def step_inspect_otel_resource(context: object) -> None:
    """Extract the OTel service resource block."""
    resource = (
        context.otel_config.get("service", {}).get("telemetry", {}).get("resource", {})
    )
    context.otel_resource = resource


@then("service.instance.id MUST be present")
def step_check_instance_id_present(
    context: object,
) -> None:
    """Assert service.instance.id exists in resource."""
    assert "service.instance.id" in context.otel_resource, (
        "service.instance.id not found in " "service.telemetry.resource"
    )


@then("service.instance.id MUST be a static value")
def step_check_instance_id_static(
    context: object,
) -> None:
    """Assert service.instance.id is not a dynamic UUID."""
    value = context.otel_resource.get(
        "service.instance.id",
        "",
    )
    uuid_pattern = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-" r"[0-9a-f]{4}-[0-9a-f]{12}$",
        re.IGNORECASE,
    )
    assert not uuid_pattern.match(str(value)), (
        f"service.instance.id appears to be a " f"dynamic UUID: {value}"
    )
    assert value, "service.instance.id is empty"
