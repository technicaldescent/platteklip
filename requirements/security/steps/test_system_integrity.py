# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

"""Step implementations for PK.SI features.

Background steps and shared inspection steps are in
requirements/security/steps/test_shared_steps.py.
"""

from behave import then, when

# ----------------------------------------------------------------
# PK-SI-01: Image digest pinning
# ----------------------------------------------------------------


@when("each service's image reference is inspected")
def step_inspect_images(context: object) -> None:
    """Collect image references and pull policies."""
    context.image_results = {}
    for name, svc in context.compose["services"].items():
        pull_policy = svc.get("pull_policy", "")
        image = svc.get("image", "")
        context.image_results[name] = {
            "image": image,
            "pull_policy": pull_policy,
        }


@then('every image MUST contain "@sha256:"')
def step_check_digest(context: object) -> None:
    """Assert every image uses a digest pin."""
    missing = [
        f"{name} ({info['image']})"
        for name, info in context.image_results.items()
        if "@sha256:" not in info["image"] and info["pull_policy"] != "build"
    ]
    assert not missing, f"Images without @sha256: digest: " f"{', '.join(missing)}"


@then('services with pull_policy "build" are exempt')
def step_build_exempt(context: object) -> None:
    """Acknowledge build-policy services are exempt."""


@when(
    "each service's image reference and surrounding" " lines are inspected",
)
def step_inspect_image_comments(
    context: object,
) -> None:
    """Check for tag comments near digest-pinned images."""
    lines = context.compose_text.splitlines()
    context.digest_comment_results = {}
    for i, line in enumerate(lines):
        if "@sha256:" in line:
            has_tag = "#" in line
            if not has_tag and i > 0:
                prev = lines[i - 1].strip()
                has_tag = prev.startswith("#")
            context.digest_comment_results[i] = {
                "line": line.strip(),
                "has_tag_comment": has_tag,
            }


@then(
    "every digest-pinned image MUST have a tag comment",
)
def step_check_tag_comments(context: object) -> None:
    """Assert every digest pin has a tag comment."""
    missing = [
        info["line"]
        for info in context.digest_comment_results.values()
        if not info["has_tag_comment"]
    ]
    assert not missing, f"Digest-pinned images without tag comments: " f"{missing}"


# ----------------------------------------------------------------
# PK-SI-02: Weaver code generation verification
# ----------------------------------------------------------------


@when("edge_semconv.py is inspected")
def step_inspect_edge_semconv(context: object) -> None:
    """Set the edge_semconv.py path for inspection."""
    context.edge_semconv_path = context.python_gen


@then("edge_semconv.py MUST exist")
def step_check_edge_semconv_exists(
    context: object,
) -> None:
    """Assert edge_semconv.py exists on disc."""
    assert (
        context.edge_semconv_path.is_file()
    ), f"{context.edge_semconv_path} does not exist"


@then(
    "edge_semconv.py MUST be larger than 0 bytes",
)
def step_check_edge_semconv_size(
    context: object,
) -> None:
    """Assert edge_semconv.py is non-empty."""
    size = context.edge_semconv_path.stat().st_size
    assert size > 0, f"{context.edge_semconv_path} is empty (0 bytes)"


@when("transform_processor.yaml is inspected")
def step_inspect_transform_processor(
    context: object,
) -> None:
    """Set the transform_processor.yaml path."""
    context.transform_path = context.collector_gen


@then("transform_processor.yaml MUST exist")
def step_check_transform_exists(
    context: object,
) -> None:
    """Assert transform_processor.yaml exists."""
    assert context.transform_path.is_file(), f"{context.transform_path} does not exist"


@then(
    "transform_processor.yaml MUST be larger than" " 0 bytes",
)
def step_check_transform_size(
    context: object,
) -> None:
    """Assert transform_processor.yaml is non-empty."""
    size = context.transform_path.stat().st_size
    assert size > 0, f"{context.transform_path} is empty (0 bytes)"


# ----------------------------------------------------------------
# PK-SI-03: OTel attribute sanitisation
# ----------------------------------------------------------------


@then(
    "the {signal} pipeline MUST include" ' "{processor}"',
)
def step_check_pipeline_has_processor(
    context: object,
    signal: str,
    processor: str,
) -> None:
    """Assert the named processor is in the pipeline."""
    procs = context.pipeline_processors.get(signal, [])
    assert processor in procs, (
        f"Pipeline '{signal}' does not include " f"'{processor}'. Processors: {procs}"
    )
