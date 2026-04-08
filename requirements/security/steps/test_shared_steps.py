# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

"""Shared step implementations for security features.

Background steps that are used across multiple control
families (compose.yaml loading, OTel Collector config
loading, .env loading, pipeline inspection) live here
to avoid duplicate definitions in behave's flat step
namespace.
"""

from pathlib import Path

import yaml
from behave import given, when

# ----------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------


def _parse_memory(value: str) -> int:
    """Parse a Docker memory string to MiB."""
    value = value.strip().lower()
    if value.endswith("g"):
        return int(float(value[:-1]) * 1024)
    if value.endswith("m"):
        return int(float(value[:-1]))
    return int(value)


# ----------------------------------------------------------------
# Configuration loaders (Background steps)
# ----------------------------------------------------------------


@given("the compose.yaml configuration is loaded")
def step_read_compose(context: object) -> None:
    """Load compose.yaml as text and parsed YAML."""
    path = Path("compose.yaml")
    assert path.is_file(), "compose.yaml not found"
    context.compose_path = path
    context.compose_text = path.read_text()
    with path.open() as f:
        context.compose = yaml.safe_load(f)


@given("the OTel Collector config.yaml is loaded")
def step_read_otel_config(context: object) -> None:
    """Load the OTel Collector config as parsed YAML."""
    path = Path("services/otel-collector/config.yaml")
    assert path.is_file(), f"{path} not found"
    with path.open() as f:
        context.otel_config = yaml.safe_load(f)


@given("the .env configuration is loaded")
def step_read_env(context: object) -> None:
    """Load .env as text and a key-value dict."""
    path = Path(".env")
    assert path.is_file(), ".env not found"
    context.env_text = path.read_text()
    context.env_vars = {}
    for line in context.env_text.splitlines():
        stripped = line.split("#")[0].strip()
        if "=" in stripped:
            key, _, val = stripped.partition("=")
            context.env_vars[key.strip()] = val.strip()


@given("the nginx configuration is loaded")
def step_read_nginx_config(context: object) -> None:
    """Load nginx.conf and default.conf as text."""
    path = Path("services/nginx/nginx.conf")
    assert path.is_file(), f"{path} not found"
    context.nginx_conf = path.read_text()
    default = Path("services/nginx/conf.d/default.conf")
    if default.is_file():
        context.nginx_conf += "\n" + default.read_text()


@given("the mosquitto.conf configuration is loaded")
def step_read_mosquitto_config(context: object) -> None:
    """Load and parse mosquitto.conf directives."""
    path = Path(
        "services/mosquitto/config/mosquitto.conf",
    )
    assert path.is_file(), f"{path} not found"
    context.mosquitto_conf = path.read_text()
    context.mosquitto_directives = {}
    for line in context.mosquitto_conf.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            parts = stripped.split(None, 1)
            if len(parts) == 2:
                context.mosquitto_directives[parts[0]] = parts[1]


@given("the deploy.sh script is loaded")
def step_read_deploy_script(context: object) -> None:
    """Load the certificate generation script."""
    path = Path("scripts/generate-certificates.sh")
    assert path.is_file(), f"{path} not found"
    context.deploy_script = path.read_text()


@given(
    "the Collector container memory limit from" " compose.yaml",
)
def step_read_collector_memory(context: object) -> None:
    """Read the OTel Collector memory limit in MiB."""
    if not hasattr(context, "compose"):
        step_read_compose(context)
    svc = context.compose["services"]["otel-collector"]
    mem_str = svc["deploy"]["resources"]["limits"]["memory"]
    context.collector_memory_mib = _parse_memory(
        mem_str,
    )


@given("the Weaver generated output directory")
def step_read_weaver_paths(context: object) -> None:
    """Set paths to Weaver-generated artefacts."""
    context.python_gen = Path(
        "src/platteklip/instrumentation/edge_semconv.py",
    )
    context.collector_gen = Path(
        "services/weaver/generated/collector/" "transform_processor.yaml",
    )


@given("the MQTTConnectionConfig defaults")
def step_read_mqtt_config(context: object) -> None:
    """Instantiate default MQTTConnectionConfig."""
    from platteklip.mqtt_producer import (
        MQTTConnectionConfig,
    )

    context.mqtt_config = MQTTConnectionConfig()


# ----------------------------------------------------------------
# Shared inspection steps
# ----------------------------------------------------------------


@when("each pipeline's processors list is inspected")
def step_inspect_pipeline_processors(
    context: object,
) -> None:
    """Collect processor lists per OTel pipeline."""
    pipelines = context.otel_config.get("service", {}).get("pipelines", {})
    context.pipeline_processors = {
        name: pipe.get("processors", []) for name, pipe in pipelines.items()
    }
