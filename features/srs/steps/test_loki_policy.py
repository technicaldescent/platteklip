# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

"""Loki configuration policy testing using OPA and Behave."""

import copy
import json
import subprocess
from typing import Any, Final

from behave import given, then, when

# --- BASELINE GOLDEN CONFIGURATION ---
GOLDEN_CONFIG: Final[dict[str, Any]] = {
    "server": {
        "http_listen_port": 3100,
        "http_listen_address": "::",
        "grpc_listen_port": 9095,
        "grpc_listen_address": "::",
        "http_tls_config": {
            "client_auth_type": "RequireAndVerifyClientCert",
            "cert_file": "/run/secrets/loki.crt",
            "key_file": "/run/secrets/loki.key",
            "client_ca_file": "/run/secrets/ca.crt",
        },
    },
    "common": {
        "path_prefix": "/loki",
        "instance_addr": "::1",
        "storage": {
            "filesystem": {
                "chunks_directory": "/loki/chunks",
                "rules_directory": "/loki/rules",
            }
        },
        "ring": {"kvstore": {"store": "inmemory"}},
    },
    "schema_config": {
        "configs": [
            {
                "store": "tsdb",
                "object_store": "filesystem",
                "schema": "v13",
                "index": {"period": "24h"},
            }
        ]
    },
    "analytics": {"reporting_enabled": False},
    "tracing": {"enabled": True},
    "auth_enabled": False,
    "compactor": {
        "retention_enabled": True,
        "delete_request_store": "filesystem",
    },
    "limits_config": {
        "reject_old_samples": True,
        "unordered_writes": True,
        "allow_structured_metadata": True,
        "retention_period": "2h",
        "reject_old_samples_max_age": "24h",
    },
    "ingester": {"lifecycler": {"ring": {"kvstore": {"store": "inmemory"}}}},
    "distributor": {"ring": {"kvstore": {"store": "inmemory"}}},
    "ruler": {"ring": {"kvstore": {"store": "inmemory"}}},
    "memberlist": {"bind_addr": ["::"]},
}

# --- UTILITIES ---


def parse_value(val_str: str) -> bool | int | str:
    """Cast Gherkin strings to proper Python types.

    Args:
        val_str: The raw string value from the Gherkin feature file.

    Returns:
        The value converted to a boolean, integer, or kept as a string.
    """
    normalized = val_str.lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    if val_str.isdigit():
        return int(val_str)
    return val_str


def set_nested_value(d: dict[str, Any], path: str, value: str) -> None:
    """Set a value deep inside a nested dictionary using dot notation.

    Args:
        d: The dictionary to mutate.
        path: A dot-separated string representing the nested keys.
        value: The string value to parse and set.
    """
    keys = path.split(".")
    current = d
    for key in keys[:-1]:
        current = current.setdefault(key, {})
    current[keys[-1]] = parse_value(value)


# --- BASELINE SETUP STEPS ---


@given("a baseline valid Loki JSON configuration")
@given("a baseline Loki configuration parsed as JSON")
def step_baseline_config(context: Any) -> None:
    """Initialize the context with a deep copy of the golden configuration."""
    context.loki_config = copy.deepcopy(GOLDEN_CONFIG)
    if not hasattr(context, "runtime_env"):
        context.runtime_env = "development"
    context.opa_results = []


@given('the OPA policy engine is loaded from "{path}"')
def step_load_opa_from(context: Any, path: str) -> None:
    """Provide a placeholder for OPA loading logic."""


@given('the runtime environment is "{env_name}"')
def step_set_env(context: Any, env_name: str) -> None:
    """Set the environment context for OPA evaluation."""
    context.runtime_env = env_name


# --- MUTATION STEPS ---


@given('the configuration property "{path}" is set to "{value}"')
@given('the configuration sets "{path}" to "{value}"')
def step_set_property(context: Any, path: str, value: str) -> None:
    """Mutate the baseline configuration with a specific value."""
    set_nested_value(context.loki_config, path, value)


# --- EXECUTION STEPS ---


@when("the policy is evaluated against the configuration")
@when("the OPA policy is evaluated")
def step_evaluate_opa(context: Any) -> None:
    """Execute the OPA CLI to evaluate the policy.

    Raises:
        RuntimeError: If OPA execution fails.
    """
    payload = json.dumps(context.loki_config)
    env = context.runtime_env
    query = f'data.services.loki.deny with data.runtime.environment as "{env}"'

    cmd = [
        "opa",
        "eval",
        "--data",
        "policy/services/loki/policy.rego",
        "--stdin-input",
        "-f",
        "json",
        query,
    ]

    try:
        res = subprocess.run(
            cmd, input=payload, capture_output=True, text=True, check=True
        )
        data = json.loads(res.stdout)
        if "result" in data and data["result"]:
            exprs = data["result"][0].get("expressions", [{}])
            context.opa_results = exprs[0].get("value", [])
        else:
            context.opa_results = []
    except (subprocess.CalledProcessError, FileNotFoundError, KeyError) as e:
        raise RuntimeError from e
    except json.JSONDecodeError as e:
        raise RuntimeError from e


# --- ASSERTION STEPS ---


@then('the evaluation result should be "deny"')
@then("the policy should deny the configuration")
def step_check_deny(context: Any) -> None:
    """Verify that the policy generated violations."""
    if len(context.opa_results) == 0:
        raise AssertionError("Policy expected to deny")


@then("the policy should pass with zero violations")
def step_check_pass(context: Any) -> None:
    """Verify that the policy generated no violations."""
    if len(context.opa_results) != 0:
        msg = f"Unexpected: {context.opa_results}"
        raise AssertionError(msg)


@then('the policy violation message should contain "{expected_message}"')
@then('the violation message should contain "{expected_message}"')
def step_check_message(context: Any, expected_message: str) -> None:
    """Check if a specific message exists in the denial list."""
    clean_message = expected_message.replace('\\"', '"')
    found = any(clean_message in msg for msg in context.opa_results)
    if not found:
        msg = f"Missing: {clean_message}"
        raise AssertionError(msg)
