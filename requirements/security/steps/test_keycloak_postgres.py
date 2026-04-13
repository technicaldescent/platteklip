# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

"""Step implementations for Keycloak PostgreSQL hardening.

Parses a raw ``postgresql.conf`` file into a key-value
dict, then asserts individual settings against CIS
PostgreSQL v1.0.0 Benchmark and OWASP Database Security
requirements.
"""

import os
from pathlib import Path

from behave import given, then  # type: ignore[import-untyped]

_DEFAULT_CONF_PATH = "services/keycloak-postgres/postgresql.conf"


def _parse_postgresql_conf(
    path: Path,
) -> dict[str, str]:
    """Parse postgresql.conf into a key-value dict.

    Strips comments (both full-line and inline),
    splits on the first ``=`` sign, and removes
    surrounding single quotes from values.
    Whitespace around keys and values is removed.

    Parameters
    ----------
    path
        Path to the postgresql.conf file.

    Returns
    -------
    dict[str, str]
        Configuration keys mapped to their values.
    """
    config: dict[str, str] = {}
    for raw_line in path.read_text(
        encoding="utf-8",
    ).splitlines():
        line = raw_line.split(
            "#",
            maxsplit=1,
        )[0].strip()
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        val = val.strip()
        if len(val) >= 2 and val.startswith("'") and val.endswith("'"):
            val = val[1:-1]
        config[key.strip()] = val
    return config


@given("the PostgreSQL configuration is loaded")
def step_read_config(context):  # noqa: ANN001
    """Load and parse the PostgreSQL configuration."""
    conf_path = Path(
        os.getenv(
            "POSTGRES_CONF_PATH",
            _DEFAULT_CONF_PATH,
        ),
    )
    assert conf_path.exists(), f"PostgreSQL configuration not found:" f" {conf_path}"
    context.pg_config = _parse_postgresql_conf(
        conf_path,
    )


@then('{key} must be "{expected}"')
def step_key_must_be(
    context,  # noqa: ANN001
    key: str,
    expected: str,
) -> None:
    """Assert that a configuration key equals the value."""
    actual = context.pg_config.get(key)
    assert actual is not None, f"{key} is not set in postgresql.conf"
    assert actual == expected, f"{key} is '{actual}'," f" expected '{expected}'"


@then('{key} must not be "{forbidden}"')
def step_key_must_not_be(
    context,  # noqa: ANN001
    key: str,
    forbidden: str,
) -> None:
    """Assert that a configuration key is not the value."""
    actual = context.pg_config.get(key)
    assert actual != forbidden, f"{key} is '{actual}'," f" which is forbidden"
