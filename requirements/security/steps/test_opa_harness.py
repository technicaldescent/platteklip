# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

"""OPA evaluation step harness and config inspection.

Implements the step definitions for pre-existing
features that evaluate OPA policies programmatically:

Pattern A — Loki OPA evaluation:
    identity/loki_mtls_validation.feature
    use_control/loki_retention_limits.feature
    data_flow/loki_topology_enforcement.feature

Pattern B — Compose and service config inspection:
    identity/mtls_enforcement.feature

Pattern C — Loki security posture (OPA variant):
    use_control/loki_security_posture.feature
"""

import contextlib
import datetime
import json
import re
import subprocess
import tempfile
from pathlib import Path

import yaml
from behave import given, then, when

# ----------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------


class _YAMLEncoder(json.JSONEncoder):
    """Handle types YAML produces that JSON cannot."""

    def default(self, o: object) -> str:
        """Serialise date and datetime to ISO 8601."""
        if isinstance(
            o,
            (datetime.date, datetime.datetime),
        ):
            return o.isoformat()
        return super().default(o)


def _read_loki_baseline() -> dict:
    """Load the Loki service config as a dict."""
    path = Path("services/loki/config.yaml")
    assert path.is_file(), f"{path} not found"
    with path.open() as f:
        return yaml.safe_load(f)


def _set_nested(
    obj: dict,
    dotpath: str,
    value: object,
) -> None:
    """Set a value at a dotted path, creating dicts."""
    parts = dotpath.split(".")
    for part in parts[:-1]:
        obj = obj.setdefault(part, {})
    if isinstance(value, str):
        if value.lower() == "true":
            value = True
        elif value.lower() == "false":
            value = False
        elif value.lower() == "null":
            value = None
        else:
            with contextlib.suppress(ValueError):
                value = int(value)
    obj[parts[-1]] = value


def _get_nested(
    obj: dict,
    dotpath: str,
) -> object:
    """Get a value at a dotted path."""
    parts = dotpath.split(".")
    for part in parts:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(part)
    return obj


def _resolve_policy_path(
    feature_path: str,
) -> str:
    """Resolve a policy path from feature reference.

    Features reference paths like
    ``services/loki/policy.rego`` which after the
    reorganisation are at
    ``requirements/security/use_control/policy/loki.rego``.
    """
    mapping = {
        "services/loki/policy.rego": (
            "requirements/security/use_control" "/policy/loki.rego"
        ),
        "policy/compose.rego": (
            "requirements/security/container_runtime" "/policy/compose.rego"
        ),
    }
    resolved = mapping.get(feature_path, feature_path)
    assert Path(resolved).is_file(), (
        f"Policy not found: {resolved} " f"(original: {feature_path})"
    )
    return resolved


def _opa_eval_violations(
    cmd: list[str],
) -> list[str]:
    """Execute an OPA command and extract violations.

    Separated from ``_run_opa_eval`` so the subprocess
    call and JSON parsing are outside the try/finally
    cleanup block.
    """
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=30,
    )

    if result.returncode != 0:
        msg = (
            f"opa eval failed (rc={result.returncode}):"
            f"\nstderr: {result.stderr}"
            f"\nstdout: {result.stdout}"
        )
        raise RuntimeError(msg)

    output = json.loads(result.stdout)
    violations: list[str] = []

    for r in output.get("result", []):
        for expr in r.get("expressions", []):
            val = expr.get("value", [])
            if isinstance(val, (list, set)):
                violations.extend(str(v) for v in val)

    return violations


def _run_opa_eval(
    policy_path: str,
    input_data: dict,
    runtime_env: str = "development",
    query: str = "data.services.loki.deny",
) -> list[str]:
    """Run opa eval and return the violation strings."""
    import shutil

    tmpdir = tempfile.mkdtemp(prefix="opa_eval_")

    try:
        input_path = f"{tmpdir}/input.json"
        with open(input_path, "w") as inp:
            json.dump(
                input_data,
                inp,
                cls=_YAMLEncoder,
            )

        data_dir = f"{tmpdir}/data"
        runtime_dir = f"{data_dir}/runtime"
        Path(runtime_dir).mkdir(parents=True)
        runtime_path = f"{runtime_dir}/runtime.json"
        with open(runtime_path, "w") as rt:
            json.dump(
                {"environment": runtime_env},
                rt,
            )

        cmd = [
            "opa",
            "eval",
            "--data",
            policy_path,
            "--data",
            data_dir,
            "--input",
            input_path,
            query,
            "--format",
            "json",
        ]

        return _opa_eval_violations(cmd)

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ================================================================
# Pattern A: Loki OPA Evaluation
# ================================================================


@given("a baseline valid Loki JSON configuration")
def step_baseline_loki(context: object) -> None:
    """Load and store the baseline Loki config."""
    context.loki_config = _read_loki_baseline()
    context.runtime_env = "development"
    context.policy_path = None


@given("a baseline Loki configuration parsed as JSON")
def step_baseline_loki_json(
    context: object,
) -> None:
    """Load and store the baseline Loki config."""
    context.loki_config = _read_loki_baseline()
    context.runtime_env = "development"
    context.policy_path = None


@given(
    'the OPA policy engine is loaded with "{path}"',
)
def step_read_opa_policy(
    context: object,
    path: str,
) -> None:
    """Resolve and store the policy file path."""
    context.policy_path = _resolve_policy_path(path)


@given('the runtime environment is "{env}"')
def step_set_runtime_env(
    context: object,
    env: str,
) -> None:
    """Set the runtime environment for OPA evaluation."""
    context.runtime_env = env


@given(
    'the configuration property "{path}" is set to' ' "{value}"',
)
def step_set_config_property(
    context: object,
    path: str,
    value: str,
) -> None:
    """Set a nested configuration property."""
    _set_nested(context.loki_config, path, value)


@given(
    'the configuration sets "{path}" to "{value}"',
)
def step_set_config_property_alt(
    context: object,
    path: str,
    value: str,
) -> None:
    """Set a nested configuration property (alt)."""
    _set_nested(context.loki_config, path, value)


@when(
    "the policy is evaluated against the configuration",
)
def step_eval_opa_policy(context: object) -> None:
    """Evaluate the OPA policy against the config."""
    assert context.policy_path, (
        "No OPA policy loaded — use " "'Given the OPA policy engine is loaded'"
    )
    context.opa_violations = _run_opa_eval(
        policy_path=context.policy_path,
        input_data=context.loki_config,
        runtime_env=context.runtime_env,
    )


@when("the OPA policy is evaluated")
def step_eval_opa_policy_alt(
    context: object,
) -> None:
    """Evaluate the OPA policy, defaulting to Loki."""
    if not context.policy_path:
        context.policy_path = _resolve_policy_path(
            "services/loki/policy.rego",
        )
    context.opa_violations = _run_opa_eval(
        policy_path=context.policy_path,
        input_data=context.loki_config,
        runtime_env=context.runtime_env,
    )


@then('the evaluation result should be "{expected}"')
def step_check_eval_result(
    context: object,
    expected: str,
) -> None:
    """Assert the evaluation result is deny or pass."""
    if expected == "deny":
        assert context.opa_violations, "Expected deny violations but got none"
    elif expected == "pass":
        assert not context.opa_violations, (
            "Expected pass but got violations: " f"{context.opa_violations}"
        )


@then("the policy should pass with zero violations")
def step_check_zero_violations(
    context: object,
) -> None:
    """Assert no OPA violations were produced."""
    assert not context.opa_violations, (
        "Expected zero violations but got: " f"{context.opa_violations}"
    )


@then("the policy should deny the configuration")
def step_check_deny(context: object) -> None:
    """Assert at least one violation was produced."""
    assert context.opa_violations, "Expected deny violations but got none"


@then(
    "the policy violation message should contain" ' "{text}"',
)
def step_check_violation_contains(
    context: object,
    text: str,
) -> None:
    """Assert a violation message contains text."""
    text = text.replace('\\"', '"')
    joined = " | ".join(context.opa_violations)
    assert text in joined, (
        f"Expected violation containing '{text}' " f"but got: {context.opa_violations}"
    )


@then(
    'the violation message should contain "{text}"',
)
def step_check_violation_contains_alt(
    context: object,
    text: str,
) -> None:
    """Assert a violation message contains text (alt)."""
    text = text.replace('\\"', '"')
    joined = " | ".join(context.opa_violations)
    assert text in joined, (
        f"Expected violation containing '{text}' " f"but got: {context.opa_violations}"
    )


# ================================================================
# Pattern B: Compose and Service Config Inspection
# ================================================================


@given("a baseline valid compose.yaml configuration")
def step_baseline_compose(context: object) -> None:
    """Load and store the baseline compose config."""
    path = Path("compose.yaml")
    assert path.is_file(), "compose.yaml not found"
    with path.open() as f:
        context.compose = yaml.safe_load(f)


@given("a compose file with services defined")
def step_compose_services(context: object) -> None:
    """Assert services exist and store them."""
    assert "services" in context.compose, "compose.yaml has no services"
    context.services = dict(
        context.compose["services"],
    )


@given('"{name}" is exempt as {reason}')
def step_exempt_service(
    context: object,
    name: str,
    reason: str,
) -> None:
    """Remove a service from the inspection set."""
    context.services.pop(name, None)


@given(
    '"{first}" and "{second}" are exempt' " as {reason}",
)
def step_exempt_services(
    context: object,
    first: str,
    second: str,
    reason: str,
) -> None:
    """Remove multiple services from the inspection set."""
    context.services.pop(first, None)
    context.services.pop(second, None)


@given("the nginx default.conf configuration")
def step_read_nginx_default(context: object) -> None:
    """Load the nginx default.conf as text."""
    path = Path("services/nginx/conf.d/default.conf")
    assert path.is_file(), f"{path} not found"
    context.nginx_default_conf = path.read_text()


@given("the mosquitto.conf configuration")
def step_read_mosquitto_conf(
    context: object,
) -> None:
    """Load and parse mosquitto.conf directives."""
    path = Path(
        "services/mosquitto/config/mosquitto.conf",
    )
    assert path.is_file(), f"{path} not found"
    context.mosquitto_text = path.read_text()
    context.mosquitto_directives = {}
    for line in context.mosquitto_text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            parts = stripped.split(None, 1)
            if len(parts) == 2:
                context.mosquitto_directives[parts[0]] = parts[1]


@when("each service's secrets are inspected")
def step_inspect_secrets(context: object) -> None:
    """Collect secret names for each service."""
    context.service_secrets = {}
    for name, svc in context.services.items():
        secrets = svc.get("secrets", [])
        secret_names = []
        for s in secrets:
            if isinstance(s, str):
                secret_names.append(s)
            elif isinstance(s, dict):
                secret_names.append(
                    s.get(
                        "target",
                        s.get("source", ""),
                    ),
                )
        context.service_secrets[name] = secret_names


@then(
    'every service MUST have a "{secret}" secret',
)
def step_check_secret(
    context: object,
    secret: str,
) -> None:
    """Assert every inspected service has the secret."""
    missing = [
        name
        for name, secrets in context.service_secrets.items()
        if secret not in secrets
    ]
    assert not missing, f"Services missing '{secret}' secret: " f"{', '.join(missing)}"


@when("the proxy_ssl directives are inspected")
def step_inspect_proxy_ssl(context: object) -> None:
    """Extract proxy_ssl directives from nginx config."""
    context.proxy_ssl = {}
    for directive in [
        "proxy_ssl_verify",
        "proxy_ssl_trusted_certificate",
    ]:
        pattern = re.compile(
            rf"{directive}\s+([^;]+);",
        )
        match = pattern.search(
            context.nginx_default_conf,
        )
        if match:
            context.proxy_ssl[directive] = match.group(1).strip()


@then(
    'proxy_ssl_verify MUST be set to "{expected}"',
)
def step_check_proxy_ssl_verify(
    context: object,
    expected: str,
) -> None:
    """Assert proxy_ssl_verify matches expected value."""
    actual = context.proxy_ssl.get(
        "proxy_ssl_verify",
    )
    assert actual is not None, "proxy_ssl_verify not found in default.conf"
    assert actual == expected, (
        f"proxy_ssl_verify is '{actual}', " f"expected '{expected}'"
    )


@then(
    "proxy_ssl_trusted_certificate MUST reference" " the platform CA",
)
def step_check_proxy_ssl_ca(context: object) -> None:
    """Assert proxy_ssl_trusted_certificate refs CA."""
    actual = context.proxy_ssl.get(
        "proxy_ssl_trusted_certificate",
    )
    assert actual is not None, "proxy_ssl_trusted_certificate not found"
    assert "ca" in actual.lower(), (
        "proxy_ssl_trusted_certificate is" f" '{actual}', expected a CA reference"
    )


@when("the TLS directives are inspected")
def step_inspect_tls_directives(
    context: object,
) -> None:
    """Extract TLS-related mosquitto directives."""
    context.tls_directives = {
        k: v
        for k, v in context.mosquitto_directives.items()
        if k
        in {
            "require_certificate",
            "use_identity_as_username",
            "tls_version",
            "cafile",
            "certfile",
            "keyfile",
        }
    }


@then(
    'require_certificate MUST be set to "{expected}"',
)
def step_check_require_cert(
    context: object,
    expected: str,
) -> None:
    """Assert require_certificate matches expected."""
    actual = context.tls_directives.get(
        "require_certificate",
    )
    assert actual is not None, "require_certificate not found in" " mosquitto.conf"
    assert actual == expected, (
        f"require_certificate is '{actual}', " f"expected '{expected}'"
    )


@then(
    "use_identity_as_username MUST be set to" ' "{expected}"',
)
def step_check_use_identity(
    context: object,
    expected: str,
) -> None:
    """Assert use_identity_as_username matches."""
    actual = context.tls_directives.get(
        "use_identity_as_username",
    )
    assert actual is not None, "use_identity_as_username not found in" " mosquitto.conf"
    assert actual == expected, (
        f"use_identity_as_username is '{actual}', " f"expected '{expected}'"
    )


# ================================================================
# Pattern C: Loki Security Posture
# ================================================================


@given("a proposed Loki deployment configuration")
def step_proposed_loki_config(
    context: object,
) -> None:
    """Load baseline Loki config for posture testing."""
    context.loki_config = _read_loki_baseline()
    context.runtime_env = "development"
    context.policy_path = _resolve_policy_path(
        "services/loki/policy.rego",
    )


@given(
    "the configuration lacks mutual TLS client" " verification",
)
def step_remove_mtls(context: object) -> None:
    """Disable mTLS client verification in config."""
    _set_nested(
        context.loki_config,
        "server.http_tls_config.client_auth_type",
        "NoClientCert",
    )


@given(
    "the configuration mounts certificates from a" " secure memory partition",
)
def step_ensure_secure_mounts(
    context: object,
) -> None:
    """Set certificate paths to tmpfs-backed secrets."""
    tls = context.loki_config.setdefault(
        "server",
        {},
    ).setdefault("http_tls_config", {})
    tls["cert_file"] = "/run/secrets/loki/tls_certificate.crt"
    tls["key_file"] = "/run/secrets/loki/tls_private_key.key"
    tls["client_ca_file"] = "/run/secrets/loki/ca.crt"
    tls["client_auth_type"] = "RequireAndVerifyClientCert"


@when("the system compliance check is executed")
def step_run_compliance_check(
    context: object,
) -> None:
    """Run the OPA compliance check against config."""
    context.opa_violations = _run_opa_eval(
        policy_path=context.policy_path,
        input_data=context.loki_config,
        runtime_env=context.runtime_env,
    )


@then("the deployment configuration is rejected")
def step_config_rejected(context: object) -> None:
    """Assert the deployment config was rejected."""
    assert context.opa_violations, (
        "Expected configuration to be rejected " "but no violations were found"
    )


@then("the deployment configuration is accepted")
def step_config_accepted(context: object) -> None:
    """Assert the deployment config was accepted."""
    assert not context.opa_violations, (
        "Expected configuration to be accepted "
        f"but got violations: "
        f"{context.opa_violations}"
    )
