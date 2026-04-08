# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

"""Step implementations for PK.DC features.

Background steps and shared inspection steps are in
requirements/security/steps/test_shared_steps.py.
"""

import re
import ssl

from behave import then, when

# ----------------------------------------------------------------
# PK-DC-01: TLS 1.3
# ----------------------------------------------------------------


@when("the ssl_protocols directive is inspected")
def step_inspect_ssl_protocols(context: object) -> None:
    """Extract the ssl_protocols value from nginx."""
    pattern = re.compile(
        r"ssl_protocols\s+([^;]+);",
    )
    match = pattern.search(context.nginx_conf)
    assert match, "ssl_protocols directive not found in " "nginx config"
    context.ssl_protocols = match.group(1).strip()


@then('ssl_protocols MUST specify "{expected}" only')
def step_check_ssl_protocols(
    context: object,
    expected: str,
) -> None:
    """Assert only the expected protocol is listed."""
    protocols = context.ssl_protocols.split()
    assert protocols == [expected], (
        f"ssl_protocols is '{context.ssl_protocols}', " f"expected '{expected}' only"
    )


@when("the TLS version constraints are inspected")
def step_inspect_tls_version(context: object) -> None:
    """Read TLS min/max versions from MQTT config."""
    context.tls_min = context.mqtt_config.tls_min_version
    context.tls_max = context.mqtt_config.tls_max_version


@then("tls_min_version MUST be TLSv1.3")
def step_check_tls_min(context: object) -> None:
    """Assert TLS minimum version is 1.3."""
    assert context.tls_min == ssl.TLSVersion.TLSv1_3, (
        f"tls_min_version is {context.tls_min}, " f"expected TLSv1.3"
    )


@then("tls_max_version MUST be TLSv1.3")
def step_check_tls_max(context: object) -> None:
    """Assert TLS maximum version is 1.3."""
    assert context.tls_max == ssl.TLSVersion.TLSv1_3, (
        f"tls_max_version is {context.tls_max}, " f"expected TLSv1.3"
    )


@when("the tls_version directive is inspected")
def step_inspect_mosquitto_tls(context: object) -> None:
    """Extract tls_version from mosquitto directives."""
    context.mosquitto_tls_version = context.mosquitto_directives.get("tls_version")


@then('tls_version MUST be "{expected}"')
def step_check_mosquitto_tls(
    context: object,
    expected: str,
) -> None:
    """Assert mosquitto tls_version matches expected."""
    assert context.mosquitto_tls_version is not None, (
        "tls_version directive not found in " "mosquitto.conf"
    )
    assert context.mosquitto_tls_version == expected, (
        f"tls_version is "
        f"'{context.mosquitto_tls_version}', "
        f"expected '{expected}'"
    )


# ----------------------------------------------------------------
# PK-DC-02: ECDSA P-384
# ----------------------------------------------------------------


@when(
    "the certificate generation commands are inspected",
)
def step_inspect_cert_commands(context: object) -> None:
    """Collect openssl commands from the deploy script."""
    context.cert_commands = [
        line.strip()
        for line in context.deploy_script.splitlines()
        if "openssl" in line.lower() and not line.strip().startswith("#")
    ]


@then(
    "every openssl ecparam or openssl genpkey command" " MUST specify secp384r1",
)
def step_check_ecdsa_curve(context: object) -> None:
    """Assert all key generation uses secp384r1."""
    keygen = [
        cmd for cmd in context.cert_commands if "ecparam" in cmd or "genpkey" in cmd
    ]
    assert keygen, "No openssl ecparam or genpkey commands found"
    missing = [cmd for cmd in keygen if "secp384r1" not in cmd]
    assert not missing, f"Commands not specifying secp384r1: {missing}"


@then("no RSA key generation commands MUST be present")
def step_check_no_rsa(context: object) -> None:
    """Assert no RSA key generation commands exist."""
    rsa_cmds = [
        cmd for cmd in context.cert_commands if "genrsa" in cmd or "rsa" in cmd.split()
    ]
    assert not rsa_cmds, f"RSA key generation found: {rsa_cmds}"
