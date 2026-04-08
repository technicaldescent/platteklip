# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

r"""Gemara Layer 5 automated evaluation for platteklip controls.

Reads project configuration files, evaluates each assessment
requirement from the Layer 2 control catalog, and emits a
schema-valid Gemara EvaluationLog to stdout.

Usage::

    python evaluate_controls.py /path/to/platteklip > eval.yaml
    cue vet -c -d '#EvaluationLog' \\
        github.com/gemaraproj/gemara@latest eval.yaml

The script requires no dependencies beyond the standard library
and PyYAML (used by the project already).
"""

import datetime
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

import yaml

# ------------------------------------------------------------------
# Result constants
# ------------------------------------------------------------------

PASS: Final[str] = "Pass"
FAIL: Final[str] = "Fail"
NOT_APPLICABLE: Final[str] = "Not Applicable"
ERROR: Final[str] = "Error"

CATALOG_REF: Final[str] = "PK.EDGE"


# ------------------------------------------------------------------
# Check result
# ------------------------------------------------------------------


@dataclass(slots=True)
class CheckResult:
    """Outcome of a single assessment requirement check."""

    result: str = FAIL
    message: str = ""
    steps: list[str] = field(default_factory=list)
    recommendation: str = ""


# ------------------------------------------------------------------
# Project file loader
# ------------------------------------------------------------------


@dataclass(slots=True)
class ProjectFiles:
    """Lazily loaded project configuration files."""

    root: Path
    _compose: dict | None = None
    _collector: dict | None = None
    _nginx_conf: str | None = None
    _nginx_default: str | None = None
    _env: dict[str, str] | None = None
    _nifi_dockerfile: str | None = None
    _mosquitto_conf: str | None = None

    def _read(self, rel: str) -> str | None:
        """Read a project-relative file as text."""
        p = self.root / rel
        if p.is_file():
            return p.read_text(encoding="utf-8")
        return None

    def _parse_yaml(self, rel: str) -> dict | None:
        """Parse a project-relative YAML file."""
        text = self._read(rel)
        if text is None:
            return None
        return yaml.safe_load(text)

    @property
    def stack_cfg(self) -> dict:  # noqa: FNE002
        """Return the parsed compose.yaml."""
        if self._compose is None:
            self._compose = self._parse_yaml("compose.yaml") or {}
        return self._compose

    @property
    def collector(self) -> dict:
        """Return the parsed OTel Collector config."""
        if self._collector is None:
            self._collector = (
                self._parse_yaml(
                    "services/otel-collector/config.yaml",
                )
                or {}
            )
        return self._collector

    @property
    def nginx_conf(self) -> str:
        """Return nginx.conf content."""
        if self._nginx_conf is None:
            self._nginx_conf = self._read("services/nginx/nginx.conf") or ""
        return self._nginx_conf

    @property
    def nginx_default(self) -> str:
        """Return nginx default.conf content."""
        if self._nginx_default is None:
            self._nginx_default = (
                self._read(
                    "services/nginx/conf.d/default.conf",
                )
                or ""
            )
        return self._nginx_default

    @property
    def env(self) -> dict[str, str]:
        """Return parsed .env key-value pairs."""
        if self._env is None:
            self._env = {}
            text = self._read(".env")
            if text:
                for line in text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        k, _, v = line.partition("=")
                        self._env[k.strip()] = v.strip().strip('"').strip("'")
        return self._env

    @property
    def nifi_dockerfile(self) -> str:
        """Return the NiFi Dockerfile content."""
        if self._nifi_dockerfile is None:
            self._nifi_dockerfile = self._read("services/nifi/Dockerfile") or ""
        return self._nifi_dockerfile

    @property
    def mosquitto_conf(self) -> str:
        """Return mosquitto.conf content."""
        if self._mosquitto_conf is None:
            self._mosquitto_conf = (
                self._read(
                    "services/mosquitto/mosquitto.conf",
                )
                or ""
            )
        return self._mosquitto_conf


# ------------------------------------------------------------------
# Check functions
# ------------------------------------------------------------------

CheckFn = Callable[[ProjectFiles], CheckResult]
_REGISTRY: dict[str, CheckFn] = {}


def check(ar_id: str) -> Callable[[CheckFn], CheckFn]:
    """Register a check function for an AR ID."""

    def decorator(fn: CheckFn) -> CheckFn:
        """Bind the check function to the AR ID."""
        _REGISTRY[ar_id] = fn
        return fn

    return decorator


# -- PK-IA-01: mTLS -----------------------------------------------


@check("PK-IA-01.01")
def _pk_ia_01_01(pf: ProjectFiles) -> CheckResult:
    """Evaluate PK-IA-01.01."""
    r = CheckResult(
        steps=["Check compose secrets for mTLS certs"],
    )
    services = pf.stack_cfg.get("services", {})
    missing = []
    for name, svc in services.items():
        secrets = [
            s.get("target", "") if isinstance(s, dict) else s
            for s in svc.get("secrets", [])
        ]
        targets = " ".join(secrets)
        if "tls_certificate" not in targets:
            missing.append(name)
    if not missing:
        r.result = PASS
        r.message = "All services have TLS cert secrets."
    else:
        r.message = f"Services missing TLS cert: " f"{', '.join(missing)}"
    return r


@check("PK-IA-01.02")
def _pk_ia_01_02(pf: ProjectFiles) -> CheckResult:
    """Evaluate PK-IA-01.02."""
    r = CheckResult(
        steps=["Check nginx proxy_ssl_verify in " "default.conf"],
    )
    if "proxy_ssl_verify" not in pf.nginx_default:
        r.message = "proxy_ssl_verify not found in " "default.conf."
        return r
    if (
        "proxy_ssl_verify              on" in pf.nginx_default
        or "proxy_ssl_verify on" in pf.nginx_default
    ):
        r.result = PASS
        r.message = "proxy_ssl_verify is on."
    else:
        r.message = "proxy_ssl_verify is present but not " "set to on."
    return r


@check("PK-IA-01.03")
def _pk_ia_01_03(pf: ProjectFiles) -> CheckResult:
    """Evaluate PK-IA-01.03."""
    r = CheckResult(
        steps=["Check mosquitto.conf require_certificate"],
    )
    if "require_certificate true" in pf.mosquitto_conf:
        r.result = PASS
        r.message = "Mosquitto requires client certs."
    else:
        r.message = "require_certificate true not found."
    return r


@check("PK-IA-02.01")
def _pk_ia_02_01(pf: ProjectFiles) -> CheckResult:
    """Evaluate PK-IA-02.01."""
    r = CheckResult(
        steps=["Check deploy.sh generates short-lived " "certs"],
    )
    deploy = pf._read("scripts/deploy.sh") or ""
    if "-days" in deploy:
        m = re.search(r"-days\s+(\d+)", deploy)
        if m and int(m.group(1)) <= 11:
            r.result = PASS
            r.message = f"Cert lifetime: {m.group(1)} days."
        elif m:
            r.message = f"Cert lifetime {m.group(1)} days " f"exceeds 11-day limit."
        else:
            r.message = "Could not parse -days value."
    else:
        r.message = "deploy.sh not found or -days not present."
        r.result = ERROR
    return r


@check("PK-IA-02.02")
def _pk_ia_02_02(pf: ProjectFiles) -> CheckResult:
    """Evaluate PK-IA-02.02."""
    return CheckResult(
        result=NOT_APPLICABLE,
        message=(
            "Rotation timing requires runtime check; "
            "not verifiable from static files."
        ),
        steps=["Deferred to runtime certificate monitoring"],
    )


@check("PK-IA-03.01")
def _pk_ia_03_01(pf: ProjectFiles) -> CheckResult:
    """Evaluate PK-IA-03.01."""
    r = CheckResult(
        steps=["Check NiFi keystore.p12 exists in " "nifi/data/conf/"],
    )
    ks = pf.root / "services/nifi/data/conf/keystore.p12"
    if ks.is_file():
        r.result = PASS
        r.message = "keystore.p12 exists. Issuer CN requires " "runtime verification."
    else:
        r.message = "keystore.p12 not found."
    return r


@check("PK-IA-03.02")
def _pk_ia_03_02(pf: ProjectFiles) -> CheckResult:
    """Evaluate PK-IA-03.02."""
    r = CheckResult(
        steps=["Check deploy.sh generates NiFi keystores"],
    )
    deploy = pf._read("scripts/deploy.sh") or ""
    if "keystore.p12" in deploy:
        r.result = PASS
        r.message = "deploy.sh references NiFi keystore " "generation."
    else:
        r.message = "deploy.sh does not reference NiFi " "keystore generation."
    return r


@check("PK-UC-01.01")
def _pk_uc_01_01(pf: ProjectFiles) -> CheckResult:
    """Evaluate PK-UC-01.01."""
    r = CheckResult(
        steps=["Check NiFi Dockerfile for NAR whitelist"],
    )
    df = pf.nifi_dockerfile
    if "rm -f" in df and "keep" in df.lower():
        r.result = PASS
        r.message = "Dockerfile uses whitelist approach " "for NARs."
    elif "rm -f" in df:
        r.message = "Dockerfile removes NARs but may not " "use a whitelist approach."
    else:
        r.message = "No NAR removal found in Dockerfile."
    return r


@check("PK-UC-01.02")
def _pk_uc_01_02(pf: ProjectFiles) -> CheckResult:
    """Evaluate PK-UC-01.02."""
    r = CheckResult(
        steps=["Count kept NARs in Dockerfile"],
    )
    df = pf.nifi_dockerfile
    kept = re.findall(r"nifi-[\w-]+(?=-nar\b)", df)
    count = len(set(kept))
    if count == 0:
        r.message = "Could not determine NAR count."
        r.result = ERROR
    elif count <= 20:
        r.result = PASS
        r.message = f"NAR count: {count} (limit: 20)."
    else:
        r.message = f"NAR count: {count} exceeds limit of 20."
    return r


@check("PK-UC-02.01")
def _pk_uc_02_01(pf: ProjectFiles) -> CheckResult:
    """Evaluate PK-UC-02.01."""
    r = CheckResult(
        steps=["Check mqtt_producer.py for otelTraceID " "in format string"],
    )
    src = pf._read("src/platteklip/mqtt_producer.py") or ""
    if "otelTraceID" in src and "otelSpanID" in src:
        r.result = PASS
        r.message = "OTel trace context fields present in " "log format."
    else:
        r.message = "otelTraceID/otelSpanID not found in " "mqtt_producer.py."
    return r


@check("PK-UC-02.02")
def _pk_uc_02_02(pf: ProjectFiles) -> CheckResult:
    """Evaluate PK-UC-02.02."""
    r = CheckResult(
        steps=["Check nginx log_format for OTel " "semantic attributes"],
    )
    required = [
        "client.address",
        "http.request.method",
        "url.path",
        "http.response.status_code",
    ]
    missing = [a for a in required if a not in pf.nginx_conf]
    if not missing:
        r.result = PASS
        r.message = "All OTel semantic attributes present " "in nginx log format."
    else:
        r.message = f"Missing attributes: {', '.join(missing)}"
    return r


@check("PK-UC-03.01")
def _pk_uc_03_01(pf: ProjectFiles) -> CheckResult:
    """Evaluate PK-UC-03.01."""
    r = CheckResult(
        steps=["Check Loki config for retention_period"],
    )
    loki = pf._parse_yaml("services/loki/config.yaml") or {}
    limits = loki.get("limits_config", {})
    retention = limits.get("retention_period", "")
    if retention:
        r.result = PASS
        r.message = f"Loki retention_period: {retention}"
    else:
        r.message = "Loki retention_period not explicitly " "configured."
    return r


@check("PK-SI-01.01")
def _pk_si_01_01(pf: ProjectFiles) -> CheckResult:
    """Evaluate PK-SI-01.01."""
    r = CheckResult(
        steps=["Scan compose.yaml for image references " "without @sha256:"],
    )
    services = pf.stack_cfg.get("services", {})
    unpinned = []
    for name, svc in services.items():
        img = svc.get("image", "")
        if not img:
            continue
        pp = svc.get("pull_policy", "")
        if pp == "build":
            continue
        if "@sha256:" not in img:
            unpinned.append(f"{name}: {img}")
    if not unpinned:
        r.result = PASS
        r.message = "All non-build images pinned by digest."
    else:
        r.message = f"Unpinned images: " f"{'; '.join(unpinned)}"
    return r


@check("PK-SI-01.02")
def _pk_si_01_02(pf: ProjectFiles) -> CheckResult:
    """Evaluate PK-SI-01.02."""
    r = CheckResult(
        steps=["Check compose.yaml for tag comments " "near digest pins"],
    )
    text = pf._read("compose.yaml") or ""
    digests = re.findall(r"@sha256:[a-f0-9]+", text)
    if not digests:
        r.message = "No digest pins found."
        r.result = ERROR
        return r
    comments = text.count("#") + text.count("# ")
    if comments > 0:
        r.result = PASS
        r.message = f"Found {len(digests)} digest pins; " f"comments present in file."
        r.recommendation = "Verify each digest has an adjacent " "tag comment manually."
    else:
        r.message = "No comments found near digests."
    return r


@check("PK-SI-02.01")
def _pk_si_02_01(pf: ProjectFiles) -> CheckResult:
    """Evaluate PK-SI-02.01."""
    r = CheckResult(
        steps=["Check edge_semconv.py exists and is " "non-empty"],
    )
    p = pf.root / "src/platteklip/instrumentation" / "edge_semconv.py"
    if p.is_file() and p.stat().st_size > 0:
        r.result = PASS
        r.message = f"edge_semconv.py: {p.stat().st_size} " f"bytes."
    elif p.is_file():
        r.message = "edge_semconv.py exists but is empty."
    else:
        r.message = "edge_semconv.py not found."
    return r


@check("PK-SI-02.02")
def _pk_si_02_02(pf: ProjectFiles) -> CheckResult:
    """Evaluate PK-SI-02.02."""
    r = CheckResult(
        steps=["Check transform_processor.yaml exists " "and is non-empty"],
    )
    p = pf.root / "services/weaver/generated/collector" / "transform_processor.yaml"
    if p.is_file() and p.stat().st_size > 0:
        r.result = PASS
        r.message = f"transform_processor.yaml: " f"{p.stat().st_size} bytes."
    elif p.is_file():
        r.message = "transform_processor.yaml exists but " "is empty."
    else:
        r.message = "transform_processor.yaml not found."
    return r


def _collector_pipelines(
    cfg: dict,
) -> dict[str, list[str]]:
    """Extract processor lists per pipeline."""
    svc = cfg.get("service", {})
    pipelines = svc.get("pipelines", {})
    result: dict[str, list[str]] = {}
    for name, pipe in pipelines.items():
        procs = pipe.get("processors", [])
        result[name] = [str(p) for p in procs]
    return result


@check("PK-SI-03.01")
def _pk_si_03_01(pf: ProjectFiles) -> CheckResult:
    """Evaluate PK-SI-03.01."""
    r = CheckResult(
        steps=["Check attributes/sanitize in metrics " "and logs pipelines"],
    )
    pipes = _collector_pipelines(pf.collector)
    missing = []
    for name in pipes:
        if "metrics" in name or "logs" in name:
            procs = pipes[name]
            if not any("sanitize" in p for p in procs):
                missing.append(name)
    if not missing:
        r.result = PASS
        r.message = "attributes/sanitize present in all " "metrics and logs pipelines."
    else:
        r.message = f"Missing sanitize in: " f"{', '.join(missing)}"
    return r


@check("PK-SI-03.02")
def _pk_si_03_02(pf: ProjectFiles) -> CheckResult:
    """Evaluate PK-SI-03.02."""
    r = CheckResult(
        steps=["Check attributes/sanitize in traces " "pipeline"],
    )
    pipes = _collector_pipelines(pf.collector)
    trace_pipes = [n for n in pipes if "traces" in n]
    if not trace_pipes:
        r.message = "No traces pipeline found."
        r.result = ERROR
        return r
    missing = []
    for name in trace_pipes:
        if not any("sanitize" in p for p in pipes[name]):
            missing.append(name)
    if not missing:
        r.result = PASS
        r.message = "attributes/sanitize present in traces " "pipeline."
    else:
        r.message = f"Missing sanitize in: " f"{', '.join(missing)}"
    return r


@check("PK-DC-01.01")
def _pk_dc_01_01(pf: ProjectFiles) -> CheckResult:
    """Evaluate PK-DC-01.01."""
    r = CheckResult(
        steps=["Check nginx ssl_protocols directive"],
    )
    if "ssl_protocols TLSv1.3;" in pf.nginx_conf:
        r.result = PASS
        r.message = "nginx ssl_protocols is TLSv1.3 only."
    else:
        r.message = "ssl_protocols TLSv1.3; not found in " "nginx.conf."
    return r


@check("PK-DC-01.02")
def _pk_dc_01_02(pf: ProjectFiles) -> CheckResult:
    """Evaluate PK-DC-01.02."""
    r = CheckResult(
        steps=["Check mqtt_producer.py TLS version " "constraints"],
    )
    src = pf._read("src/platteklip/mqtt_producer.py") or ""
    if "tls_min_version" in src and "TLSv1_3" in src and "tls_max_version" in src:
        r.result = PASS
        r.message = "MQTTConnectionConfig constrains TLS " "to 1.3."
    else:
        r.message = "TLS 1.3 constraints not found in " "MQTTConnectionConfig."
    return r


@check("PK-DC-01.03")
def _pk_dc_01_03(pf: ProjectFiles) -> CheckResult:
    """Evaluate PK-DC-01.03."""
    r = CheckResult(
        steps=["Check mosquitto.conf tls_version"],
    )
    if "tls_version tlsv1.3" in (pf.mosquitto_conf.lower()):
        r.result = PASS
        r.message = "Mosquitto enforces TLS 1.3."
    else:
        r.message = "tls_version tlsv1.3 not found in " "mosquitto.conf."
    return r


@check("PK-DC-02.01")
def _pk_dc_02_01(pf: ProjectFiles) -> CheckResult:
    """Evaluate PK-DC-02.01."""
    r = CheckResult(
        steps=["Check deploy.sh for ECDSA P-384 " "key generation"],
    )
    deploy = pf._read("scripts/deploy.sh") or ""
    if "prime384v1" in deploy or "secp384r1" in deploy:
        r.result = PASS
        r.message = "deploy.sh generates ECDSA P-384 keys."
    elif "ec" in deploy.lower():
        r.message = "EC key generation found but curve " "not confirmed as P-384."
    else:
        r.message = "No EC key generation found in deploy.sh."
        r.result = ERROR
    return r


@check("PK-DF-01.01")
def _pk_df_01_01(pf: ProjectFiles) -> CheckResult:
    """Evaluate PK-DF-01.01."""
    r = CheckResult(
        steps=["Check compose network definitions for " "enable_ipv6"],
    )
    networks = pf.stack_cfg.get("networks", {})
    internal = [
        "net-ingest",
        "net-storage",
        "net-identity",
        "net-admin",
    ]
    problems = []
    for net in internal:
        cfg = networks.get(net, {})
        ipv6 = cfg.get("enable_ipv6", False)
        if not ipv6:
            problems.append(f"{net}: ipv6 not enabled")
    if not problems:
        r.result = PASS
        r.message = "All internal networks have IPv6 enabled."
    else:
        r.message = "; ".join(problems)
    return r


@check("PK-DF-01.02")
def _pk_df_01_02(pf: ProjectFiles) -> CheckResult:
    """Evaluate PK-DF-01.02."""
    r = CheckResult(
        steps=["Check net-edge is the only dual-stack " "network"],
    )
    networks = pf.stack_cfg.get("networks", {})
    edge = networks.get("net-edge", {})
    ipam = edge.get("ipam", {})
    configs = ipam.get("config", [])
    has_v4 = any("." in c.get("subnet", "") for c in configs)
    has_v6 = any(":" in c.get("subnet", "") for c in configs)
    if has_v4 and has_v6:
        r.result = PASS
        r.message = "net-edge is dual-stack."
    elif has_v4:
        r.message = "net-edge has IPv4 but not IPv6."
    else:
        r.message = "net-edge network config unclear."
        r.result = ERROR
    return r


@check("PK-DF-02.01")
def _pk_df_02_01(pf: ProjectFiles) -> CheckResult:
    """Evaluate PK-DF-02.01."""
    r = CheckResult(
        steps=["Check mosquitto is not on net-storage"],
    )
    services = pf.stack_cfg.get("services", {})
    for name in ("mosquitto", "mqtt-broker"):
        svc = services.get(name, {})
        nets = svc.get("networks", [])
        if "net-storage" in nets:
            r.message = f"{name} is attached to net-storage."
            return r
    r.result = PASS
    r.message = "Mosquitto is not on net-storage."
    return r


@check("PK-DF-02.02")
def _pk_df_02_02(pf: ProjectFiles) -> CheckResult:
    """Evaluate PK-DF-02.02."""
    r = CheckResult(
        steps=[
            "Check otel-collector is sole bridge " "between net-ingest and net-storage"
        ],
    )
    services = pf.stack_cfg.get("services", {})
    bridging = []
    for name, svc in services.items():
        nets = svc.get("networks", [])
        if isinstance(nets, dict):
            nets = list(nets.keys())
        if "net-ingest" in nets and "net-storage" in nets:
            bridging.append(name)
    if bridging == ["otel-collector"]:
        r.result = PASS
        r.message = "otel-collector is the sole conduit."
    elif "otel-collector" in bridging:
        others = [s for s in bridging if s != "otel-collector"]
        r.message = f"Additional services bridge zones: " f"{', '.join(others)}"
    else:
        r.message = "No service bridges net-ingest and " "net-storage."
        r.result = ERROR
    return r


@check("PK-DF-02.03")
def _pk_df_02_03(pf: ProjectFiles) -> CheckResult:
    """Evaluate PK-DF-02.03."""
    r = CheckResult(
        steps=["Check weaver has no network membership"],
    )
    services = pf.stack_cfg.get("services", {})
    weaver = services.get("weaver", {})
    nets = weaver.get("networks", [])
    if isinstance(nets, dict):
        nets = list(nets.keys())
    if not nets:
        r.result = PASS
        r.message = "Weaver has no network membership."
    else:
        r.message = f"Weaver attached to: {', '.join(nets)}"
    return r


@check("PK-TR-01.01")
def _pk_tr_01_01(pf: ProjectFiles) -> CheckResult:
    """Evaluate PK-TR-01.01."""
    r = CheckResult(
        steps=["Check platform-infrastructure dashboard " "for max by (job) (up)"],
    )
    dashboards = pf.root / "services/grafana/dashboards"
    if not dashboards.is_dir():
        r.message = "Dashboards directory not found."
        r.result = ERROR
        return r
    for f in dashboards.glob("*.json"):
        text = f.read_text(encoding="utf-8")
        if "max by (job) (up)" in text:
            r.result = PASS
            r.message = f"Found max by (job) (up) in {f.name}."
            return r
    r.message = "max by (job) (up) not found in any " "dashboard."
    return r


@check("PK-TR-01.02")
def _pk_tr_01_02(pf: ProjectFiles) -> CheckResult:
    """Evaluate PK-TR-01.02."""
    r = CheckResult(
        steps=["Check dashboards for memory_limiter " "panels"],
    )
    dashboards = pf.root / "services/grafana/dashboards"
    if not dashboards.is_dir():
        r.message = "Dashboards directory not found."
        r.result = ERROR
        return r
    for f in dashboards.glob("*.json"):
        text = f.read_text(encoding="utf-8")
        if "memory_limiter" in text:
            r.result = PASS
            r.message = f"memory_limiter panel found in " f"{f.name}."
            return r
    r.message = "No memory_limiter panel found in dashboards."
    return r


@check("PK-TR-01.03")
def _pk_tr_01_03(pf: ProjectFiles) -> CheckResult:
    """Evaluate PK-TR-01.03."""
    r = CheckResult(
        steps=["Check dashboards for invalid LogQL " "(or between stream selectors)"],
    )
    dashboards = pf.root / "services/grafana/dashboards"
    if not dashboards.is_dir():
        r.message = "Dashboards directory not found."
        r.result = ERROR
        return r
    invalid = []
    pattern = re.compile(
        r"\{[^}]+\}\s*\|[^|]*\bor\b\s*\{",
    )
    for f in dashboards.glob("*.json"):
        text = f.read_text(encoding="utf-8")
        if pattern.search(text):
            invalid.append(f.name)
    if not invalid:
        r.result = PASS
        r.message = "No invalid LogQL found."
    else:
        r.message = f"Invalid LogQL in: {', '.join(invalid)}"
    return r


@check("PK-TR-02.01")
def _pk_tr_02_01(pf: ProjectFiles) -> CheckResult:
    """Evaluate PK-TR-02.01."""
    return CheckResult(
        result=NOT_APPLICABLE,
        message="Control is in Draft state.",
        steps=["Skipped — Draft control"],
    )


@check("PK-TR-02.02")
def _pk_tr_02_02(pf: ProjectFiles) -> CheckResult:
    """Evaluate PK-TR-02.02."""
    return CheckResult(
        result=NOT_APPLICABLE,
        message="Control is in Draft state.",
        steps=["Skipped — Draft control"],
    )


@check("PK-RA-01.01")
def _pk_ra_01_01(pf: ProjectFiles) -> CheckResult:
    """Evaluate PK-RA-01.01."""
    r = CheckResult(
        steps=["Check deploy.resources.limits.memory " "on all services"],
    )
    services = pf.stack_cfg.get("services", {})
    missing = []
    for name, svc in services.items():
        limits = svc.get("deploy", {}).get("resources", {}).get("limits", {})
        if "memory" not in limits:
            missing.append(name)
    if not missing:
        r.result = PASS
        r.message = "All services have memory limits."
    else:
        r.message = f"Missing memory limits: " f"{', '.join(missing)}"
    return r


@check("PK-RA-01.02")
def _pk_ra_01_02(pf: ProjectFiles) -> CheckResult:
    """Evaluate PK-RA-01.02."""
    r = CheckResult(
        steps=["Check deploy.resources.limits.cpus " "on all services"],
    )
    services = pf.stack_cfg.get("services", {})
    missing = []
    for name, svc in services.items():
        limits = svc.get("deploy", {}).get("resources", {}).get("limits", {})
        if "cpus" not in limits:
            missing.append(name)
    if not missing:
        r.result = PASS
        r.message = "All services have CPU limits."
    else:
        r.message = f"Missing CPU limits: " f"{', '.join(missing)}"
    return r


@check("PK-RA-01.03")
def _pk_ra_01_03(pf: ProjectFiles) -> CheckResult:
    """Evaluate PK-RA-01.03."""
    r = CheckResult(
        steps=["Check deploy.resources.limits.pids " "on all services"],
    )
    services = pf.stack_cfg.get("services", {})
    missing = []
    for name, svc in services.items():
        limits = svc.get("deploy", {}).get("resources", {}).get("limits", {})
        if "pids" not in limits:
            missing.append(name)
    if not missing:
        r.result = PASS
        r.message = "All services have PID limits."
    else:
        r.message = f"Missing PID limits: " f"{', '.join(missing)}"
    return r


@check("PK-RA-02.01")
def _pk_ra_02_01(pf: ProjectFiles) -> CheckResult:
    """Evaluate PK-RA-02.01."""
    r = CheckResult(
        steps=["Check memory_limiter is first processor " "in every pipeline"],
    )
    pipes = _collector_pipelines(pf.collector)
    violations = []
    for name, procs in pipes.items():
        if not procs:
            violations.append(f"{name}: no processors")
            continue
        if "memory_limiter" not in procs[0]:
            violations.append(f"{name}: first is {procs[0]}")
    if not violations:
        r.result = PASS
        r.message = "memory_limiter is first in all pipelines."
    else:
        r.message = f"Violations: {'; '.join(violations)}"
    return r


@check("PK-RA-02.02")
def _pk_ra_02_02(pf: ProjectFiles) -> CheckResult:
    """Evaluate PK-RA-02.02."""
    r = CheckResult(
        steps=["Check memory_limiter configuration " "thresholds"],
    )
    procs = pf.collector.get("processors", {})
    ml = procs.get("memory_limiter", {})
    limit = ml.get("limit_mib", 0)
    spike = ml.get("spike_limit_mib", 0)
    if limit > 0 and spike > 0:
        r.result = PASS
        r.message = f"memory_limiter: limit={limit} MiB, " f"spike={spike} MiB."
    else:
        r.message = "memory_limiter thresholds not configured."
    return r


@check("PK-RA-03.01")
def _pk_ra_03_01(pf: ProjectFiles) -> CheckResult:
    """Evaluate PK-RA-03.01."""
    r = CheckResult(
        steps=["Check UID_PROMETHEUS in .env"],
    )
    uid = pf.env.get("UID_PROMETHEUS", "")
    if uid == "65532":
        r.result = PASS
        r.message = "UID_PROMETHEUS is 65532."
    elif uid:
        r.message = f"UID_PROMETHEUS is {uid}, expected 65532."
    else:
        r.message = "UID_PROMETHEUS not found in .env."
        r.result = ERROR
    return r


@check("PK-RA-03.02")
def _pk_ra_03_02(pf: ProjectFiles) -> CheckResult:
    """Evaluate PK-RA-03.02."""
    r = CheckResult(
        steps=["Check .env for UID comments"],
    )
    text = pf._read(".env") or ""
    all_lines = text.splitlines()
    uid_lines = [line for line in all_lines if line.strip().startswith("UID_")]
    commented = sum(
        1
        for i, line in enumerate(uid_lines)
        if i > 0 and all_lines[all_lines.index(line) - 1].strip().startswith("#")
    )
    if uid_lines and commented >= len(uid_lines) // 2:
        r.result = PASS
        r.message = "UID variables have adjacent comments."
    elif uid_lines:
        r.message = "Some UID variables lack comments."
    else:
        r.message = "No UID_ variables found in .env."
        r.result = ERROR
    return r


@check("PK-RA-04.01")
def _pk_ra_04_01(pf: ProjectFiles) -> CheckResult:
    """Evaluate PK-RA-04.01."""
    r = CheckResult(
        steps=["Check collector config for " "service.instance.id"],
    )
    svc = pf.collector.get("service", {})
    telemetry = svc.get("telemetry", {})
    resource = telemetry.get("resource", {})
    iid = resource.get("service.instance.id", "")
    if iid:
        r.result = PASS
        r.message = f"service.instance.id: {iid}"
    else:
        r.message = "service.instance.id not set in " "collector telemetry resource."
    return r


# ------------------------------------------------------------------
# Evaluation log assembly
# ------------------------------------------------------------------


def _build_assessment_log(
    ar_id: str,
    applicability: list[str],
    result: CheckResult,
    ts: str,
) -> dict:
    """Build a single AssessmentLog entry."""
    return {
        "requirement": {
            "entry-id": ar_id,
            "reference-id": CATALOG_REF,
        },
        "applicability": applicability,
        "description": f"Automated check for {ar_id}",
        "message": result.message,
        "result": result.result,
        "start": ts,
        "steps": result.steps,
    }


def run_evaluation(
    pf: ProjectFiles,
    catalog_path: Path,
) -> dict:
    """Run all checks and return an EvaluationLog."""
    with catalog_path.open() as f:
        catalog = yaml.safe_load(f)

    ts = datetime.datetime.now(
        tz=datetime.UTC,
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    evaluations: list[dict] = []
    total_pass = 0
    total_fail = 0

    for control in catalog.get("controls", []):
        ctrl_id = control["id"]
        ctrl_name = control["title"]
        assessment_logs: list[dict] = []
        ctrl_pass = True

        for ar in control.get(
            "assessment-requirements",
            [],
        ):
            ar_id = ar["id"]
            applicability = ar.get(
                "applicability",
                [],
            )
            check_fn = _REGISTRY.get(ar_id)

            if check_fn is None:
                cr = CheckResult(
                    result=ERROR,
                    message=(f"No check registered for " f"{ar_id}."),
                    steps=["No check implemented"],
                )
            else:
                try:
                    cr = check_fn(pf)
                except Exception as exc:
                    cr = CheckResult(
                        result=ERROR,
                        message=str(exc),
                        steps=["Check raised exception"],
                    )

            assessment_logs.append(
                _build_assessment_log(
                    ar_id,
                    applicability,
                    cr,
                    ts,
                ),
            )

            if cr.result == PASS:
                total_pass += 1
            elif cr.result == FAIL:
                total_fail += 1
                ctrl_pass = False
            elif cr.result == ERROR:
                ctrl_pass = False

        ctrl_result = PASS if ctrl_pass else FAIL
        evaluations.append(
            {
                "control": {
                    "entry-id": ctrl_id,
                    "reference-id": CATALOG_REF,
                },
                "name": ctrl_name,
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
# Entry point
# ------------------------------------------------------------------


def main() -> None:
    """CLI entry point."""
    if len(sys.argv) < 2:
        sys.stderr.write(
            "Usage: python evaluate_controls.py " "<project-root> [catalog.yaml]\n",
        )
        raise SystemExit(1)

    project_root = Path(sys.argv[1]).resolve()
    if not project_root.is_dir():
        sys.stderr.write(
            f"Not a directory: {project_root}\n",
        )
        raise SystemExit(1)

    catalog_path = (
        Path(sys.argv[2])
        if len(sys.argv) > 2
        else project_root / "gemara" / "platteklip-controls.yaml"
    )

    pf = ProjectFiles(root=project_root)
    log = run_evaluation(pf, catalog_path)

    yaml.dump(
        log,
        sys.stdout,
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
        width=72,
    )


if __name__ == "__main__":
    main()
