# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

r"""Dagger Continuous Integration pipeline.

Each function corresponds to an independently cacheable and
attestable pipeline stage.  Local development shortcuts remain
in pyproject.toml (Hatch environments); this module owns CI
orchestration, image builds, and SBOM generation.

Signing and attestation use cosign keyless mode (Sigstore
OIDC) and run outside Dagger:

- **Locally**: ``cosign sign --yes <ref>`` opens a browser
  for GitHub OIDC authentication.
- **CI**: GitHub Actions provides an OIDC token
  automatically; no secrets configuration needed.

Testing
~~~~~~~
::

    dagger call test-unit --source=.
    dagger call python-env --source=. terminal

Quality
~~~~~~~
::

    dagger call quality --source=.

Acceptance
~~~~~~~~~~
::

    dagger call acceptance --source=.

Policy
~~~~~~
::

    dagger call policy --source=.
    dagger call policy-env --source=. terminal

Image builds
~~~~~~~~~~~~
::

    dagger call build --source=. --service=mqtt-producer
    dagger call build --source=. --service=nifi

SBOM generation
~~~~~~~~~~~~~~~
::

    dagger call sbom --source=. --service=mqtt-producer \\
        export --path=./mqtt-producer.spdx.json

Publishing
~~~~~~~~~~
::

    dagger call publish --source=. \\
        --service=mqtt-producer \\
        --registry=ghcr.io/technicaldescent \\
        --version=0.1.0

Signing and attestation (outside Dagger)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
::

    cosign sign --yes <digest-ref>

    cosign attest --yes \\
        --predicate sbom.spdx.json \\
        --type spdxjson <digest-ref>

    cosign verify \\
        --certificate-identity-regexp='.*' \\
        --certificate-oidc-issuer-regexp='.*' \\
        <digest-ref>
"""

from dataclasses import dataclass
from typing import Annotated

import dagger
from dagger import DefaultPath, Doc, dag, function, object_type

# =================================================================
# Tool versions
# =================================================================

_OPA_VERSION: str = "1.15.2"
_REGAL_VERSION: str = "0.39.0"


# =================================================================
# Service build configurations
# =================================================================
#
# Maps each buildable service to its Dockerfile location and
# image name.  Services using upstream images pinned by digest
# (nginx, kafka, prometheus, etc.) are not built by this
# pipeline — they are pulled directly by compose.


@dataclass(frozen=True, slots=True)
class _ServiceBuild:
    """Build descriptor for a single service."""

    context: str
    """Path to the build context, relative to project root."""

    dockerfile: str
    """Dockerfile path, relative to the build context."""

    image_name: str
    """Base image name (without registry or tag)."""


_SERVICES: dict[str, _ServiceBuild] = {
    "keycloak-postgres": _ServiceBuild(
        context="services/keycloak-postgres",
        dockerfile="Dockerfile",
        image_name="keycloak-postgres",
    ),
    "nifi": _ServiceBuild(
        context="services/nifi",
        dockerfile="Dockerfile",
        image_name="nifi-plc4x",
    ),
    "mqtt-producer": _ServiceBuild(
        context=".",
        dockerfile="services/mqtt-producer/Dockerfile",
        image_name="mqtt-producer",
    ),
}


# Ignore during test/quality source mount.
_TEST_EXCLUDE: list[str] = [
    ".dagger/",
    ".git/",
    ".venv/",
    "__pycache__/",
    "*.pyc",
    "dist/",
    "docs/build/",
    "gemara/evidence/",
    "k8s/",
    "services/secrets/",
    "services/grafana/data/",
    "services/kafka/data/",
    "services/keycloak-postgres/data/",
    "services/nifi/data/",
    "services/otel-collector/data/",
]


def _lookup_build(service: str) -> _ServiceBuild:
    """Look up a service build descriptor or raise."""
    try:
        return _SERVICES[service]
    except KeyError:
        valid = ", ".join(sorted(_SERVICES))
        msg = f"Unknown service {service!r}. " f"Buildable services: {valid}"
        raise ValueError(msg) from None


def _opa_url() -> str:
    """OPA static binary download URL."""
    return (
        "https://github.com/open-policy-agent/opa"
        f"/releases/download/v{_OPA_VERSION}"
        "/opa_linux_amd64_static"
    )


def _regal_url() -> str:
    """Regal binary download URL."""
    return (
        "https://github.com/StyraInc/regal"
        f"/releases/download/v{_REGAL_VERSION}"
        "/regal_Linux_x86_64"
    )


def _install_opa(ctr: dagger.Container) -> dagger.Container:
    """Download and install OPA into a container."""
    return ctr.with_exec(
        [
            "sh",
            "-c",
            f"curl -sL -o /usr/local/bin/opa {_opa_url()}"
            " && chmod +x /usr/local/bin/opa",
        ]
    )


# =================================================================
# Pipeline
# =================================================================


@object_type
class Ci:
    """Continuous Integration pipeline."""

    # -------------------------------------------------------------
    # Test stages
    # -------------------------------------------------------------

    @function
    def python_env(
        self,
        source: Annotated[
            dagger.Directory,
            DefaultPath("/"),
            Doc("Project root directory"),
        ],
    ) -> dagger.Container:
        """Python 3.14 container with dev dependencies.

        Shared across test, quality, and acceptance stages.
        Pip downloads are cached between runs.

        Use interactively for debugging::

            dagger call python-env --source=. terminal
        """
        pip_cache = dag.cache_volume("pip")
        return (
            dag.container()
            .from_("python:3.14-slim")
            .with_exec(
                [
                    "apt-get",
                    "update",
                    "-qq",
                ]
            )
            .with_exec(
                [
                    "apt-get",
                    "install",
                    "-y",
                    "-qq",
                    "git",
                    "curl",
                ]
            )
            .with_mounted_cache("/root/.cache/pip", pip_cache)
            .with_directory(
                "/app",
                source,
                exclude=_TEST_EXCLUDE,
            )
            .with_workdir("/app")
            .with_exec(
                [
                    "pip",
                    "install",
                    "--quiet",
                    "-e",
                    ".[dev,observability]",
                ]
            )
            .with_env_variable("PYTHONPATH", "src")
        )

    @function
    async def test_unit(
        self,
        source: Annotated[
            dagger.Directory,
            DefaultPath("/"),
            Doc("Project root directory"),
        ],
    ) -> str:
        """Run pytest unit tests.

        Options from ``[tool.pytest.ini_options]`` in
        ``pyproject.toml`` are applied automatically.
        """
        return await (
            self.python_env(source).with_exec(["pytest", "tests/unit"]).stdout()
        )

    @function
    async def test_unit_results(
        self,
        source: Annotated[
            dagger.Directory,
            DefaultPath("/"),
            Doc("Project root directory"),
        ],
    ) -> dagger.Directory:
        """Run unit tests and return the artefact directory.

        Exports JUnit XML and coverage XML produced by
        pytest.  These feed into the evidence collection
        stage downstream.
        """
        ctr = await self.python_env(source).with_exec(["pytest", "tests/unit"]).sync()
        return ctr.directory("/app/tests")

    # -------------------------------------------------------------
    # Quality stage — static analysis
    # -------------------------------------------------------------

    @function
    async def quality(
        self,
        source: Annotated[
            dagger.Directory,
            DefaultPath("/"),
            Doc("Project root directory"),
        ],
    ) -> str:
        """Run the full static analysis suite.

        Executes each check sequentially.  The pipeline
        stops at the first failure so the output shows
        exactly which check needs attention.

        Checks: bandit, black, detect-secrets,
        flake8, interrogate, mypy, xenon, tryceratops.
        """
        return await (
            self.python_env(source)
            .with_exec(
                [
                    "bandit",
                    "-c",
                    "pyproject.toml",
                    "-r",
                    "src",
                ]
            )
            .with_exec(
                [
                    "black",
                    "--check",
                    "--diff",
                    "src",
                    "tests",
                    "requirements",
                ]
            )
            .with_exec(["detect-secrets", "scan"])
            .with_exec(["flake8", "src", "tests"])
            .with_exec(["interrogate", "-vv", "."])
            .with_exec(["mypy"])
            .with_exec(
                [
                    "xenon",
                    "--max-absolute",
                    "B",
                    "--max-modules",
                    "A",
                    "--max-average",
                    "A",
                    "src",
                ]
            )
            .with_exec(
                [
                    "tryceratops",
                    "check",
                    "src",
                    "tests",
                ]
            )
            .stdout()
        )

    # -------------------------------------------------------------
    # Acceptance stage — behave BDD
    # -------------------------------------------------------------

    @function
    async def acceptance(
        self,
        source: Annotated[
            dagger.Directory,
            DefaultPath("/"),
            Doc("Project root directory"),
        ],
    ) -> str:
        """Run behave BDD acceptance tests.

        Uses a Python environment with OPA installed,
        since several step definitions evaluate Rego
        policies via subprocess.

        Feature files are discovered from the paths
        configured in ``[tool.behave]`` in
        ``pyproject.toml``.
        """
        return await (
            _install_opa(self.python_env(source)).with_exec(["behave"]).stdout()
        )

    # -------------------------------------------------------------
    # Policy stage — OPA and Regal
    # -------------------------------------------------------------

    @function
    def policy_env(
        self,
        source: Annotated[
            dagger.Directory,
            DefaultPath("/"),
            Doc("Project root directory"),
        ],
    ) -> dagger.Container:
        """Container with Open Policy Agent (OPA) and Regal.

        Use interactively for debugging::

            dagger call policy-env --source=. terminal
        """
        return (
            dag.container()
            .from_("alpine:3.23.3")
            .with_exec(
                [
                    "apk",
                    "add",
                    "--no-cache",
                    "curl",
                ]
            )
            .with_exec(
                [
                    "sh",
                    "-c",
                    f"curl -sL -o /usr/local/bin/opa"
                    f" {_opa_url()}"
                    " && chmod +x /usr/local/bin/opa",
                ]
            )
            .with_exec(
                [
                    "sh",
                    "-c",
                    f"curl -sL -o /usr/local/bin/regal"
                    f" {_regal_url()}"
                    " && chmod +x /usr/local/bin/regal",
                ]
            )
            .with_directory(
                "/app",
                source,
                exclude=_TEST_EXCLUDE,
            )
            .with_workdir("/app")
        )

    @function
    async def policy(
        self,
        source: Annotated[
            dagger.Directory,
            DefaultPath("/"),
            Doc("Project root directory"),
        ],
    ) -> str:
        """Run OPA unit tests and Regal linting.

        Tests all Rego policies under ``requirements/``
        and ``policy/``, then lints them with Regal.
        """
        return await (
            self.policy_env(source)
            .with_exec(
                [
                    "opa",
                    "test",
                    "requirements/security/" "container_runtime/policy/",
                    "-v",
                ]
            )
            .with_exec(
                [
                    "opa",
                    "test",
                    "requirements/security/" "container_image/policy/",
                    "-v",
                ]
            )
            .with_exec(
                [
                    "opa",
                    "test",
                    "requirements/security/" "use_control/policy/",
                    "-v",
                ]
            )
            .with_exec(
                [
                    "opa",
                    "test",
                    "requirements/development/semconv/policy/",
                    "-v",
                ]
            )
            .with_exec(
                [
                    "regal",
                    "lint",
                    "requirements/",
                ]
            )
            .stdout()
        )

    # -------------------------------------------------------------
    # Image builds
    # -------------------------------------------------------------

    @function
    def build(
        self,
        source: Annotated[
            dagger.Directory,
            DefaultPath("/"),
            Doc("Project root directory"),
        ],
        service: Annotated[
            str,
            Doc("Service to build: " "keycloak-postgres, nifi, mqtt-producer"),
        ],
    ) -> dagger.Container:
        r"""Build a service container image from its Dockerfile.

        Returns the built container, which can be inspected
        interactively, exported as a tarball, or published
        to a registry::

            dagger call build --source=. \\
                --service=mqtt-producer terminal

            dagger call build --source=. \\
                --service=mqtt-producer \\
                export --path=./image.tar
        """
        cfg = _lookup_build(service)
        if cfg.context == ".":
            context = (
                source.without_directory(
                    ".dagger",
                )
                .without_directory(
                    ".git",
                )
                .without_directory(
                    ".venv",
                )
                .without_directory(
                    "dist",
                )
                .without_directory(
                    "docs",
                )
                .without_directory(
                    "gemara",
                )
                .without_directory(
                    "k8s",
                )
                .without_directory(
                    "services/secrets",
                )
                .without_directory(
                    "tests",
                )
            )
        else:
            context = source.directory(cfg.context)
        return context.docker_build(
            dockerfile=cfg.dockerfile,
        )

    # -------------------------------------------------------------
    # SBOM generation
    # -------------------------------------------------------------

    @function
    def sbom(
        self,
        source: Annotated[
            dagger.Directory,
            DefaultPath("/"),
            Doc("Project root directory"),
        ],
        service: Annotated[
            str,
            Doc("Service to scan: " "keycloak-postgres, nifi, mqtt-producer"),
        ],
    ) -> dagger.File:
        r"""Generate an SPDX 2.3 SBOM for a service image.

        Builds the service image, exports it as an OCI
        tarball, and scans it with Syft.  Returns the
        SBOM as an SPDX JSON file.

        Export locally::

            dagger call sbom --source=. \\
                --service=mqtt-producer \\
                export --path=./sbom.spdx.json
        """
        cfg = _lookup_build(service)
        image = self.build(source, service)
        tarball = image.as_tarball()
        return (
            dag.container()
            .from_("anchore/syft:latest")
            .with_mounted_file(
                "/work/image.tar",
                tarball,
            )
            .with_exec(
                [
                    "/syft",
                    "oci-archive:/work/image.tar",
                    "--source-name",
                    cfg.image_name,
                    "-o",
                    "spdx-json=/work/sbom.spdx.json",
                ]
            )
            .file("/work/sbom.spdx.json")
        )

    # -------------------------------------------------------------
    # Publish
    # -------------------------------------------------------------

    @function
    async def publish(
        self,
        source: Annotated[
            dagger.Directory,
            DefaultPath("/"),
            Doc("Project root directory"),
        ],
        service: Annotated[
            str,
            Doc("Service to publish: " "keycloak-postgres, nifi, mqtt-producer"),
        ],
        registry: Annotated[
            str,
            Doc("Registry prefix " "(e.g. ghcr.io/technicaldescent)"),
        ],
        version: Annotated[
            str,
            Doc("Image tag (e.g. 0.1.0, 0.2.0-alpha.1)"),
        ],
    ) -> str:
        r"""Build and push a service image to a registry.

        Returns the fully qualified image reference with
        digest.  Sign the returned reference with cosign
        keyless mode::

            REF=$(dagger call publish --source=. \\
                --service=mqtt-producer \\
                --registry=ghcr.io/technicaldescent \\
                --version=0.1.0)

            cosign sign --yes "$REF"

            cosign attest --yes \\
                --predicate sbom.spdx.json \\
                --type spdxjson "$REF"
        """
        cfg = _lookup_build(service)
        image = self.build(source, service)
        ref = f"{registry}/{cfg.image_name}:{version}"
        return await image.publish(ref)
