<!--
# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: CC-BY-4.0
-->

# CHANGELOG

<!-- version list -->

## v0.2.0 (2026-04-13)

### Bug Fixes

- **ci**: Resolve pre-commit findings in Dagger
  ([`758f822`](https://github.com/technicaldescent/platteklip/commit/758f8222bd5428f3d7a37e508aa2c7b2de884c93))

- **release**: Tag-only signing
  ([`c9b49b8`](https://github.com/technicaldescent/platteklip/commit/c9b49b853bbc30356453d732668df084390f8502))

### Build System

- **hatch**: Restructure environments and deps
  ([`1b8b2bb`](https://github.com/technicaldescent/platteklip/commit/1b8b2bb0e5cdea51b7bfd8fa84ae66b3009cf3ee))

### Features

- **ci**: Add Dagger pipeline module
  ([`89d593b`](https://github.com/technicaldescent/platteklip/commit/89d593b31d7bacaeb8fdaf52c234b09213f846d7))

- **ci**: Attested pipeline with Witness Rego
  ([`be4ed8f`](https://github.com/technicaldescent/platteklip/commit/be4ed8fdab287e3ae5277e6c87ed7ee367a82ab6))

- **gemara**: Add GRC evidence and evaluation
  ([`4e6efef`](https://github.com/technicaldescent/platteklip/commit/4e6efef73ff436dde073dccf30d7609c32d210a2))

- **grafana**: Provision dashboards and alerts
  ([`eea12c0`](https://github.com/technicaldescent/platteklip/commit/eea12c0fac1977342e169fa36452a38856b6f98c))

- **jaeger**: Adopt v2 config and enforce mTLS
  ([`da71467`](https://github.com/technicaldescent/platteklip/commit/da714672c34d09f6bf451d39eb76d9cf13b3bb03))

- **loki**: Enforce policy and BDD tests
  ([`d00a7df`](https://github.com/technicaldescent/platteklip/commit/d00a7df96a444e3d3e530a4d9ac82e2568b3bf14))

- **mosquitto**: Secure broker and tune limits
  ([`84cebe5`](https://github.com/technicaldescent/platteklip/commit/84cebe5df6c7dff1a2265215ca22eba0b1ed33f0))

- **nginx**: Configure reverse proxy and metrics
  ([`d646639`](https://github.com/technicaldescent/platteklip/commit/d646639dbdc468f620423f7b62bfdfb2bc5eb1d8))

- **otel**: Secure and tune collector pipelines
  ([`dcf24c3`](https://github.com/technicaldescent/platteklip/commit/dcf24c3ef948e7df92e82f7810ee9f1ca5960268))

- **pre-commit**: Add strict gherkin linter hook
  ([`f701d9d`](https://github.com/technicaldescent/platteklip/commit/f701d9d4dee1ad240af47f455f0bc856bf1d4a36))

- **prometheus**: Enforce mTLS and tsdb limits
  ([`66a9d1a`](https://github.com/technicaldescent/platteklip/commit/66a9d1afd2ebf48ee6e0887401d8c1ac4ec693ad))

- **weaver**: Add edge models and templates
  ([`366ef13`](https://github.com/technicaldescent/platteklip/commit/366ef13f591fd1f142d2454c1ff585dffc6ee9e9))

### Refactoring

- **mqtt-producer**: Refactor and vendor client
  ([`d621621`](https://github.com/technicaldescent/platteklip/commit/d621621d2323466598b002ffdfb8873abad4e116))

- **policy**: Restructure into requirements
  ([`8ddaa94`](https://github.com/technicaldescent/platteklip/commit/8ddaa942b7ee83077acf75a805bd87fdc9208b1f))

### Testing

- Expand coverage and fix mypy strict
  ([`1560716`](https://github.com/technicaldescent/platteklip/commit/15607160fc4b52f551dff1056493958c0866fb9f))


## v0.1.0 (2025-10-30)

- Initial Release
