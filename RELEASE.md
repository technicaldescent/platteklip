<!--
# SPDX-FileCopyrightText: 2025 best-known-practice contributors
# SPDX-License-Identifier: CC-BY-4.0
-->

# Release and Support Policy

This document outlines our release process, dependency support, and the support lifecycle for our releases.

## Release Automation

This project uses [Conventional Commits](https://www.conventionalcommits.org/) for its commit history. Based on these commits, our release process is automated using a semantic release system.

* **Versioning:** Version numbers are automatically determined and incremented according to the [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html) specification.
* **Changelogs:** A detailed changelog is automatically generated for every release.
* **Release Cadence:** A new version is published automatically whenever commits that trigger a version bump are merged into our main branch.

## Dependency Support Policy

Our support policy is influenced by Scientific Python Ecosystem Coordination, as detailed in [SPEC 0](https://scientific-python.org/specs/spec-0000/).

In addition, the policy is to treat `DeprecationWarning` and `PendingDeprecationWarning` from dependencies as errors when testing. This is configured in `pyproject.toml`.

This practice means the codebase is always compatible with the *next* versions of our dependencies. As a result, a `MINOR` release of this project may require newer dependency versions than the minimums defined below, a choice we make to prevent future breakage.

### Minimum Support Window
The following defines the minimum support window for dependencies:

* **Python Support:** We drop support for a MINOR version of Python **36 months after its initial release**. We will support at least the last two MINOR versions of Python.
* **Library Support (NumPy, etc.):** We drop support for a MINOR version of third party packages **24 months after its initial release**. We support at least the last two MINOR versions.

### Breaking Changes
**Dropping support for a version of Python is a BREAKING CHANGE.** Such changes will only occur in a `MAJOR` version release of this project.

## Project Support Lifecycle

While the release of new versions is continuous, we provide a predictable support policy for our own `MAJOR` release series.

* **Active Support:** The latest release series receives regular bug fixes (`PATCH` releases) and new features (`MINOR` releases).
* **Security Fixes Only:** Older, but still supported, release series will only receive critical security patches.
* **End-of-Life (EoL):** Once a release series reaches its End-of-Life date, it is no longer supported.

---
*This document was last updated on `2025-09-26`.*
