# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

"""Initialisation of the Python package.

This module defines the versioning interface for the package and
exposes public symbols through `__all__`. The version string
complies with Semantic Versioning (SemVer 2.0.0) and is
intended for use in programmatic version checks and release
automation workflows.
"""

from importlib.metadata import PackageNotFoundError, version

__all__ = [
    "__version__",
]

try:
    # The distribution name is defined in pyproject.toml
    __version__ = version("platteklip")
except PackageNotFoundError:
    # The package is not installed, so we don't know the version
    __version__ = "0.0.0"
