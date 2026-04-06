# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

"""Tests for the platteklip package __init__ module.

Covers the version discovery logic: the success path
where ``importlib.metadata.version`` returns a valid
version string, and the fallback path where the
package is not installed and ``PackageNotFoundError``
is caught.
"""

import importlib
import unittest
from importlib import metadata
from unittest.mock import patch


class TestPackageInitVersion(unittest.TestCase):
    """Verify __version__ discovery from package metadata."""

    def test_version_success_branch(self) -> None:
        """Set __version__ from installed metadata."""
        with patch(
            "importlib.metadata.version",
            return_value="9.9.9",
        ):
            pkg = importlib.import_module("platteklip")
            importlib.reload(pkg)
            self.assertEqual(
                pkg.__version__,
                "9.9.9",
            )

        pkg = importlib.import_module("platteklip")
        importlib.reload(pkg)

    def test_version_package_not_found_branch(
        self,
    ) -> None:
        """Fall back to 0.0.0 when not installed."""
        with patch(
            "importlib.metadata.version",
            side_effect=(metadata.PackageNotFoundError),
        ):
            pkg = importlib.import_module("platteklip")
            importlib.reload(pkg)
            self.assertEqual(
                pkg.__version__,
                "0.0.0",
            )

        pkg = importlib.import_module("platteklip")
        importlib.reload(pkg)
