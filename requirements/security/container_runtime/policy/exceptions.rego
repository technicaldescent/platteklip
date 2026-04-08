# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

package main

import rego.v1

# ============================================================================
# Exceptions / Allow-lists
# ============================================================================

# Services allowed to run with read_only: false
# These require write access for logs, temporary files, or internal storage.
exceptions_read_only_allowlist := {
	"kafka",
	"jenkins",
}

# True if a service name is in the allow-list.
is_read_only_exempt(name) if {
	name in exceptions_read_only_allowlist
}

# ============================================================================
# Network Exceptions
# ============================================================================

# CIS-5.14: Services allowed to bind to 0.0.0.0 (Public Internet Access)
# Justification: Ingress controllers / endpoints intended for public access.
exceptions_public_port_allowlist := {"nginx"}

is_public_port_exempt(name) if {
	name in exceptions_public_port_allowlist
}
