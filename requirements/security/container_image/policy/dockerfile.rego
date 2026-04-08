# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

package main

import rego.v1

# Import control metadata (Gemara L2 AR IDs)
import data.cis_docker_controls

# ============================================================================
# Helpers
# ============================================================================

format_violation(id, specific_msg) := msg if {
	control := cis_docker_controls.controls[id]
	msg := sprintf(
		"%s %s: %s (Remediation: %s)",
		[
			id, control.title,
			specific_msg, control.remediation,
		],
	)
} else := msg if {
	not cis_docker_controls.controls[id]
	msg := sprintf("%s: %s", [id, specific_msg])
}

is_dockerfile if {
	is_array(input)
}

# ============================================================================
# Deny rules
# ============================================================================

# CIS-CTL-4.1.01: USER instruction present
deny contains msg if {
	is_dockerfile

	users := [u |
		some i
		input[i].Cmd == "user"
		u := input[i].Value
	]

	count(users) == 0

	msg := format_violation(
		"CIS-CTL-4.1.01",
		"No USER instruction found.",
	)
}

# CIS-CTL-4.1.02: Last USER is not root
deny contains msg if {
	is_dockerfile

	users := [u |
		some i
		input[i].Cmd == "user"
		u := input[i].Value
	]
	count(users) > 0

	last_user := users[count(users) - 1]
	user_str := concat("", last_user)
	contains(lower(user_str), "root")

	msg := format_violation(
		"CIS-CTL-4.1.02",
		sprintf(
			"Last USER is '%v'.",
			[user_str],
		),
	)
}

# CIS-CTL-4.6.01: HEALTHCHECK present
deny contains msg if {
	is_dockerfile

	healthchecks := [h |
		some i
		input[i].Cmd == "healthcheck"
		h := input[i]
	]
	count(healthchecks) == 0

	msg := format_violation(
		"CIS-CTL-4.6.01",
		"No HEALTHCHECK instruction found.",
	)
}

# CIS-CTL-4.7.01: No standalone update instructions
deny contains msg if {
	is_dockerfile

	some i
	input[i].Cmd == "run"
	val := concat(" ", input[i].Value)

	regex.match(
		`(?i)(apt-get|apk|yum)\s+update`,
		val,
	)
	not regex.match(`(?i)(install|add)`, val)

	msg := format_violation(
		"CIS-CTL-4.7.01",
		sprintf(
			"Update instruction used alone: '%v'.",
			[val],
		),
	)
}

# CIS-CTL-4.9.01: COPY instead of ADD
deny contains msg if {
	is_dockerfile

	some i
	input[i].Cmd == "add"
	val := input[i].Value

	msg := format_violation(
		"CIS-CTL-4.9.01",
		sprintf(
			"ADD instruction found: '%v'.",
			[val],
		),
	)
}

# CIS-CTL-4.10.01: No secrets in ENV
deny contains msg if {
	is_dockerfile

	some i
	input[i].Cmd == "env"
	val := input[i].Value

	key := env_key(val)
	regex.match(
		`(?i)(password|secret|key|token|auth)`,
		key,
	)

	msg := format_violation(
		"CIS-CTL-4.10.01",
		sprintf(
			"Suspicious ENV key found '%v'.",
			[key],
		),
	)
}

# CIS-CTL-4.11.01: No pipe-to-shell
deny contains msg if {
	is_dockerfile

	some i
	input[i].Cmd == "run"
	val := concat(" ", input[i].Value)

	regex.match(
		`(?i)(curl|wget).*\|\s*(sh|bash|zsh)`,
		val,
	)

	msg := format_violation(
		"CIS-CTL-4.11.01",
		sprintf(
			"Insecure pipe to shell detected in '%v'.",
			[val],
		),
	)
}

# CIS-CTL-5.7-DF.01: No SSH daemon installation
deny contains msg if {
	is_dockerfile

	some i
	input[i].Cmd == "run"
	val := concat(" ", input[i].Value)

	regex.match(
		`(?i)(openssh-server|dropbear|sshd)`,
		val,
	)

	msg := format_violation(
		"CIS-CTL-5.7-DF.01",
		sprintf(
			"Found potential SSH installation '%v'.",
			[val],
		),
	)
}

# CIS-CTL-5.7-DF.02: Port 22 not exposed
deny contains msg if {
	is_dockerfile

	some i
	input[i].Cmd == "expose"
	val := input[i].Value

	some j
	val[j] == "22"

	msg := format_violation(
		"CIS-CTL-5.7-DF.02",
		"Port 22 is exposed.",
	)
}

# CIS-CTL-5.28-DF.01: Explicit tag present
deny contains msg if {
	is_dockerfile

	some i
	input[i].Cmd == "from"
	val := input[i].Value[0]
	parts := split(val, ":")

	count(parts) == 1

	msg := format_violation(
		"CIS-CTL-5.28-DF.01",
		sprintf(
			"Image '%v' has no tag.",
			[val],
		),
	)
}

# CIS-CTL-5.28-DF.02: Tag is not 'latest'
deny contains msg if {
	is_dockerfile

	some i
	input[i].Cmd == "from"
	val := input[i].Value[0]
	parts := split(val, ":")

	count(parts) > 1
	parts[count(parts) - 1] == "latest"

	msg := format_violation(
		"CIS-CTL-5.28-DF.02",
		sprintf(
			"Image '%v' uses the 'latest' tag.",
			[val],
		),
	)
}

# ============================================================================
# Warn rules
# ============================================================================

# CIS-CTL-4.3.01: Minimal base image
warn contains msg if {
	is_dockerfile

	some i
	input[i].Cmd == "from"
	val := input[i].Value[0]

	regex.match(
		`(?i)^(ubuntu|debian|centos|fedora|python|node|golang)`,
		val,
	)
	not regex.match(
		`(?i)(alpine|slim|distroless|scratch)`,
		val,
	)

	msg := format_violation(
		"CIS-CTL-4.3.01",
		sprintf(
			"Base image '%v' is not a minimal variant.",
			[val],
		),
	)
}

# CIS-CTL-4.8.01: SUID/SGID bit removal
warn contains msg if {
	is_dockerfile

	runs := [r |
		some i
		input[i].Cmd == "run"
		r := concat(" ", input[i].Value)
	]

	found_hardening := count([r |
		some r in runs
		regex.match(`(?i)\bchmod\b.*\-s\b`, r)
	]) > 0

	not found_hardening

	msg := format_violation(
		"CIS-CTL-4.8.01",
		"No instruction found removing SUID/SGID bits.",
	)
}

# ============================================================================
# Helpers (Internal)
# ============================================================================

env_key(val) := split(val[0], "=")[0] if {
	is_array(val)
	count(val) > 0
	is_string(val[0])
	contains(val[0], "=")
} else := val[0] if {
	is_array(val)
	count(val) > 0
	is_string(val[0])
	not contains(val[0], "=")
} else := sprintf("%v", [val[0]]) if {
	is_array(val)
	count(val) > 1
} else := ""
