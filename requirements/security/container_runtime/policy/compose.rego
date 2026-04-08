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

# ============================================================================
# File Type Guard: Docker Compose
# ============================================================================

is_compose_file if {
	is_object(input)
	input.services
}

# ============================================================================
# Section 5: Container Runtime Configuration
# ============================================================================

deny contains msg if {
	is_compose_file
	some name, service in input.services
	service.privileged == true
	msg := format_violation(
		"CIS-CTL-5.5.01",
		sprintf("Service '%v' is configured as privileged.", [name]),
	)
}

deny contains msg if {
	is_compose_file
	some name, service in input.services
	sensitive_paths := ["/boot", "/dev", "/etc", "/lib", "/proc", "/sys", "/usr"]
	some volume in object.get(service, "volumes", [])
	src := volume_source(volume)
	startswith(src, "/")
	some path in sensitive_paths
	startswith(src, path)
	msg := format_violation(
		"CIS-CTL-5.6.01",
		sprintf("Service '%v' mounts sensitive host path '%v'.", [name, src]),
	)
}

deny contains msg if {
	is_compose_file
	some name, service in input.services
	service.network_mode == "host"
	not is_host_network_exempt(name)
	msg := format_violation(
		"CIS-CTL-5.10.01",
		sprintf("Service '%v' shares the host network namespace.", [name]),
	)
}

deny contains msg if {
	is_compose_file
	some name, service in input.services
	mem := object.get(
		object.get(object.get(object.get(service, "deploy", {}), "resources", {}), "limits", {}),
		"memory", null,
	)
	mem == null
	msg := format_violation(
		"CIS-CTL-5.11.01",
		sprintf("Service '%v' does not have a memory limit set.", [name]),
	)
}

deny contains msg if {
	is_compose_file
	some name, service in input.services
	cpus := object.get(
		object.get(object.get(object.get(service, "deploy", {}), "resources", {}), "limits", {}),
		"cpus", null,
	)
	cpus == null
	msg := format_violation(
		"CIS-CTL-5.12.01",
		sprintf("Service '%v' does not have a CPU limit set.", [name]),
	)
}

deny contains msg if {
	is_compose_file
	some name, service in input.services
	not is_read_only_exempt(name)
	object.get(service, "read_only", false) == false
	msg := format_violation(
		"CIS-CTL-5.13.01",
		sprintf("Service '%v' does not have a read-only root filesystem.", [name]),
	)
}

deny contains msg if {
	is_compose_file
	some name, service in input.services
	service.pid == "host"
	msg := format_violation(
		"CIS-CTL-5.16.01",
		sprintf("Service '%v' shares the host PID namespace.", [name]),
	)
}

deny contains msg if {
	is_compose_file
	some name, service in input.services
	service.ipc == "host"
	msg := format_violation(
		"CIS-CTL-5.17.01",
		sprintf("Service '%v' shares the host IPC namespace.", [name]),
	)
}

deny contains msg if {
	is_compose_file
	some name, service in input.services
	service.uts == "host"
	msg := format_violation(
		"CIS-CTL-5.21.01",
		sprintf("Service '%v' shares the host UTS namespace.", [name]),
	)
}

deny contains msg if {
	is_compose_file
	some name, service in input.services
	opts := object.get(service, "security_opt", [])
	not has_no_new_privileges(opts)
	msg := format_violation(
		"CIS-CTL-5.26.01",
		sprintf(
			"Service '%v' does not restrict acquiring new privileges (no-new-privileges).",
			[name],
		),
	)
}

deny contains msg if {
	is_compose_file
	some name, service in input.services
	hc := object.get(service, "healthcheck", null)
	hc == null
	msg := format_violation(
		"CIS-CTL-5.27.01",
		sprintf("Service '%v' is missing a 'healthcheck' configuration.", [name]),
	)
}

deny contains msg if {
	is_compose_file
	some name, service in input.services
	pids := object.get(
		object.get(object.get(object.get(service, "deploy", {}), "resources", {}), "limits", {}),
		"pids", null,
	)
	pids == null
	msg := format_violation(
		"CIS-CTL-5.29.01",
		sprintf("Service '%v' does not have a PIDs limit set.", [name]),
	)
}

deny contains msg if {
	is_compose_file
	some name, service in input.services
	service.userns_mode == "host"
	msg := format_violation(
		"CIS-CTL-5.31.01",
		sprintf("Service '%v' shares the host user namespace.", [name]),
	)
}

deny contains msg if {
	is_compose_file
	some name, service in input.services
	some volume in object.get(service, "volumes", [])
	src := volume_source(volume)
	contains(src, "docker.sock")
	msg := format_violation(
		"CIS-CTL-5.32.01",
		sprintf("Service '%v' mounts the Docker socket (%v).", [name, src]),
	)
}

# ============================================================================
# Warnings
# ============================================================================

warn contains msg if {
	is_compose_file
	some name, service in input.services
	not is_public_port_exempt(name)
	some port_def in object.get(service, "ports", [])
	regex.match(`^[0-9]+:`, port_def)
	msg := format_violation(
		"CIS-CTL-5.14.01",
		sprintf(
			"Service '%v' binds port '%v' to all interfaces (0.0.0.0).",
			[name, port_def],
		),
	)
}

# ============================================================================
# Helpers (Internal)
# ============================================================================

volume_source(vol) := src if {
	is_string(vol)
	parts := split(vol, ":")
	count(parts) >= 2
	src := parts[0]
} else := src if {
	is_string(vol)
	parts := split(vol, ":")
	count(parts) < 2
	src := ""
}

volume_source(vol) := src if {
	is_object(vol)
	src := vol.source
}

has_no_new_privileges(opts) if {
	some opt in opts
	contains(opt, "no-new-privileges")
}

# ============================================================================
# Fallback Mocks (Safe Defaults)
# ============================================================================

is_read_only_exempt(name) if false

is_host_network_exempt(name) if false

is_public_port_exempt(name) if false
