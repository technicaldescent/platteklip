# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

package main

import rego.v1

# ============================================================================
# Mock Data — keyed by Gemara L2 AR IDs
# ============================================================================
mock_cis_docker_controls := {"controls": {
	"CIS-CTL-5.5.01": {"title": "No privileged containers", "remediation": "Set privileged: false"},
	"CIS-CTL-5.6.01": {"title": "No sensitive host directory mounts", "remediation": "Do not mount host paths"},
	"CIS-CTL-5.10.01": {"title": "No host network namespace sharing", "remediation": "Use bridge network"},
	"CIS-CTL-5.11.01": {"title": "Container memory limits", "remediation": "Set deploy.resources.limits.memory"},
	"CIS-CTL-5.12.01": {"title": "Container CPU limits", "remediation": "Set deploy.resources.limits.cpus"},
	"CIS-CTL-5.13.01": {"title": "Read-only root filesystem", "remediation": "Set read_only: true"},
	"CIS-CTL-5.14.01": {"title": "Specific host interface binding", "remediation": "Bind to specific IP"},
	"CIS-CTL-5.16.01": {"title": "No host PID namespace sharing", "remediation": "Do not use pid: host"},
	"CIS-CTL-5.17.01": {"title": "No host IPC namespace sharing", "remediation": "Do not use ipc: host"},
	"CIS-CTL-5.21.01": {"title": "No host UTS namespace sharing", "remediation": "Do not use uts: host"},
	"CIS-CTL-5.26.01": {"title": "No new privileges restriction", "remediation": "Set no-new-privileges"},
	"CIS-CTL-5.27.01": {"title": "Runtime health check", "remediation": "Add healthcheck"},
	"CIS-CTL-5.29.01": {"title": "PID cgroup limits", "remediation": "Set pids limit"},
	"CIS-CTL-5.31.01": {"title": "No host user namespace sharing", "remediation": "Do not use userns_mode: host"},
	"CIS-CTL-5.32.01": {"title": "No Docker socket mount", "remediation": "Do not mount docker.sock"},
}}

# ============================================================================
# Deterministic exemption behaviour for unit tests
# ============================================================================
is_read_only_exempt(name) if false
is_host_network_exempt(name) if false
is_public_port_exempt(name) if false

# ============================================================================
# CIS-CTL-5.5: No privileged containers
# ============================================================================

test_cis_ctl_5_5_01_privileged_denied if {
	res := deny with input as {"services": {"web": {"privileged": true}}}
		with data.cis_docker_controls as mock_cis_docker_controls

	some msg in res
	contains(msg, "CIS-CTL-5.5.01")
	contains(msg, "configured as privileged")
}

test_cis_ctl_5_5_01_unprivileged_allowed if {
	res := deny with input as {"services": {"web": {"privileged": false}}}
		with data.cis_docker_controls as mock_cis_docker_controls

	count({m | some m in res; contains(m, "CIS-CTL-5.5.01")}) == 0
}

# ============================================================================
# CIS-CTL-5.6: No sensitive host directory mounts
# ============================================================================

test_cis_ctl_5_6_01_sensitive_mount_string_denied if {
	res := deny with input as {"services": {"db": {"volumes": ["/etc:/rootfs/etc:ro"]}}}
		with data.cis_docker_controls as mock_cis_docker_controls

	some msg in res
	contains(msg, "CIS-CTL-5.6.01")
	contains(msg, "mounts sensitive host path '/etc'")
}

test_cis_ctl_5_6_01_sensitive_mount_object_denied if {
	res := deny with input as {"services": {"db": {"volumes": [{"source": "/etc", "target": "/host/etc"}]}}}
		with data.cis_docker_controls as mock_cis_docker_controls

	some msg in res
	contains(msg, "CIS-CTL-5.6.01")
	contains(msg, "mounts sensitive host path '/etc'")
}

test_cis_ctl_5_6_01_safe_mount_allowed if {
	res := deny with input as {"services": {"db": {"volumes": ["./data:/var/lib/mysql"]}}}
		with data.cis_docker_controls as mock_cis_docker_controls

	count({m | some m in res; contains(m, "CIS-CTL-5.6.01")}) == 0
}

test_cis_ctl_5_6_01_container_only_mount_allowed if {
	res := deny with input as {"services": {"db": {"volumes": ["/var/lib/mysql"]}}}
		with data.cis_docker_controls as mock_cis_docker_controls

	count({m | some m in res; contains(m, "CIS-CTL-5.6.01")}) == 0
}

# ============================================================================
# CIS-CTL-5.10: No host network namespace sharing
# ============================================================================

test_cis_ctl_5_10_01_host_net_denied if {
	res := deny with input as {"services": {"proxy": {"network_mode": "host"}}}
		with data.cis_docker_controls as mock_cis_docker_controls

	some msg in res
	contains(msg, "CIS-CTL-5.10.01")
}

# ============================================================================
# CIS-CTL-5.11, 5.12, 5.29: Resource limits
# ============================================================================

test_cis_ctl_resource_limits_missing_denied if {
	res := deny with input as {"services": {"app": {"image": "nginx"}}}
		with data.cis_docker_controls as mock_cis_docker_controls

	some m1 in res
	contains(m1, "CIS-CTL-5.11.01")
	some m2 in res
	contains(m2, "CIS-CTL-5.12.01")
	some m3 in res
	contains(m3, "CIS-CTL-5.29.01")
}

test_cis_ctl_resource_limits_set_allowed if {
	res := deny with input as {"services": {"app": {"deploy": {"resources": {"limits": {
		"cpus": "0.5",
		"memory": "512M",
		"pids": 100,
	}}}}}}
		with data.cis_docker_controls as mock_cis_docker_controls

	count({m | some m in res; contains(m, "CIS-CTL-5.11.01")}) == 0
	count({m | some m in res; contains(m, "CIS-CTL-5.12.01")}) == 0
	count({m | some m in res; contains(m, "CIS-CTL-5.29.01")}) == 0
}

# ============================================================================
# CIS-CTL-5.13: Read-only root filesystem
# ============================================================================

test_cis_ctl_5_13_01_writable_root_denied if {
	res := deny with input as {"services": {"web": {"read_only": false}}}
		with data.cis_docker_controls as mock_cis_docker_controls

	some msg in res
	contains(msg, "CIS-CTL-5.13.01")
}

test_cis_ctl_5_13_01_readonly_root_allowed if {
	res := deny with input as {"services": {"web": {"read_only": true}}}
		with data.cis_docker_controls as mock_cis_docker_controls

	count({m | some m in res; contains(m, "CIS-CTL-5.13.01")}) == 0
}

# ============================================================================
# CIS-CTL-5.14: Specific host interface binding (warn)
# ============================================================================

test_cis_ctl_5_14_01_all_interfaces_warns if {
	res := warn with input as {"services": {"web": {"ports": ["80:80"]}}}
		with data.cis_docker_controls as mock_cis_docker_controls

	some msg in res
	contains(msg, "CIS-CTL-5.14.01")
	contains(msg, "binds port '80:80' to all interfaces")
}

test_cis_ctl_5_14_01_specific_interface_allowed if {
	res := warn with input as {"services": {"web": {"ports": ["127.0.0.1:80:80"]}}}
		with data.cis_docker_controls as mock_cis_docker_controls

	count(res) == 0
}

# ============================================================================
# CIS-CTL-5.16, 5.17, 5.21, 5.31: Host namespaces
# ============================================================================

test_cis_ctl_host_namespaces_denied if {
	res := deny with input as {"services": {"bad_service": {
		"pid": "host",
		"ipc": "host",
		"uts": "host",
		"userns_mode": "host",
	}}}
		with data.cis_docker_controls as mock_cis_docker_controls

	some m1 in res
	contains(m1, "CIS-CTL-5.16.01")
	some m2 in res
	contains(m2, "CIS-CTL-5.17.01")
	some m3 in res
	contains(m3, "CIS-CTL-5.21.01")
	some m4 in res
	contains(m4, "CIS-CTL-5.31.01")
}

# ============================================================================
# CIS-CTL-5.26: No new privileges
# ============================================================================

test_cis_ctl_5_26_01_missing_denied if {
	res := deny with input as {"services": {"web": {"image": "nginx"}}}
		with data.cis_docker_controls as mock_cis_docker_controls

	some msg in res
	contains(msg, "CIS-CTL-5.26.01")
}

test_cis_ctl_5_26_01_configured_allowed if {
	res := deny with input as {"services": {"web": {"security_opt": ["no-new-privileges:true"]}}}
		with data.cis_docker_controls as mock_cis_docker_controls

	count({m | some m in res; contains(m, "CIS-CTL-5.26.01")}) == 0
}

# ============================================================================
# CIS-CTL-5.27: Runtime health check
# ============================================================================

test_cis_ctl_5_27_01_missing_denied if {
	res := deny with input as {"services": {"web": {"image": "nginx"}}}
		with data.cis_docker_controls as mock_cis_docker_controls

	some msg in res
	contains(msg, "CIS-CTL-5.27.01")
}

test_cis_ctl_5_27_01_present_allowed if {
	res := deny with input as {"services": {"web": {"healthcheck": {"test": ["CMD", "curl", "localhost"]}}}}
		with data.cis_docker_controls as mock_cis_docker_controls

	count({m | some m in res; contains(m, "CIS-CTL-5.27.01")}) == 0
}

# ============================================================================
# CIS-CTL-5.32: No Docker socket mount
# ============================================================================

test_cis_ctl_5_32_01_socket_mount_denied if {
	res := deny with input as {"services": {"monitor": {"volumes": ["/var/run/docker.sock:/var/run/docker.sock"]}}}
		with data.cis_docker_controls as mock_cis_docker_controls

	some msg in res
	contains(msg, "CIS-CTL-5.32.01")
	contains(msg, "mounts the Docker socket")
}

test_cis_ctl_5_32_01_no_socket_allowed if {
	res := deny with input as {"services": {"web": {"volumes": ["./app:/app"]}}}
		with data.cis_docker_controls as mock_cis_docker_controls

	count({m | some m in res; contains(m, "CIS-CTL-5.32.01")}) == 0
}
