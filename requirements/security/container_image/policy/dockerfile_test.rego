# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

package main

import rego.v1

# ============================================================================
# Mock Data — keyed by Gemara L2 AR IDs
# ============================================================================
mock_cis_docker_controls := {"controls": {
	"CIS-CTL-4.1.01": {"title": "Non-root container user", "remediation": "Add USER instruction"},
	"CIS-CTL-4.1.02": {"title": "Non-root container user", "remediation": "Change USER to non-root"},
	"CIS-CTL-4.3.01": {"title": "Minimal base image", "remediation": "Use Alpine/slim/distroless"},
	"CIS-CTL-4.6.01": {"title": "Dockerfile HEALTHCHECK", "remediation": "Add HEALTHCHECK instruction"},
	"CIS-CTL-4.7.01": {"title": "No standalone update", "remediation": "Combine update with install"},
	"CIS-CTL-4.8.01": {"title": "SUID/SGID bit removal", "remediation": "Remove SUID/SGID bits"},
	"CIS-CTL-4.9.01": {"title": "COPY instead of ADD", "remediation": "Replace ADD with COPY"},
	"CIS-CTL-4.10.01": {"title": "No secrets in Dockerfiles", "remediation": "Use secrets manager"},
	"CIS-CTL-4.11.01": {"title": "No unverified packages", "remediation": "Avoid curl|sh"},
	"CIS-CTL-5.7-DF.01": {"title": "No SSH in Dockerfiles", "remediation": "Do not install SSH"},
	"CIS-CTL-5.7-DF.02": {"title": "No SSH in Dockerfiles", "remediation": "Do not expose port 22"},
	"CIS-CTL-5.28-DF.01": {"title": "Specific image version tags", "remediation": "Add explicit tag"},
	"CIS-CTL-5.28-DF.02": {"title": "Specific image version tags", "remediation": "Do not use latest"},
}}

# ============================================================================
# CIS-CTL-4.1: Non-root container user
# ============================================================================

# CIS-CTL-4.1.01: USER instruction present
test_cis_ctl_4_1_01_no_user_denied if {
	res := deny with input as [{"Cmd": "from", "Value": ["alpine:3.20"]}]
		with data.cis_docker_controls as mock_cis_docker_controls

	some msg in res
	contains(msg, "CIS-CTL-4.1.01")
	contains(msg, "No USER instruction found")
}

test_cis_ctl_4_1_01_user_present_allowed if {
	res := deny with input as [
		{"Cmd": "from", "Value": ["alpine:3.20"]},
		{"Cmd": "user", "Value": ["appuser"]},
	]
		with data.cis_docker_controls as mock_cis_docker_controls

	count({m | some m in res; contains(m, "CIS-CTL-4.1.01")}) == 0
}

# CIS-CTL-4.1.02: Last USER is not root
test_cis_ctl_4_1_02_root_user_denied if {
	res := deny with input as [
		{"Cmd": "user", "Value": ["appuser"]},
		{"Cmd": "user", "Value": ["root"]},
	]
		with data.cis_docker_controls as mock_cis_docker_controls

	some msg in res
	contains(msg, "CIS-CTL-4.1.02")
	contains(msg, "Last USER is 'root'")
}

test_cis_ctl_4_1_02_nonroot_last_allowed if {
	res := deny with input as [
		{"Cmd": "user", "Value": ["root"]},
		{"Cmd": "user", "Value": ["appuser"]},
	]
		with data.cis_docker_controls as mock_cis_docker_controls

	count({m | some m in res; contains(m, "CIS-CTL-4.1.02")}) == 0
}

# ============================================================================
# CIS-CTL-4.3: Minimal base image
# ============================================================================

test_cis_ctl_4_3_01_bloated_image_warns if {
	res := warn with input as [{"Cmd": "from", "Value": ["ubuntu:20.04"]}]
		with data.cis_docker_controls as mock_cis_docker_controls

	some msg in res
	contains(msg, "CIS-CTL-4.3.01")
}

test_cis_ctl_4_3_01_minimal_image_allowed if {
	res := warn with input as [{"Cmd": "from", "Value": ["alpine:3.20"]}]
		with data.cis_docker_controls as mock_cis_docker_controls

	count({m | some m in res; contains(m, "CIS-CTL-4.3.01")}) == 0
}

# ============================================================================
# CIS-CTL-4.6: Dockerfile HEALTHCHECK
# ============================================================================

test_cis_ctl_4_6_01_no_healthcheck_denied if {
	res := deny with input as [{"Cmd": "from", "Value": ["alpine:3.20"]}]
		with data.cis_docker_controls as mock_cis_docker_controls

	some msg in res
	contains(msg, "CIS-CTL-4.6.01")
	contains(msg, "No HEALTHCHECK instruction found")
}

test_cis_ctl_4_6_01_healthcheck_present_allowed if {
	res := deny with input as [
		{"Cmd": "from", "Value": ["alpine:3.20"]},
		{"Cmd": "healthcheck", "Value": ["CMD", "curl", "-f", "localhost"]},
	]
		with data.cis_docker_controls as mock_cis_docker_controls

	count({m | some m in res; contains(m, "CIS-CTL-4.6.01")}) == 0
}

# ============================================================================
# CIS-CTL-4.7: No standalone update instructions
# ============================================================================

test_cis_ctl_4_7_01_update_alone_denied if {
	res := deny with input as [{"Cmd": "run", "Value": ["apt-get", "update"]}]
		with data.cis_docker_controls as mock_cis_docker_controls

	some msg in res
	contains(msg, "CIS-CTL-4.7.01")
}

test_cis_ctl_4_7_01_update_and_install_allowed if {
	res := deny with input as [{"Cmd": "run", "Value": ["apt-get", "update", "&&", "apt-get", "install", "-y", "vim"]}]
		with data.cis_docker_controls as mock_cis_docker_controls

	count({m | some m in res; contains(m, "CIS-CTL-4.7.01")}) == 0
}

# ============================================================================
# CIS-CTL-4.8: SUID/SGID bit removal
# ============================================================================

test_cis_ctl_4_8_01_no_hardening_warns if {
	res := warn with input as [{"Cmd": "run", "Value": ["echo", "hello"]}]
		with data.cis_docker_controls as mock_cis_docker_controls

	some msg in res
	contains(msg, "CIS-CTL-4.8.01")
}

test_cis_ctl_4_8_01_hardening_present_allowed if {
	res := warn with input as [{"Cmd": "run", "Value": ["chmod", "-s", "/usr/bin/passwd"]}]
		with data.cis_docker_controls as mock_cis_docker_controls

	count({m | some m in res; contains(m, "CIS-CTL-4.8.01")}) == 0
}

# ============================================================================
# CIS-CTL-4.9: COPY instead of ADD
# ============================================================================

test_cis_ctl_4_9_01_add_denied if {
	res := deny with input as [{"Cmd": "add", "Value": ["src", "/dest"]}]
		with data.cis_docker_controls as mock_cis_docker_controls

	some msg in res
	contains(msg, "CIS-CTL-4.9.01")
	contains(msg, "ADD instruction found")
}

test_cis_ctl_4_9_01_copy_allowed if {
	res := deny with input as [{"Cmd": "copy", "Value": ["src", "/dest"]}]
		with data.cis_docker_controls as mock_cis_docker_controls

	count({m | some m in res; contains(m, "CIS-CTL-4.9.01")}) == 0
}

# ============================================================================
# CIS-CTL-4.10: No secrets in Dockerfiles
# ============================================================================

test_cis_ctl_4_10_01_secret_pair_syntax_denied if {
	res := deny with input as [{"Cmd": "env", "Value": ["MY_PASSWORD", "secret123"]}]
		with data.cis_docker_controls as mock_cis_docker_controls

	some msg in res
	contains(msg, "CIS-CTL-4.10.01")
}

test_cis_ctl_4_10_01_secret_equals_syntax_denied if {
	res := deny with input as [{"Cmd": "env", "Value": ["MY_PASSWORD=secret123"]}]
		with data.cis_docker_controls as mock_cis_docker_controls

	some msg in res
	contains(msg, "CIS-CTL-4.10.01")
}

# ============================================================================
# CIS-CTL-4.11: No unverified package installation
# ============================================================================

test_cis_ctl_4_11_01_pipe_to_shell_denied if {
	res := deny with input as [{"Cmd": "run", "Value": ["curl", "https://example.invalid", "|", "sh"]}]
		with data.cis_docker_controls as mock_cis_docker_controls

	some msg in res
	contains(msg, "CIS-CTL-4.11.01")
	contains(msg, "Insecure pipe to shell")
}

# ============================================================================
# CIS-CTL-5.7-DF: No SSH in Dockerfiles
# ============================================================================

# CIS-CTL-5.7-DF.01: No SSH daemon installation
test_cis_ctl_5_7_df_01_ssh_install_denied if {
	res := deny with input as [{"Cmd": "run", "Value": ["apt-get", "install", "openssh-server"]}]
		with data.cis_docker_controls as mock_cis_docker_controls

	some msg in res
	contains(msg, "CIS-CTL-5.7-DF.01")
	contains(msg, "Found potential SSH installation")
}

# CIS-CTL-5.7-DF.02: Port 22 not exposed
test_cis_ctl_5_7_df_02_port_22_denied if {
	res := deny with input as [{"Cmd": "expose", "Value": ["22"]}]
		with data.cis_docker_controls as mock_cis_docker_controls

	some msg in res
	contains(msg, "CIS-CTL-5.7-DF.02")
	contains(msg, "Port 22 is exposed")
}

# ============================================================================
# CIS-CTL-5.28-DF: Specific image version tags
# ============================================================================

# CIS-CTL-5.28-DF.01: Tag present
test_cis_ctl_5_28_df_01_no_tag_denied if {
	res := deny with input as [{"Cmd": "from", "Value": ["node"]}]
		with data.cis_docker_controls as mock_cis_docker_controls

	some msg in res
	contains(msg, "CIS-CTL-5.28-DF.01")
	contains(msg, "has no tag")
}

# CIS-CTL-5.28-DF.02: Tag is not 'latest'
test_cis_ctl_5_28_df_02_latest_tag_denied if {
	res := deny with input as [{"Cmd": "from", "Value": ["node:latest"]}]
		with data.cis_docker_controls as mock_cis_docker_controls

	some msg in res
	contains(msg, "CIS-CTL-5.28-DF.02")
	contains(msg, "uses the 'latest' tag")
}

test_cis_ctl_5_28_df_specific_tag_allowed if {
	res := deny with input as [{"Cmd": "from", "Value": ["node:14.17.0-alpine"]}]
		with data.cis_docker_controls as mock_cis_docker_controls

	count({m |
		some m in res
		contains(m, "CIS-CTL-5.28-DF")
	}) == 0
}
