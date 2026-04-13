# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

# witness/ci_test.rego — unit tests for CI
# attestation policy rules.

package platteklip.ci_test

import rego.v1

import data.platteklip.ci

# ---------------------------------------------------------
# Fixtures
# ---------------------------------------------------------

_base_git := {
	"commithash": "abc123",
	"signature": "-----BEGIN SSH SIGNATURE-----",
	"committeremail": "raymond.ellis@gmail.com",
	"authoremail": "raymond.ellis@gmail.com",
	"branch": "main",
	"status": {},
}

_base_cmd := {
	"cmd": ["dagger", "call", "test-unit", "--source=."],
	"exitcode": 0,
	"stdout": "306 passed in 9.75s",
	"stderr": "",
}

_base_env := {"os": "linux", "hostname": "builder"}

_attestations(name, git, cmd) := {"predicate": {
	"name": name,
	"attestations": [
		{
			"type": "https://witness.dev/attestations/git/v0.1",
			"attestation": git,
		},
		{
			"type": "https://witness.dev/attestations/command-run/v0.1",
			"attestation": cmd,
		},
		{
			"type": "https://witness.dev/attestations/environment/v0.1",
			"attestation": _base_env,
		},
	],
}}

# ---------------------------------------------------------
# Identity tests
# ---------------------------------------------------------

test_signed_commit_passes if {
	count(ci.deny) == 0 with input as _attestations(
		"test-unit",
		_base_git,
		_base_cmd,
	)
}

test_unsigned_commit_denied if {
	result := ci.deny with input as _attestations(
		"test-unit",
		object.union(_base_git, {"signature": ""}),
		_base_cmd,
	)
	some msg in result
	contains(msg, "not signed")
}

test_unknown_committer_denied if {
	result := ci.deny with input as _attestations(
		"test-unit",
		object.union(
			_base_git,
			{"committeremail": "attacker@example.com"},
		),
		_base_cmd,
	)
	some msg in result
	contains(msg, "unexpected committer")
}

# ---------------------------------------------------------
# Execution tests
# ---------------------------------------------------------

test_nonzero_exit_denied if {
	result := ci.deny with input as _attestations(
		"test-unit",
		_base_git,
		object.union(_base_cmd, {"exitcode": 1}),
	)
	some msg in result
	contains(msg, "exited with code")
}

# ---------------------------------------------------------
# Step-specific output tests
# ---------------------------------------------------------

test_unit_missing_passed_denied if {
	result := ci.deny with input as _attestations(
		"test-unit",
		_base_git,
		object.union(
			_base_cmd,
			{"stdout": "16 failed, 0 errors"},
		),
	)
	some msg in result
	contains(msg, "does not contain 'passed'")
}

test_unit_with_passed_allowed if {
	count(ci.deny) == 0 with input as _attestations(
		"test-unit",
		_base_git,
		object.union(
			_base_cmd,
			{"stdout": "306 passed in 9.75s"},
		),
	)
}

test_quality_clean_bandit_passes if {
	count(ci.deny) == 0 with input as _attestations(
		"quality",
		_base_git,
		object.union(
			_base_cmd,
			{"stdout": "No issues identified.\nAll done!"},
		),
	)
}

test_quality_dirty_bandit_denied if {
	result := ci.deny with input as _attestations(
		"quality",
		_base_git,
		object.union(
			_base_cmd,
			{"stdout": "Issue: [B108:hardcoded_tmp]"},
		),
	)
	some msg in result
	contains(msg, "bandit did not report clean")
}

test_acceptance_clean_passes if {
	count(ci.deny) == 0 with input as _attestations(
		"acceptance",
		_base_git,
		object.union(
			_base_cmd,
			{"stdout": "35 scenarios passed, 0 failed"},
		),
	)
}

test_acceptance_failures_denied if {
	result := ci.deny with input as _attestations(
		"acceptance",
		_base_git,
		object.union(
			_base_cmd,
			{"stdout": "Failing scenarios:\n  feature:25"},
		),
	)
	some msg in result
	contains(msg, "failing scenarios")
}

test_acceptance_errors_denied if {
	result := ci.deny with input as _attestations(
		"acceptance",
		_base_git,
		object.union(
			_base_cmd,
			{"stdout": "Errored scenarios:\n  feature:16"},
		),
	)
	some msg in result
	contains(msg, "errored scenarios")
}

# ---------------------------------------------------------
# Policy step: only exit code matters
# ---------------------------------------------------------

test_policy_clean_passes if {
	count(ci.deny) == 0 with input as _attestations(
		"policy",
		_base_git,
		object.union(
			_base_cmd,
			{"stdout": "PASS: 12/12"},
		),
	)
}

test_policy_failure_denied if {
	result := ci.deny with input as _attestations(
		"policy",
		_base_git,
		object.union(
			_base_cmd,
			{"exitcode": 1, "stdout": "FAIL: 1/12"},
		),
	)
	some msg in result
	contains(msg, "exited with code")
}
