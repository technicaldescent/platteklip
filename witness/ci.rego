# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

# witness/ci.rego — attestation policy for the
# platteklip CI pipeline.
#
# Evaluated by ``witness verify`` against each step's
# in-toto attestation envelope.  The input is the
# decoded predicate from the DSSE envelope.
#
# deny rules produce a set of violation strings.
# An empty set means the step passes.

package platteklip.ci

import rego.v1

# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------

_attestation(typ) := att if {
	some att in input.predicate.attestations
	att.type == typ
}

_git := _attestation("https://witness.dev/attestations/git/v0.1").attestation

_cmd := _attestation("https://witness.dev/attestations/command-run/v0.1").attestation

_env := _attestation("https://witness.dev/attestations/environment/v0.1").attestation

# ---------------------------------------------------------
# Identity: signed commits from a known committer
# ---------------------------------------------------------

deny contains msg if {
	_git.signature == ""
	msg := "git commit is not signed"
}

deny contains msg if {
	_git.committeremail != "raymond.ellis@gmail.com"
	msg := sprintf(
		"unexpected committer: %s",
		[_git.committeremail],
	)
}

# ---------------------------------------------------------
# Execution: every step must exit cleanly
# ---------------------------------------------------------

deny contains msg if {
	_cmd.exitcode != 0
	msg := sprintf(
		"command exited with code %d",
		[_cmd.exitcode],
	)
}

# ---------------------------------------------------------
# Step-specific output verification
# ---------------------------------------------------------

deny contains msg if {
	input.predicate.name == "test-unit"
	not contains(_cmd.stdout, "passed")
	msg := "test-unit stdout does not contain 'passed'"
}

deny contains msg if {
	input.predicate.name == "quality"
	not contains(
		_cmd.stdout,
		"No issues identified",
	)
	msg := "quality: bandit did not report clean results"
}

deny contains msg if {
	input.predicate.name == "acceptance"
	contains(_cmd.stdout, "Failing scenarios")
	msg := "acceptance: behave reported failing scenarios"
}

deny contains msg if {
	input.predicate.name == "acceptance"
	contains(_cmd.stdout, "Errored scenarios")
	msg := "acceptance: behave reported errored scenarios"
}
