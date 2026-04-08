# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

package semconv_test

import rego.v1

import data.semconv

test_fails_on_const_name_collision if {
	collision := {"groups": [
		{"id": "test1", "attributes": [{
			"name": "foo.bar.baz",
			"stability": "development",
			"brief": "brief.",
		}]},
		{"id": "test2", "attributes": [{
			"name": "foo.bar_baz",
			"stability": "development",
			"brief": "brief.",
		}]},
	]}
	denies := semconv.deny with input as collision
	count(denies) == 2
}

test_fails_on_namespace_collision if {
	collision := {"groups": [
		{"id": "test1", "attributes": [{
			"name": "foo.bar.baz",
			"stability": "development",
			"brief": "brief.",
		}]},
		{"id": "test2", "attributes": [{
			"name": "foo.bar",
			"stability": "development",
			"brief": "brief.",
		}]},
	]}
	denies := semconv.deny with input as collision
	count(denies) == 1
}

test_does_not_fail_on_deprecated_namespace_collision if {
	collision := {"groups": [
		{"id": "test1", "attributes": [{
			"name": "test.namespace.id",
			"stability": "development",
			"brief": "brief.",
		}]},
		{"id": "test2", "attributes": [{
			"name": "test.namespace",
			"stability": "development",
			"brief": "brief.",
			"deprecated": {"reason": "obsoleted"},
		}]},
		{"id": "test3", "attributes": [{
			"name": "another_test.namespace.id",
			"stability": "development",
			"brief": "brief.",
			"deprecated": {
				"reason": "renamed",
				"renamed_to": "another_test.namespace",
			},
		}]},
		{"id": "test4", "attributes": [{
			"name": "another_test.namespace",
			"stability": "development",
			"brief": "brief.",
		}]},
	]}
	denies := semconv.deny with input as collision
	count(denies) == 0
}

test_does_not_fail_on_excluded_name_collision if {
	collision := {"groups": [
		{"id": "test1", "attributes": [
			{
				"name": "test1.namespace.id",
				"stability": "development",
				"brief": "brief.",
			},
			{
				"name": "test1.namespace_id",
				"stability": "development",
				"brief": "brief.",
				"annotations": {"code_generation": {"exclude": true}},
			},
		]},
		{"id": "test2", "attributes": [
			{
				"name": "test2.namespace_id",
				"stability": "development",
				"brief": "brief.",
			},
			{
				"name": "test2.namespace.id",
				"stability": "development",
				"brief": "brief.",
				"annotations": {"code_generation": {"exclude": true}},
			},
		]},
	]}
	denies := semconv.deny with input as collision
	count(denies) == 0
}
