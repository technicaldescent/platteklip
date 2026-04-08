# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

package semconv_test

import data.semconv
import rego.v1

test_fails_on_stable_entity_with_attributes_having_no_role if {
	# FIX: Changed 'deny' to 'semconv.deny'
	count(semconv.deny) >= 1 with input as {"groups": [{
		"id": "entity.foo",
		"type": "entity",
		"name": "foo",
		"stability": "stable",
		"brief": "brief.",
		"attributes": [
			{
				"name": "test.experimental",
				"stability": "stable",
				"brief": "brief.",
			},
			{
				"name": "test.id",
				"stability": "stable",
				"role": "identifying",
				"brief": "brief.",
			},
		],
	}]}
}

test_fails_on_stable_entity_with_attributes_having_no_id if {
	# FIX: Changed 'deny' to 'semconv.deny'
	count(semconv.deny) >= 1 with input as {"groups": [{
		"id": "entity.foo",
		"type": "entity",
		"name": "foo",
		"stability": "stable",
		"brief": "brief.",
		"attributes": [{
			"name": "test.experimental",
			"stability": "stable",
			"role": "descriptive",
			"brief": "brief.",
		}],
	}]}
}

test_passes_on_stable_entity_with_id if {
	# FIX: Changed 'deny' to 'semconv.deny'
	count(semconv.deny) == 0 with input as {"groups": [{
		"id": "entity.foo",
		"type": "entity",
		"name": "foo",
		"stability": "stable",
		"brief": "brief.",
		"attributes": [
			{
				"name": "test.experimental",
				"stability": "stable",
				"role": "descriptive",
				"brief": "brief.",
			},
			{
				"name": "test.id",
				"stability": "stable",
				"role": "identifying",
				"brief": "brief.",
			},
		],
	}]}
}
