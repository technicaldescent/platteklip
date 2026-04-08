# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

package semconv_test

import rego.v1

import data.semconv

test_fails_on_complex_attribute if {
	attribute_types := ["any", "template[any]"]
	group_types := ["entity", "resource", "metric"]

	every attribute_type in attribute_types {
		every group_type in group_types {
			input_obj := {"groups": [{
				"id": concat(".", [group_type, "attr"]),
				"type": group_type,
				"stability": "development",
				"brief": "brief.",
				"attributes": [{
					"name": "test.any",
					"stability": "development",
					"type": attribute_type,
					"brief": "brief.",
				}],
			}]}

			denies := semconv.deny with input as input_obj
			count(denies) == 1
		}
	}
}

test_pass_on_complex_attribute if {
	attribute_types := ["any", "template[any]"]
	group_types := ["attribute_group", "event", "span"]

	every attribute_type in attribute_types {
		every group_type in group_types {
			input_obj := {"groups": [{
				"id": concat(".", [group_type, "attr"]),
				"type": group_type,
				"stability": "development",
				"brief": "brief.",
				"attributes": [{
					"name": "test.any",
					"stability": "development",
					"type": attribute_type,
					"brief": "brief.",
				}],
			}]}

			denies := semconv.deny with input as input_obj
			count(denies) == 0
		}
	}
}
