# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

package semconv_test

import data.semconv
import rego.v1

test_metric_brief_ends_with_period if {
	count(semconv.deny) == 0 with input as {"groups": [{
		"id": "metric.test",
		"type": "metric",
		"brief": "This is a valid metric brief.",
		"stability": "development",
	}]}

	count(semconv.deny) == 0 with input as {"groups": [{
		"id": "metric.test2",
		"type": "metric",
		"brief": "This is a valid metric brief.   ",
		"stability": "development",
	}]}
}

test_metric_brief_without_period if {
	count(semconv.deny) > 0 with input as {"groups": [{
		"id": "metric.test",
		"type": "metric",
		"brief": "This metric brief is missing a period",
		"stability": "development",
	}]}

	count(semconv.deny) > 0 with input as {"groups": [{
		"id": "metric.test2",
		"type": "metric",
		"brief": "This metric brief is missing a period   ",
		"stability": "development",
	}]}
}

test_non_metric_groups_ignored if {
	count(semconv.deny) == 0 with input as {"groups": [
		{
			"id": "span.test",
			"type": "span",
			"brief": "No period",
			"stability": "development",
		},
		{
			"id": "event.test",
			"type": "event",
			"brief": "No period",
			"stability": "development",
		},
		{
			"id": "registry.attribute_test",
			"type": "attribute_group",
			"brief": "No period",
		},
	]}
}
