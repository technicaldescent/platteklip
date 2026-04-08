# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

package semconv_test

import data.semconv
import rego.v1

test_fails_on_stable_group_with_experimental_attribute if {
	count(semconv.deny) >= 1 with input as {"groups": [{
		"id": "metric.foo",
		"type": "metric",
		"metric_name": "foo",
		"stability": "stable",
		"brief": "brief.",
		"attributes": [{
			"name": "test.experimental",
			"stability": "experimental",
			"brief": "brief.",
		}],
	}]}
}

test_fails_on_stable_group_with_deprecated_attribute if {
	count(semconv.deny) >= 1 with input as {"groups": [{
		"id": "metric.foo",
		"type": "metric",
		"metric_name": "foo",
		"stability": "stable",
		"brief": "brief.",
		"attributes": [{
			"name": "test.deprecated",
			"stability": "stable",
			"brief": "brief.",
			"deprecated": "true",
		}],
	}]}
}

test_pass_on_stable_group_with_stable_attribute if {
	count(semconv.deny) == 0 with input as {"groups": [{
		"id": "metric.foo",
		"type": "metric",
		"metric_name": "foo",
		"stability": "stable",
		"brief": "brief.",
		"attributes": [{
			"name": "test.stable",
			"stability": "stable",
			"brief": "brief.",
		}],
	}]}
}
