# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

package semconv_test

import data.semconv
import rego.v1

test_fails_on_namespace_collision if {
	collision := {"groups": [
		{
			"id": "metric.foo.bar",
			"type": "metric",
			"metric_name": "foo.bar",
			"stability": "development",
			"brief": "brief.",
		},
		{
			"id": "metric.foo.bar.baz",
			"type": "metric",
			"metric_name": "foo.bar.baz",
			"stability": "development",
			"brief": "brief.",
		},
	]}

	count(semconv.deny) == 1 with input as collision
}

test_does_not_fail_when_no_collision if {
	no_collision := {"groups": [
		{
			"id": "metric.foo.bar",
			"type": "metric",
			"metric_name": "foo.bar",
			"stability": "development",
			"brief": "brief.",
		},
		{
			"id": "metric.foo.baz",
			"type": "metric",
			"metric_name": "foo.baz",
			"stability": "development",
			"brief": "brief.",
		},
	]}

	count(semconv.deny) == 0 with input as no_collision
}

test_does_not_fail_on_deprecated_namespace_metric if {
	deprecated := {"groups": [
		{
			"id": "metric.foo.bar",
			"type": "metric",
			"metric_name": "foo.bar",
			"stability": "development",
			"brief": "brief.",
			"deprecated": {"reason": "obsoleted"},
		},
		{
			"id": "metric.foo.bar.baz",
			"type": "metric",
			"metric_name": "foo.bar.baz",
			"stability": "development",
			"brief": "brief.",
		},
	]}

	count(semconv.deny) == 0 with input as deprecated
}

test_does_not_fail_on_deprecated_colliding_metric if {
	deprecated := {"groups": [
		{
			"id": "metric.foo.bar",
			"type": "metric",
			"metric_name": "foo.bar",
			"stability": "development",
			"brief": "brief.",
		},
		{
			"id": "metric.foo.bar.baz",
			"type": "metric",
			"metric_name": "foo.bar.baz",
			"stability": "development",
			"brief": "brief.",
			"deprecated": {"reason": "obsoleted"},
		},
	]}

	count(semconv.deny) == 0 with input as deprecated
}

test_does_not_fail_on_both_deprecated if {
	deprecated := {"groups": [
		{
			"id": "metric.foo.bar",
			"type": "metric",
			"metric_name": "foo.bar",
			"stability": "development",
			"brief": "brief.",
			"deprecated": {"reason": "obsoleted"},
		},
		{
			"id": "metric.foo.bar.baz",
			"type": "metric",
			"metric_name": "foo.bar.baz",
			"stability": "development",
			"brief": "brief.",
			"deprecated": {"reason": "obsoleted"},
		},
	]}

	count(semconv.deny) == 0 with input as deprecated
}
