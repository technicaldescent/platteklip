# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

package semconv_test

import data.semconv
import rego.v1

###############################################################################
# Golden pass
###############################################################################

test_identical_schema_pass if {
	tc := {
		"old": {
			"metrics": [{
				"name": "m1",
				"instrument": "counter",
				"unit": "1",
				"stability": "stable",
				"attributes": [],
			}],
			"resources": [],
			"events": [],
			"attributes": [],
		},
		"new": {
			"metrics": [{
				"name": "m1",
				"instrument": "counter",
				"unit": "1",
				"stability": "stable",
				"attributes": [],
			}],
			"resources": [],
			"events": [],
			"attributes": [],
		},
	}

	results := semconv.deny with input as tc
	count(results) == 0
}

###############################################################################
# Metric rules
###############################################################################

test_removed_metric if {
	tc := {"old": {"metrics": [{"name": "m1"}]}, "new": {"metrics": []}}

	results := semconv.deny with input as tc
	some d in results
	d.type == "removed_metric"
}

test_metric_instrument_change if {
	tc := {
		"old": {"metrics": [{"name": "m1", "instrument": "counter"}]},
		"new": {"metrics": [{"name": "m1", "instrument": "gauge"}]},
	}

	results := semconv.deny with input as tc
	some d in results
	d.type == "metric_instrument_change"
}

test_metric_unit_change if {
	tc := {
		"old": {"metrics": [{"name": "m1", "unit": "s"}]},
		"new": {"metrics": [{"name": "m1", "unit": "ms"}]},
	}

	results := semconv.deny with input as tc
	some d in results
	d.type == "metric_unit_change"
}

test_metric_stability_change if {
	tc := {
		"old": {"metrics": [{"name": "m1", "stability": "stable"}]},
		"new": {"metrics": [{"name": "m1", "stability": "experimental"}]},
	}

	results := semconv.deny with input as tc
	some d in results
	d.type == "metric_stability_change"
}

test_metric_attribute_missing if {
	tc := {
		"old": {"metrics": [{
			"name": "m1",
			"attributes": [{"name": "a1", "stability": "stable"}],
		}]},
		"new": {"metrics": [{
			"name": "m1",
			"attributes": [],
		}]},
	}

	results := semconv.deny with input as tc
	some d in results
	d.type == "metric_attribute_missing"
}

test_metric_attribute_added if {
	tc := {
		"old": {"metrics": [{"name": "m1", "attributes": []}]},
		"new": {"metrics": [{
			"name": "m1",
			"attributes": [{"name": "a1", "stability": "stable"}],
		}]},
	}

	results := semconv.deny with input as tc
	some d in results
	d.type == "metric_attribute_added"
}

test_metric_attribute_added_unstable_allowed if {
	tc := {
		"old": {"metrics": [{"name": "m1", "attributes": []}]},
		"new": {"metrics": [{
			"name": "m1",
			"attributes": [{"name": "a1", "stability": "experimental"}],
		}]},
	}

	results := semconv.deny with input as tc
	count(results) == 0
}

###############################################################################
# Resource rules
###############################################################################

test_removed_resource if {
	tc := {"old": {"resources": [{"name": "r1"}]}, "new": {"resources": []}}

	results := semconv.deny with input as tc
	some d in results
	d.type == "removed_resource"
}

test_resource_stability_change if {
	tc := {
		"old": {"resources": [{"name": "r1", "stability": "stable"}]},
		"new": {"resources": [{"name": "r1", "stability": "experimental"}]},
	}

	results := semconv.deny with input as tc
	some d in results
	d.type == "resource_stability_change"
}

test_resource_attribute_missing if {
	tc := {
		"old": {"resources": [{
			"name": "r1",
			"attributes": [{"name": "a1", "stability": "stable"}],
		}]},
		"new": {"resources": [{
			"name": "r1",
			"attributes": [],
		}]},
	}

	results := semconv.deny with input as tc
	some d in results
	d.type == "resource_attribute_missing"
}

###############################################################################
# Event rules
###############################################################################

test_removed_event if {
	tc := {"old": {"events": [{"name": "e1"}]}, "new": {"events": []}}

	results := semconv.deny with input as tc
	some d in results
	d.type == "removed_event"
}

test_event_attribute_missing if {
	tc := {
		"old": {"events": [{
			"name": "e1",
			"attributes": [{"name": "a1", "stability": "stable"}],
		}]},
		"new": {"events": [{
			"name": "e1",
			"attributes": [],
		}]},
	}

	results := semconv.deny with input as tc
	some d in results
	d.type == "event_attribute_missing"
}

###############################################################################
# Attribute rules
###############################################################################

test_attribute_type_change if {
	tc := {
		"old": {"attributes": [{"name": "a1", "type": "string"}]},
		"new": {"attributes": [{"name": "a1", "type": "int"}]},
	}

	results := semconv.deny with input as tc
	some d in results
	d.type == "attribute_type_change"
}

test_attribute_stability_change if {
	tc := {
		"old": {"attributes": [{"name": "a1", "stability": "stable"}]},
		"new": {"attributes": [{"name": "a1", "stability": "experimental"}]},
	}

	results := semconv.deny with input as tc
	some d in results
	d.type == "attribute_stability_change"
}

test_attribute_enum_type_change if {
	tc := {
		"old": {"attributes": [{"name": "a1", "type": "enum"}]},
		"new": {"attributes": [{"name": "a1", "type": "string"}]},
	}

	results := semconv.deny with input as tc
	some d in results
	d.type == "attribute_enum_type_change"
}

test_attribute_enum_member_missing if {
	tc := {
		"old": {"attributes": [{
			"name": "a1",
			"type": "enum",
			"members": [{"name": "x", "value": 1}],
		}]},
		"new": {"attributes": [{
			"name": "a1",
			"type": "enum",
			"members": [],
		}]},
	}

	results := semconv.deny with input as tc
	some d in results
	d.type == "attribute_enum_member_missing"
}

test_attribute_enum_member_value_change if {
	tc := {
		"old": {"attributes": [{
			"name": "a1",
			"type": "enum",
			"members": [{"name": "x", "value": 1}],
		}]},
		"new": {"attributes": [{
			"name": "a1",
			"type": "enum",
			"members": [{"name": "x", "value": 2}],
		}]},
	}

	results := semconv.deny with input as tc
	some d in results
	d.type == "attribute_enum_member_value_change"
}

test_attribute_enum_member_stability_change if {
	tc := {
		"old": {"attributes": [{
			"name": "a1",
			"type": "enum",
			"members": [{"name": "x", "value": 1, "stability": "stable"}],
		}]},
		"new": {"attributes": [{
			"name": "a1",
			"type": "enum",
			"members": [{"name": "x", "value": 1, "stability": "experimental"}],
		}]},
	}

	results := semconv.deny with input as tc
	some d in results
	d.type == "attribute_enum_member_stability_change"
}

###############################################################################
# Aggregation test
###############################################################################

test_multiple_violations_count if {
	tc := {
		"old": {"metrics": [{
			"name": "m1",
			"instrument": "counter",
			"unit": "s",
		}]},
		"new": {"metrics": [{
			"name": "m1",
			"instrument": "gauge",
			"unit": "ms",
		}]},
	}

	results := semconv.deny with input as tc
	count(results) == 2
}
