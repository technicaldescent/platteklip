# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

package semconv_test

import data.semconv
import rego.v1

################################################################################
# Attribute renamed_to – invalid targets
################################################################################

test_fails_on_attribute_renamed_to_not_existing_attribute if {
	count(semconv.deny) >= 1 with input as {"groups": [{
		"id": "registry.deprecation.test",
		"type": "attribute_group",
		"attributes": [{
			"name": "test.me",
			"deprecated": {
				"reason": "renamed",
				"renamed_to": "does.not.exist",
			},
		}],
	}]}
}

test_fails_on_attribute_renamed_to_deprecated_attribute if {
	count(semconv.deny) >= 1 with input as {"groups": [{
		"id": "registry.deprecation.test",
		"type": "attribute_group",
		"attributes": [
			{
				"name": "test.old",
				"type": "string",
				"deprecated": {
					"reason": "renamed",
					"renamed_to": "test.new",
				},
			},
			{
				"name": "test.new",
				"type": "string",
				"deprecated": {"reason": "obsoleted"},
			},
		],
	}]}
}

################################################################################
# Attribute renamed_to – type mismatch
################################################################################

test_fails_on_attribute_renamed_to_attribute_of_different_type if {
	count(semconv.deny) >= 1 with input as {"groups": [{
		"id": "registry.deprecation.test",
		"type": "attribute_group",
		"attributes": [
			{
				"name": "a",
				"type": "string",
				"deprecated": {
					"reason": "renamed",
					"renamed_to": "b",
				},
			},
			{
				"name": "b",
				"type": "int",
			},
		],
	}]}
}

################################################################################
# Enum member renamed_to validation
################################################################################

test_fails_on_enum_member_renamed_to_not_existing_member if {
	count(semconv.deny) >= 1 with input as {"groups": [{
		"id": "registry.enum.test",
		"type": "attribute_group",
		"attributes": [{
			"name": "enum.attr",
			"type": {"members": [
				{"id": "one", "value": "one"},
				{
					"id": "two",
					"value": "two",
					"deprecated": {
						"reason": "renamed",
						"renamed_to": "missing",
					},
				},
			]},
		}],
	}]}
}

test_fails_on_enum_member_renamed_to_deprecated_member if {
	count(semconv.deny) >= 1 with input as {"groups": [{
		"id": "registry.enum.test",
		"type": "attribute_group",
		"attributes": [{
			"name": "enum.attr",
			"type": {"members": [
				{
					"id": "one",
					"value": "one",
					"deprecated": {"reason": "obsolete"},
				},
				{
					"id": "two",
					"value": "two",
					"deprecated": {
						"reason": "renamed",
						"renamed_to": "one",
					},
				},
			]},
		}],
	}]}
}

################################################################################
# Metric renamed_to validation
################################################################################

test_fails_on_metric_renamed_to_not_existing_metric if {
	count(semconv.deny) >= 1 with input as {"groups": [{
		"id": "metric.old",
		"type": "metric",
		"metric_name": "old.metric",
		"deprecated": {
			"reason": "renamed",
			"renamed_to": "missing.metric",
		},
	}]}
}

test_passes_on_metric_renamed_to_existing_metric if {
	count(semconv.deny) == 0 with input as {"groups": [
		{
			"id": "metric.old.metric",
			"type": "metric",
			"metric_name": "old.metric",
			"brief": "Old metric.",
			"stability": "experimental",
			"deprecated": {
				"reason": "renamed",
				"renamed_to": "new.metric",
			},
		},
		{
			"id": "metric.new.metric",
			"type": "metric",
			"metric_name": "new.metric",
			"brief": "New metric.",
			"stability": "experimental",
		},
	]}
}

################################################################################
# Event renamed_to validation
################################################################################

test_passes_on_event_renamed_to_existing_event if {
	count(semconv.deny) == 0 with input as {"groups": [
		{
			"id": "event.old.event",
			"type": "event",
			"name": "old.event",
			"brief": "Old event.",
			"stability": "experimental",
			"deprecated": {
				"reason": "renamed",
				"renamed_to": "new.event",
			},
		},
		{
			"id": "event.new.event",
			"type": "event",
			"name": "new.event",
			"brief": "New event.",
			"stability": "experimental",
		},
	]}
}

################################################################################
# Valid attribute rename (same type)
################################################################################

test_passes_on_valid_attribute_rename_same_type if {
	count(semconv.deny) == 0 with input as {"groups": [{
		"id": "registry.valid.test",
		"type": "attribute_group",
		"brief": "Test group.",
		"attributes": [
			{
				"name": "old.attr",
				"type": "string",
				"brief": "Old attribute.",
				"stability": "experimental",
				"deprecated": {
					"reason": "renamed",
					"renamed_to": "new.attr",
				},
			},
			{
				"name": "new.attr",
				"type": "string",
				"brief": "New attribute.",
				"stability": "experimental",
			},
		],
	}]}
}
