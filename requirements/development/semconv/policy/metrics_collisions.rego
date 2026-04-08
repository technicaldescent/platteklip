# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

package semconv

import rego.v1

metric_names contains obj if {
	some group in input.groups
	group.type == "metric"
	obj := {
		"name": group.metric_name,
		"namespace_prefix": extract_metric_namespace_prefix(group.metric_name),
		"deprecated": is_property_set(group, "deprecated"),
	}
}

# Legacy hardware metrics known to collide.
# NOTE: semconv#3058
metric_collision_exceptions := {
	"hw.battery.charge",
	"hw.cpu.speed",
	"hw.fan.speed",
	"hw.temperature",
	"hw.voltage",
}

deny contains metrics_registry_collision(description, name) if {
	some i
	name := metric_names[i].name
	prefix := metric_names[i].namespace_prefix
	not metric_names[i].deprecated
	not metric_collision_exceptions[name]

	collisions := [other.name |
		some other in metric_names
		not other.deprecated
		other.name != name
		startswith(other.name, prefix)
	]
	count(collisions) > 0
	description := sprintf(
		concat("", [
			"Metric with name '%s' is used as a ",
			"namespace in the following metrics '%s'.",
		]),
		[name, collisions],
	)
}

metrics_registry_collision(description, metric_name) := {
	"msg": description,
	"id": description,
	"type": "semconv_attribute",
	"category": "namespace_collision",
	"attr": metric_name,
	"group": "",
}

extract_metric_namespace_prefix(name) := concat("", [name, "."])

is_property_set(obj, property) if {
	obj[property] != null
} else := false
