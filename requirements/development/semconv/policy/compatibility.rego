# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

package semconv

import rego.v1

###############################################################################
# Entry point
###############################################################################

deny contains removed_metric
deny contains metric_instrument_change
deny contains metric_unit_change
deny contains metric_stability_change
deny contains metric_attribute_missing
deny contains metric_attribute_added
deny contains removed_resource
deny contains resource_stability_change
deny contains resource_attribute_missing
deny contains removed_event
deny contains event_attribute_missing
deny contains attribute_type_change
deny contains attribute_stability_change
deny contains attribute_enum_type_change
deny contains attribute_enum_member_missing
deny contains attribute_enum_member_value_change
deny contains attribute_enum_member_stability_change

###############################################################################
# Helper existence predicates (required for safe negation)
###############################################################################

metric_exists(name) if {
	some m in input.new.metrics
	m.name == name
}

resource_exists(name) if {
	some r in input.new.resources
	r.name == name
}

event_exists(name) if {
	some e in input.new.events
	e.name == name
}

metric_has_attribute(metric, attr) if {
	some a in metric.attributes
	a.name == attr
}

attribute_exists(name) if {
	some a in input.new.attributes
	a.name == name
}

enum_member_exists(attr, member) if {
	some m in attr.members
	m.name == member
}

###############################################################################
# Metric rules
###############################################################################

removed_metric := {
	"type": "removed_metric",
	"metric": old.name,
} if {
	some old in input.old.metrics
	not metric_exists(old.name)
}

metric_instrument_change := {
	"type": "metric_instrument_change",
	"metric": old.name,
} if {
	some old in input.old.metrics
	metric_exists(old.name)
	new := metric_by_name(old.name)
	old.instrument != new.instrument
}

metric_unit_change := {
	"type": "metric_unit_change",
	"metric": old.name,
} if {
	some old in input.old.metrics
	metric_exists(old.name)
	new := metric_by_name(old.name)
	old.unit != new.unit
}

metric_stability_change := {
	"type": "metric_stability_change",
	"metric": old.name,
} if {
	some old in input.old.metrics
	metric_exists(old.name)
	old.stability == "stable"
	new := metric_by_name(old.name)
	new.stability != "stable"
}

metric_attribute_missing := {
	"type": "metric_attribute_missing",
	"metric": old.name,
	"attribute": attr.name,
} if {
	some old in input.old.metrics
	metric_exists(old.name)
	new := metric_by_name(old.name)

	some attr in old.attributes
	attr.stability == "stable"

	not metric_has_attribute(new, attr.name)
}

metric_attribute_added := {
	"type": "metric_attribute_added",
	"metric": old.name,
	"attribute": attr.name,
} if {
	some old in input.old.metrics
	metric_exists(old.name)
	new := metric_by_name(old.name)

	some attr in new.attributes
	attr.stability == "stable"

	not metric_has_attribute(old, attr.name)
}

###############################################################################
# Resource rules
###############################################################################

removed_resource := {
	"type": "removed_resource",
	"resource": old.name,
} if {
	some old in input.old.resources
	not resource_exists(old.name)
}

resource_stability_change := {
	"type": "resource_stability_change",
	"resource": old.name,
} if {
	some old in input.old.resources
	resource_exists(old.name)
	old.stability == "stable"
	new := resource_by_name(old.name)
	new.stability != "stable"
}

resource_attribute_missing := {
	"type": "resource_attribute_missing",
	"resource": old.name,
	"attribute": attr.name,
} if {
	some old in input.old.resources
	resource_exists(old.name)
	new := resource_by_name(old.name)

	some attr in old.attributes
	attr.stability == "stable"

	not metric_has_attribute(new, attr.name)
}

###############################################################################
# Event rules
###############################################################################

removed_event := {
	"type": "removed_event",
	"event": old.name,
} if {
	some old in input.old.events
	not event_exists(old.name)
}

event_attribute_missing := {
	"type": "event_attribute_missing",
	"event": old.name,
	"attribute": attr.name,
} if {
	some old in input.old.events
	event_exists(old.name)
	new := event_by_name(old.name)

	some attr in old.attributes
	attr.stability == "stable"

	not metric_has_attribute(new, attr.name)
}

###############################################################################
# Attribute rules
###############################################################################

attribute_type_change := {
	"type": "attribute_type_change",
	"attribute": old.name,
} if {
	some old in input.old.attributes
	attribute_exists(old.name)
	new := attribute_by_name(old.name)
	old.type != new.type
}

attribute_stability_change := {
	"type": "attribute_stability_change",
	"attribute": old.name,
} if {
	some old in input.old.attributes
	attribute_exists(old.name)
	old.stability == "stable"
	new := attribute_by_name(old.name)
	new.stability != "stable"
}

attribute_enum_type_change := {
	"type": "attribute_enum_type_change",
	"attribute": old.name,
} if {
	some old in input.old.attributes
	old.type == "enum"
	attribute_exists(old.name)
	new := attribute_by_name(old.name)
	new.type != "enum"
}

attribute_enum_member_missing := {
	"type": "attribute_enum_member_missing",
	"attribute": old.name,
	"member": member.name,
} if {
	some old in input.old.attributes
	old.type == "enum"

	some member in old.members

	new := attribute_by_name(old.name)
	not enum_member_exists(new, member.name)
}

attribute_enum_member_value_change := {
	"type": "attribute_enum_member_value_change",
	"attribute": old.name,
	"member": member.name,
} if {
	some old in input.old.attributes
	old.type == "enum"

	some member in old.members
	new := attribute_by_name(old.name)

	some m in new.members
	m.name == member.name
	m.value != member.value
}

attribute_enum_member_stability_change := {
	"type": "attribute_enum_member_stability_change",
	"attribute": old.name,
	"member": member.name,
} if {
	some old in input.old.attributes
	old.type == "enum"

	some member in old.members
	member.stability == "stable"

	new := attribute_by_name(old.name)

	some m in new.members
	m.name == member.name
	m.stability != "stable"
}

###############################################################################
# Lookup helpers
###############################################################################

metric_by_name(name) := m if {
	some m in input.new.metrics
	m.name == name
}

resource_by_name(name) := r if {
	some r in input.new.resources
	r.name == name
}

event_by_name(name) := e if {
	some e in input.new.events
	e.name == name
}

attribute_by_name(name) := a if {
	some a in input.new.attributes
	a.name == name
}
