# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

package semconv

import rego.v1

deny contains msg if {
	some group in input.groups

	group.type != "event"
	group.type != "span"
	group.type != "attribute_group"

	some attr in group.attributes
	attr.type in ["any", "template[any]"]

	description := sprintf(
		concat("", [
			"Attribute '%s' has type '%s' and is ",
			"referenced on group '%s' of type '%s'. ",
			"Complex attributes are only allowed on ",
			"events and spans.",
		]),
		[attr.name, attr.type, group.id, group.type],
	)

	msg := attribute_type_violation_string(description, group.id, attr.name)
}

attribute_type_violation(description, group_id, attr_name) := {
	"id": description,
	"type": "semconv_attribute",
	"category": "attribute_type_violation",
	"group": group_id,
	"attr": attr_name,
}

attribute_type_violation_string(description, group_id, attr_name) := msg if {
	v := attribute_type_violation(description, group_id, attr_name)
	msg := sprintf(
		"%s type=%s category=%s group=%s attr=%s",
		[v.id, v.type, v.category, v.group, v.attr],
	)
}
