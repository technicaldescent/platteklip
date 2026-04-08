# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

package semconv

import rego.v1

deny contains entity_stability_violation(description, group.id, "") if {
	some group in input.groups
	group.type == "entity"
	group.stability == "stable"

	exceptions = {}
	not exceptions[group.id]

	ids := [attr |
		some attr in group.attributes
		attr.role == "identifying"
	]
	count(ids) < 1

	description := sprintf(
		"Stable entity '%s' has no identifying attributes",
		[group.name],
	)
}

deny contains entity_stability_violation(description, group.id, attr.name) if {
	some group in input.groups
	group.type == "entity"
	group.stability == "stable"
	exceptions = {}
	not exceptions[group.id]

	some attr in group.attributes
	not attr.role

	description := sprintf(
		"Stable entity '%s' has attribute without role: '%s'",
		[group.name, attr.name],
	)
}

entity_stability_violation(description, group, attr) := {
	"msg": description,
	"id": description,
	"type": "semconv_attribute",
	"category": "group_stability_violation",
	"attr": attr,
	"group": group,
}
