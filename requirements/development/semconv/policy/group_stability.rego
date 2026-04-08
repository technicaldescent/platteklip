# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

package semconv

import rego.v1

deny contains group_stability_violation(description, group.id, attr.name) if {
	some group in input.groups
	group.stability == "stable"

	some attr in group.attributes
	attr.stability == "experimental"

	description := sprintf(
		concat("", [
			"Attribute '%s' is experimental but is ",
			"referenced in the stable group '%s'. ",
			"Stable groups cannot contain ",
			"experimental attributes.",
		]),
		[attr.name, group.id],
	)
}

deny contains group_stability_violation(description, group.id, attr.name) if {
	some group in input.groups
	group.stability == "stable"

	some attr in group.attributes
	attr.deprecated != null

	description := sprintf(
		concat("", [
			"Attribute '%s' is deprecated but is ",
			"referenced in the stable group '%s'. ",
			"Stable groups cannot contain deprecated ",
			"attributes.",
		]),
		[attr.name, group.id],
	)
}

group_stability_violation(description, group, attr) := {
	"msg": description,
	"id": description,
	"type": "semconv_attribute",
	"category": "group_stability_violation",
	"attr": attr,
	"group": group,
}
