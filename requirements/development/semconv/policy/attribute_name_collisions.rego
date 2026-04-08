# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

package semconv

import rego.v1

# ============================================================================
# Derived structures
# ============================================================================

# Build a set of attribute descriptors.
attribute_names contains obj if {
	some group in input.groups
	some attr in group.attributes
	obj := {
		"name": attr.name,
		"const_name": to_const_name(attr.name),
		"namespace_prefix": to_namespace_prefix(attr.name),
		"deprecated": is_property_set(attr, "deprecated"),
		"annotations": property_or_null(attr, "annotations"),
	}
}

# ============================================================================
# Deny rules (NORMALISED TO STRINGS)
# ============================================================================

deny contains msg if {
	some a in attribute_names

	name := a.name
	const_name := a.const_name
	annotations := a.annotations

	not is_codegen_excluded(annotations)

	collisions := [other.name |
		some other in attribute_names
		other.name != name
		other.const_name == const_name
		not is_codegen_excluded(other.annotations)
	]
	count(collisions) > 0

	description := sprintf(
		"Attribute '%s' has the same constant name '%s' as '%s'.",
		[name, const_name, collisions],
	)

	msg := attr_registry_collision_string(description, name)
}

deny contains msg if {
	some a in attribute_names

	not a.deprecated

	name := a.name
	prefix := a.namespace_prefix

	collisions := [other.name |
		some other in attribute_names
		other.name != name
		not other.deprecated
		startswith(other.name, prefix)
	]
	count(collisions) > 0

	description := sprintf(
		"Attribute '%s' name is used as a namespace in the following attributes '%s'.",
		[name, collisions],
	)

	msg := attr_registry_collision_string(description, name)
}

deny contains msg if {
	some group in input.groups
	some attr in group.attributes
	name := attr.name

	collisions := [n |
		n := group.attributes[_].name
		n == name
	]
	count(collisions) > 1

	description := sprintf(
		"Attribute '%s' is already defined in the group '%s'. Attributes must be unique.",
		[name, group.id],
	)

	msg := attr_registry_collision_string(description, name)
}

# ============================================================================
# Violation formatting
# ============================================================================

attr_registry_collision(description, attr_name) := {
	"id": description,
	"type": "semconv_attribute",
	"category": "naming_collision",
	"attr": attr_name,
	"group": "",
}

attr_registry_collision_string(description, attr_name) := msg if {
	v := attr_registry_collision(description, attr_name)
	msg := sprintf(
		"%s type=%s category=%s attr=%s group=%s",
		[v.id, v.type, v.category, v.attr, v.group],
	)
}

# ============================================================================
# Helpers
# ============================================================================

to_namespace_prefix(name) := concat("", [name, "."])

to_const_name(name) := replace(name, ".", "_")

is_property_set(obj, property) if {
	obj[property] != null
} else := false

property_or_null(obj, property) := obj[property] if {
	obj[property] != null
} else := null

is_codegen_excluded(annotations) if {
	annotations != null
	cg := object.get(annotations, "code_generation", null)
	cg != null
	object.get(cg, "exclude", false) == true
}
