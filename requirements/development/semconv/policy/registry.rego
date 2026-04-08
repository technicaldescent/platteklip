# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

package semconv

import rego.v1

# This file enforces policies requiring all attributes
# to be defined within a semantic convention "registry".

# Helper to create attribute registry violations.
attr_registry_violation(description, group_id, attr_id) := {
	"id": description,
	"type": "semconv_attribute",
	"category": "attribute_registry_checks",
	"group": group_id,
	"attr": attr_id,
}

# Only allow attribute groups in the attribute registry.
deny contains attr_registry_violation(description, group.id, "") if {
	some group in input.groups
	startswith(group.id, "registry.")
	group.type != "attribute_group"

	# NOTE (weaver#279): provide other violation
	# properties once weaver supports it.
	description := sprintf(
		concat("", [
			"Registry group '%s' has invalid type ",
			"'%s'. Groups in attribute registry must ",
			"have `attribute_group` type.",
		]),
		[group.id, group.type],
	)
}

# Any group NOT in the attribute registry that has an
# attribute id is in violation.
deny contains attr_registry_violation(description, group.id, attr.name) if {
	some group in input.groups
	not startswith(group.id, "registry.")
	some attr in group.attributes
	attr.name != null

	attr_name := attribute_name(attr, group)

	# NOTE (weaver#279): provide other violation
	# properties once weaver supports it.
	description := sprintf(
		concat("", [
			"Attribute '%s' is defined in the group ",
			"'%s' which is not part of the attribute ",
			"registry. Attributes can be defined in ",
			"the registry group only.",
		]),
		[attr_name, group.id],
	)
}

# A registry `attribute_group` containing at least one
# `ref` attribute is invalid.
deny contains attr_registry_violation(description, group.id, attr.ref) if {
	some group in input.groups
	startswith(group.id, "registry.")
	some attr in group.attributes
	attr.ref != null

	# NOTE: will need to be updated to support `embed`
	# in the future.
	# NOTE (weaver#279): provide other violation
	# properties once weaver supports it.
	description := sprintf(
		concat("", [
			"Registry group '%s' references attribute ",
			"'%s'. Registry groups can only define ",
			"new attributes.",
		]),
		[group.id, attr.ref],
	)
}

# Attribute definitions must not have requirement_level
deny contains attr_registry_violation(description, group.id, attr.name) if {
	some group in input.groups
	startswith(group.id, "registry.")

	some attr in group.attributes

	# NOTE: requirement_level defaults to recommended;
	# no way to check if it is not set.
	attr.requirement_level != "recommended"

	# NOTE (weaver#279): provide other violation
	# properties once weaver supports it.
	description := sprintf(
		concat("", [
			"Attribute definition '%s' has ",
			"requirement_level set to %s. Only ",
			"attribute references can set ",
			"requirement_level.",
		]),
		[attr.name, attr.requirement_level],
	)
}

# Attribute definitions require stability
deny contains attr_registry_violation(description, group.id, attr.name) if {
	some group in input.groups
	some attr in group.attributes
	not attr.stability
	description := sprintf(
		concat("", [
			"Attribute definition '%s' does not ",
			"contain stability field. All attribute ",
			"definitions must include stability level.",
		]),
		[attr.name],
	)
}

# Span, metric, event, resource definitions require
# stability
deny contains attr_registry_violation(description, group.id, "") if {
	semconv_types := {"span", "metric", "event", "resource"}
	some group in input.groups

	semconv_types[group.type] != null

	not group.stability
	description := sprintf(
		concat("", [
			"Semconv group '%s' does not contain ",
			"stability field. All semconv definitions ",
			"must include stability level.",
		]),
		[group.id],
	)
}

# Member ids must not collide within the same attribute
deny contains attr_registry_violation(description, group.id, attr.name) if {
	some group in input.groups
	startswith(group.id, "registry.")

	some attr in group.attributes
	some member in attr.type.members

	collisions := [n |
		n := attr.type.members[_].id
		n == member.id
	]
	count(collisions) > 1

	description := sprintf(
		concat("", [
			"Member with id '%s' is already defined ",
			"on the attribute '%s' in the group '%s'. ",
			"Member id must be unique.",
		]),
		[member.id, attr.name, group.id],
	)
}

# Member values must not collide within the same
# attribute
deny contains attr_registry_violation(description, group.id, attr.name) if {
	some group in input.groups
	startswith(group.id, "registry.")
	some attr in group.attributes
	some member in attr.type.members
	not is_property_set(member, "deprecated")

	collisions := [m |
		some m in attr.type.members
		not is_property_set(m, "deprecated")
		m.value == member.value
	]
	count(collisions) > 1

	description := sprintf(
		concat("", [
			"Member with value '%s' (id '%s') is ",
			"already defined on the attribute '%s' ",
			"in the group '%s'. Member value must ",
			"be unique.",
		]),
		[member.value, member.id, attr.name, group.id],
	)
}

# Member const names must not collide within the same
# attribute
deny contains attr_registry_violation(description, group.id, attr.name) if {
	some group in input.groups
	startswith(group.id, "registry.")
	some attr in group.attributes
	some member in attr.type.members
	not member.annotations.code_generation.exclude

	const_name := to_const_name(member.id)

	collisions := [m |
		some m in attr.type.members
		to_const_name(m.id) == const_name
		not m.annotations.code_generation.exclude
	]
	count(collisions) > 1

	description := sprintf(
		concat("", [
			"Member with const name '%s' (id '%s'), ",
			"is already defined on the attribute ",
			"'%s' in the group '%s'. Member const ",
			"names must be unique.",
		]),
		[const_name, member.id, attr.name, group.id],
	)
}

attribute_name(attr, group) := name if {
	full_name := concat(".", [group.prefix, attr.name])
	name := trim(full_name, ".")
}

to_const_name(name) := replace(name, ".", "_")

is_property_set(obj, property) if {
	obj[property] != null
} else := false
