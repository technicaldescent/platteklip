# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

package semconv

import rego.v1

# checks attribute name format
deny contains yaml_schema_violation(description, group.id, name) if {
	some group in input.groups
	some attr in group.attributes
	name := attr.name

	not regex.match(name_regex, name)

	description := sprintf(
		"Attribute name '%s' is invalid. Attribute name %s",
		[name, invalid_name_helper],
	)
}

# checks attribute name has a namespace
deny contains yaml_schema_violation(description, group.id, name) if {
	some group in input.groups
	some attr in group.attributes
	name := attr.name

	not attr.deprecated
	not regex.match(has_namespace_regex, name)

	description := sprintf(
		"Attribute name '%s' should have a namespace. Attribute name %s",
		[name, invalid_name_helper],
	)
}

# checks metric name format
deny contains yaml_schema_violation(description, group.id, name) if {
	some group in input.groups
	name := group.metric_name

	name != null
	not regex.match(name_regex, name)

	description := sprintf(
		"Metric name '%s' is invalid. Metric name %s'",
		[name, invalid_name_helper],
	)
}

# checks that metric id matches metric.{metric_name}
deny contains yaml_schema_violation(description, group.id, name) if {
	some group in input.groups
	name := group.metric_name
	name != null

	expected_id := sprintf("metric.%s", [name])
	expected_id != group.id

	description := sprintf(
		concat("", [
			"Metric id '%s' is invalid. Metric id ",
			"must follow 'metric.{metric_name}' ",
			"pattern and match '%s'",
		]),
		[group.id, expected_id],
	)
}

# checks event name format
deny contains yaml_schema_violation(description, group.id, name) if {
	some group in input.groups
	group.type == "event"
	name := group.name

	name != null
	not regex.match(name_regex, name)

	description := sprintf(
		"Event name '%s' is invalid. Event name %s'",
		[name, invalid_name_helper],
	)
}

# checks that event id matches event.{name}
deny contains yaml_schema_violation(description, group.id, name) if {
	some group in input.groups
	group.type == "event"
	name := group.name

	expected_id := sprintf("event.%s", [name])
	expected_id != group.id

	description := sprintf(
		concat("", [
			"Event id '%s' is invalid. Event id ",
			"must follow 'event.{name}' pattern ",
			"and match '%s'",
		]),
		[group.id, expected_id],
	)
}

# checks event.name is not referenced in event
# attributes
deny contains yaml_schema_violation(description, group.id, name) if {
	some group in input.groups
	group.type == "event"
	name := group.name

	some attr in group.attributes
	attr.ref == "event.name"

	description := sprintf(
		concat("", [
			"Attribute 'event.name' is referenced ",
			"on event group '%s'. Event name must ",
			"be provided in 'name' property on the ",
			"group",
		]),
		[name],
	)
}

# require resources have names
deny contains yaml_schema_violation(description, group.id, "") if {
	some group in input.groups
	group.type == "resource"
	group.name == null
	description := sprintf(
		"Resource id '%s' is invalid. Resource must have name.",
		[group.id],
	)
}

# checks resource name format
deny contains yaml_schema_violation(description, group.id, name) if {
	some group in input.groups
	group.type == "resource"
	name := group.name

	name != null
	not regex.match(name_regex, name)

	description := sprintf(
		"Resource name '%s' is invalid. Resource name %s'",
		[name, invalid_name_helper],
	)
}

# checks that resource group id matches resource.{name}
deny contains yaml_schema_violation(description, group.id, name) if {
	some group in input.groups
	group.type == "resource"

	# NOTE: remove once semconv#1423 is merged.
	exclusions := {
		"resource.telemetry.sdk_experimental",
		"resource.service_experimental",
	}
	not exclusions[group.id]

	name := group.name

	expected_id := sprintf("resource.%s", [name])
	expected_id != group.id

	description := sprintf(
		concat("", [
			"Resource id '%s' is invalid. Resource ",
			"id must follow 'resource.{name}' ",
			"pattern and match '%s'",
		]),
		[group.id, expected_id],
	)
}

# checks attribute member id format
deny contains yaml_schema_violation(description, group.id, attr_name) if {
	some group in input.groups
	some attr in group.attributes
	attr_name := attr.name
	name := attr.type.members[_].id

	not regex.match(name_regex, name)

	description := sprintf(
		concat("", [
			"Member id '%s' on attribute '%s' is ",
			"invalid. Member id %s'",
		]),
		[name, attr_name, invalid_name_helper],
	)
}

# check that attribute is fully qualified; prefix is no
# longer supported
deny contains yaml_schema_violation(description, group.id, "") if {
	some group in input.groups

	group.prefix != null
	group.prefix != ""

	# NOTE (weaver#279): provide other violation
	# properties once weaver supports it.
	description := sprintf(
		concat("", [
			"Group '%s' uses prefix '%s'. All ",
			"attribute should be fully qualified ",
			"with their id, prefix is no longer ",
			"supported.",
		]),
		[group.id, group.prefix],
	)
}

# NOTE: remove after span_kind is required
# (semconv#1513).
deny contains yaml_schema_violation(description, group.id, "") if {
	some group in input.groups
	group.type == "span"
	kind := group.span_kind

	kind == null
	not regex.match(`^span\.[a-z0-9_.]+$`, group.id)
	description := sprintf(
		"Group id '%s' is invalid. Span group 'id' must follow 'span.*' pattern",
		[group.id],
	)
}

deny contains yaml_schema_violation(description, group.id, "") if {
	some group in input.groups
	group.type == "span"
	kind := group.span_kind

	kind != null
	pattern := sprintf("^span\\.[a-z0-9_.]+\\.%s$", [kind])
	not regex.match(pattern, group.id)
	description := sprintf(
		"Group id '%s' is invalid. Span group 'id' must follow 'span.*.%s' pattern",
		[group.id, kind],
	)
}

# brief is required on attributes
deny contains yaml_schema_violation(description, group.id, attr.name) if {
	some group in input.groups
	some attr in group.attributes
	is_empty_or_null(attr, "brief")

	description := sprintf(
		concat("", [
			"Attribute id '%s' in group '%s' is ",
			"invalid. Attributes must have a brief.",
		]),
		[attr.name, group.id],
	)
}

# brief is required on groups (except attribute groups)
deny contains yaml_schema_violation(description, group.id, "") if {
	some group in input.groups
	group.type != "attribute_group"
	is_empty_or_null(group, "brief")

	description := sprintf(
		"Group id '%s' is invalid. Groups must have a brief.",
		[group.id],
	)
}

yaml_schema_violation(description, group, attr) := {
	"msg": description,
	"id": description,
	"type": "semconv_attribute",
	"category": "yaml_schema_violation",
	"attr": attr,
	"group": group,
}

name_regex := "^[a-z][a-z0-9]*([._][a-z0-9]+)*$"

has_namespace_regex := "^[a-z0-9_]+\\.([a-z0-9._]+)+$"

invalid_name_helper := concat("", [
	"must consist of lowercase alphanumeric ",
	"characters separated by '_' and '.'",
])

is_empty_or_null(obj, property) if {
	prop := object.get(obj, property, null)
	some v in {prop == null, prop == ""}
	v == true
}
