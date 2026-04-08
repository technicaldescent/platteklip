# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

package semconv

import rego.v1

# Collection of all entity names from the registry.
known_entities contains g.name if {
	some g in input.groups
	g.type == "entity"
}

deny contains entity_association_violation(description, group.id) if {
	some group in input.groups
	some entity in group.entity_associations
	not known_entities[entity]
	description := sprintf(
		"Unknown entity '%s' associated in group '%s'",
		[entity, group.id],
	)
}

entity_association_violation(description, group) := {
	"id": description,
	"type": "semconv_attribute",
	"category": "entity_association_violation",
	"attr": "",
	"group": group,
}
