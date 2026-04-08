# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

package semconv

import rego.v1

deny contains metric_brief_violation(description, group.id) if {
	some group in input.groups
	group.type == "metric"
	brief := group.brief
	brief != null

	trimmed_brief := trim(brief, " \n")

	trimmed_brief != ""
	not endswith(trimmed_brief, ".")

	description := sprintf(
		"Non-empty metric brief '%s' must end with a period (.).",
		[trimmed_brief],
	)
}

metric_brief_violation(description, group_id) := {
	"msg": description,
	"id": description,
	"type": "semconv_attribute",
	"category": "metric_brief_formatting",
	"group": group_id,
	"attr": "",
}
