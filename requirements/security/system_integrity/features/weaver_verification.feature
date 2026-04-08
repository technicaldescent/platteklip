# SPDX-FileCopyrightText: 2026 technical descent
# SPDX-License-Identifier: CC-BY-4.0

@PK-SI-02
Feature: SRS-SI02 - Weaver code generation verification
  As a Platform Engineer
  I want the build pipeline to verify that Weaver
  generates both output artefacts
  So that stale semconv or OTTL rules are never
  deployed silently

  @PK-SI-02.01
  Scenario: edge_semconv.py exists and is non-empty
    Given the Weaver generated output directory
    When edge_semconv.py is inspected
    Then edge_semconv.py MUST exist
    And edge_semconv.py MUST be larger than 0 bytes

  @PK-SI-02.02
  Scenario: transform_processor.yaml exists and is non-empty
    Given the Weaver generated output directory
    When transform_processor.yaml is inspected
    Then transform_processor.yaml MUST exist
    And transform_processor.yaml MUST be larger than 0 bytes
