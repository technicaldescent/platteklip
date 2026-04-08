# SPDX-FileCopyrightText: 2026 technical descent
# SPDX-License-Identifier: CC-BY-4.0

@PK-SI-03
Feature: SRS-SI03 - OTel attribute sanitisation on all pipelines
  As a Platform Engineer
  I want the attributes/sanitize processor on every
  OTel pipeline
  So that sensitive attributes are stripped before
  export

  Background:
    Given the OTel Collector config.yaml is loaded

  @PK-SI-03.01
  Scenario: Metrics and logs pipelines include sanitisation
    When each pipeline's processors list is inspected
    Then the metrics pipeline MUST include "attributes/sanitize"
    And the logs pipeline MUST include "attributes/sanitize"

  @PK-SI-03.02
  Scenario: Traces pipeline includes sanitisation
    When each pipeline's processors list is inspected
    Then the traces pipeline MUST include "attributes/sanitize"
