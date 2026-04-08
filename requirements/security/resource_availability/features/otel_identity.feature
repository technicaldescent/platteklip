# SPDX-FileCopyrightText: 2026 technical descent
# SPDX-License-Identifier: CC-BY-4.0

@PK-RA-04
Feature: SRS-RA04 - Deterministic OTel service identity
  As a Platform Engineer
  I want the OTel Collector to have a stable
  service.instance.id
  So that Prometheus time series are not duplicated
  on restart

  Background:
    Given the OTel Collector config.yaml is loaded

  @PK-RA-04.01
  Scenario: Static service.instance.id is configured
    When the service.telemetry.resource block is inspected
    Then service.instance.id MUST be present
    And service.instance.id MUST be a static value
