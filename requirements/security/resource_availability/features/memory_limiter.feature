# SPDX-FileCopyrightText: 2026 technical descent
# SPDX-License-Identifier: CC-BY-4.0

@PK-RA-02
Feature: SRS-RA02 - OTel Collector memory limiter
  As a Platform Engineer
  I want the memory_limiter processor to be first in
  every OTel pipeline
  So that the Collector sheds load before exhausting
  its container memory limit

  Background:
    Given the OTel Collector config.yaml is loaded

  @PK-RA-02.01
  Scenario: memory_limiter is first in every pipeline
    When each pipeline's processors list is inspected
    Then the first processor MUST be "memory_limiter"
    And this MUST hold for metrics, logs, and traces pipelines

  @PK-RA-02.02
  Scenario: memory_limiter calibrated to container limit
    Given the Collector container memory limit from compose.yaml
    When the memory_limiter limit_mib is inspected
    Then limit_mib MUST be at most 75% of the container memory limit
