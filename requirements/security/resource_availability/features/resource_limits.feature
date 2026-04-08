# SPDX-FileCopyrightText: 2026 technical descent
# SPDX-License-Identifier: CC-BY-4.0

@PK-RA-01
Feature: SRS-RA01 - Container resource limits
  As a Platform Engineer
  I want every service to have explicit memory, CPU,
  and PID limits
  So that no single service can exhaust shared host
  resources

  Background:
    Given the compose.yaml configuration is loaded

  @PK-RA-01.01
  Scenario: Every service defines a memory limit
    When each service's deploy.resources.limits is inspected
    Then every service MUST define a "memory" limit

  @PK-RA-01.02
  Scenario: Every service defines a CPU limit
    When each service's deploy.resources.limits is inspected
    Then every service MUST define a "cpus" limit

  @PK-RA-01.03
  Scenario: Every service defines a PID limit
    When each service's deploy.resources.limits is inspected
    Then every service MUST define a "pids" limit
