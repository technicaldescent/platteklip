# SPDX-FileCopyrightText: 2026 technical descent
# SPDX-License-Identifier: CC-BY-4.0

Feature: Loki Dynamic Operational Limits
  As a Platform Engineer (Stakeholder)
  I want Loki's data retention to be restricted based on the deployment environment
  So that development environments do not incur production-level storage costs

  Background:
    Given a baseline Loki configuration parsed as JSON

  Scenario: Development environment respects the 2-hour retention limit
    Given the runtime environment is "development"
    And the configuration sets "limits_config.retention_period" to "2h"
    When the OPA policy is evaluated
    Then the policy should pass with zero violations

  Scenario: Development environment attempts to exceed the retention limit
    Given the runtime environment is "development"
    And the configuration sets "limits_config.retention_period" to "24h"
    When the OPA policy is evaluated
    Then the policy should deny the configuration
    And the violation message should contain "must be <= 2h"

  Scenario: Production environment allows extended retention limits
    Given the runtime environment is "production"
    And the configuration sets "limits_config.retention_period" to "87600h"
    When the OPA policy is evaluated
    Then the policy should pass with zero violations
