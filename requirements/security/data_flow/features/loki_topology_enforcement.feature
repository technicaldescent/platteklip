# SPDX-FileCopyrightText: 2026 technical descent
# SPDX-License-Identifier: CC-BY-4.0

Feature: Loki Single-Node Architecture Enforcement
  As a Systems Architect (Stakeholder)
  I want to enforce a monolithic, in-memory topology for Loki
  So that we avoid deploying complex distributed systems infrastructure unnecessarily

  Background:
    Given a baseline Loki configuration parsed as JSON
    And the runtime environment is "development"

  Scenario: Ingester ring is configured for in-memory coordination
    Given the configuration sets "ingester.lifecycler.ring.kvstore.store" to "inmemory"
    When the OPA policy is evaluated
    Then the policy should pass with zero violations

  Scenario: Ingester ring attempts to use external coordination
    Given the configuration sets "ingester.lifecycler.ring.kvstore.store" to "consul"
    When the OPA policy is evaluated
    Then the policy should deny the configuration
    And the violation message should contain "must be inmemory"
