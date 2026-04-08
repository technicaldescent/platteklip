# SPDX-FileCopyrightText: 2026 technical descent
# SPDX-License-Identifier: CC-BY-4.0

@PK-SI-01
Feature: SRS-SI01 - Container image digest pinning
  As a Platform Engineer
  I want all container images pinned by content
  digest
  So that tag mutation cannot alter deployed images

  Background:
    Given the compose.yaml configuration is loaded

  @PK-SI-01.01
  Scenario: Every image includes a sha256 digest
    When each service's image reference is inspected
    Then every image MUST contain "@sha256:"
    And services with pull_policy "build" are exempt

  @PK-SI-01.02
  Scenario: Every digest has a human-readable tag comment
    When each service's image reference and surrounding lines are inspected
    Then every digest-pinned image MUST have a tag comment
