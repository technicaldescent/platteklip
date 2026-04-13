#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

# =================================================================
# scripts/release.sh — attested image release
# =================================================================
#
# Builds, generates SBOMs, publishes, and signs a
# container image.  Each stage is wrapped with
# ``witness run`` for in-toto attestation.
#
# Version is read from the latest git tag, which must
# have been created by ``cz bump`` before running this
# script.  hatch-vcs reads the same tag at build time.
#
# Usage:
#
#   ./scripts/ci.sh                # attested pipeline
#   cz bump                        # signed tag + changelog
#   ./scripts/release.sh           # build, publish, sign
#   git push --follow-tags         # push tag and code
#
# Options:
#
#   ./scripts/release.sh [service] [registry]
#
# Examples:
#
#   ./scripts/release.sh
#   ./scripts/release.sh mqtt-producer
#   ./scripts/release.sh nifi ghcr.io/technicaldescent
#
# Prerequisites:
#
#   - dagger, witness, cosign on PATH
#   - Docker authenticated to the registry
#   - A signed git tag (from cz bump)
#   - Sigstore OIDC (opens browser on first attestation)
#   - ci.sh must have been run first
#
# This script is VCS-independent.  It runs identically
# on any POSIX system regardless of the hosting platform.

set -euo pipefail

# -----------------------------------------------------------------
# Arguments
# -----------------------------------------------------------------

SERVICE="${1:-mqtt-producer}"
REGISTRY="${2:-ghcr.io/technicaldescent}"

# -----------------------------------------------------------------
# Read version from latest git tag
# -----------------------------------------------------------------

TAG=$(git describe --tags --abbrev=0 2>/dev/null || true)

if [[ -z "${TAG}" ]]; then
    echo "ERROR: no git tag found." >&2
    echo "Run 'cz bump' first." >&2
    exit 1
fi

VERSION="${TAG#v}"

echo "=== releasing ${SERVICE}:${VERSION} ==="
echo "Tag:      ${TAG}"
echo "Service:  ${SERVICE}"
echo "Registry: ${REGISTRY}"

# -----------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------

ATTESTATION_DIR="gemara/evidence/attestations"
POLICY_FILE="witness/policy-signed.json"

WITNESS_COMMON=(
    --signer-fulcio-url "https://fulcio.sigstore.dev"
    --signer-fulcio-oidc-client-id "sigstore"
    --signer-fulcio-oidc-issuer "https://oauth2.sigstore.dev/auth"
    --timestamp-servers "https://freetsa.org/tsr"
    --attestations "git"
    --attestations "environment"
)

mkdir -p "${ATTESTATION_DIR}"

# -----------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------

_step() {
    local step_name="$1"
    shift
    local outfile="${ATTESTATION_DIR}/${step_name}.json"

    echo ""
    echo "=== ${step_name} ==="

    witness run \
        --step "${step_name}" \
        --outfile "${outfile}" \
        "${WITNESS_COMMON[@]}" \
        -- "$@"

    echo "--- attestation: ${outfile}"
}

# -----------------------------------------------------------------
# Check ci.sh attestations exist
# -----------------------------------------------------------------

CI_STEPS=("test-unit" "quality" "acceptance" "policy")

for step in "${CI_STEPS[@]}"; do
    if [[ ! -f "${ATTESTATION_DIR}/${step}.json" ]]; then
        echo "ERROR: missing attestation for '${step}'." >&2
        echo "Run './scripts/ci.sh' first." >&2
        exit 1
    fi
done

echo ""
echo "--- CI attestations verified"

# -----------------------------------------------------------------
# Build
# -----------------------------------------------------------------

_step build \
    dagger call build --source=. \
        --service="${SERVICE}"

# -----------------------------------------------------------------
# SBOM
# -----------------------------------------------------------------

_step sbom \
    dagger call sbom --source=. \
        --service="${SERVICE}"

# -----------------------------------------------------------------
# Publish and capture digest reference
# -----------------------------------------------------------------

echo ""
echo "=== publish ==="

REF=$(witness run \
    --step "publish" \
    --outfile "${ATTESTATION_DIR}/publish.json" \
    "${WITNESS_COMMON[@]}" \
    -- dagger call publish --source=. \
        --service="${SERVICE}" \
        --registry="${REGISTRY}" \
        --version="${VERSION}")

echo "--- attestation: ${ATTESTATION_DIR}/publish.json"
echo ""
echo "=== published ==="
echo "${REF}"

# -----------------------------------------------------------------
# Verification gate
# -----------------------------------------------------------------

if [[ -f "${POLICY_FILE}" ]]; then
    echo ""
    echo "=== verify ==="

    witness verify \
        --policy "${POLICY_FILE}" \
        --attestations "${ATTESTATION_DIR}"

    echo "--- policy verification passed"
else
    echo ""
    echo "--- WARN: no signed policy at ${POLICY_FILE}"
    echo "--- skipping verification gate"
    echo "--- see witness/README.md for setup"
fi

# -----------------------------------------------------------------
# Sign and attest the image
# -----------------------------------------------------------------

echo ""
echo "=== cosign sign ==="
cosign sign --yes "${REF}"

echo ""
echo "=== cosign attest (SBOM) ==="
cosign attest --yes \
    --predicate "./${SERVICE}.spdx.json" \
    --type spdxjson \
    "${REF}"

# -----------------------------------------------------------------
# Summary
# -----------------------------------------------------------------

echo ""
echo "=== release complete ==="
echo "Image:  ${REF}"
echo "Tag:    ${TAG}"
echo "SBOM:   ./${SERVICE}.spdx.json"
echo "Attest: ${ATTESTATION_DIR}/"
echo ""
echo "Push with: git push --follow-tags"
