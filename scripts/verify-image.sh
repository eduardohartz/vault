#!/usr/bin/env bash
#
# Verify a container image was built by this repository's CI before running it.
#
# This is where an integrity check belongs: run by you, before the image starts,
# against signatures made by GitHub's OIDC identity. An equivalent check placed
# inside the running app would be worthless, because anyone able to modify the
# app can modify the check.
#
# What this proves: the image was produced by .github/workflows/build.yml from
# a commit in this repository. What it does not prove: that the host you deploy
# to stays uncompromised afterwards. That is what the integrity monitor covers.
#
#   ./scripts/verify-image.sh ghcr.io/eduardohartz/vault@sha256:abc...
#
set -euo pipefail

IMAGE="${1:-}"
REPO="${VAULT_REPO:-eduardohartz/vault}"

if [ -z "$IMAGE" ]; then
  echo "usage: $0 <image@sha256:digest>" >&2
  exit 2
fi

case "$IMAGE" in
  *@sha256:*) ;;
  *)
    echo "Refusing to verify a tag. Pin the digest: tags are mutable and can be" >&2
    echo "repointed at a different image after you verify them." >&2
    exit 2
    ;;
esac

fail() { echo "FAILED: $*" >&2; exit 1; }

echo "Image: $IMAGE"
echo

if ! command -v cosign >/dev/null 2>&1; then
  fail "cosign not installed — see https://docs.sigstore.dev/cosign/installation/"
fi

echo "1/2 Verifying Sigstore signature..."
cosign verify "$IMAGE" \
  --certificate-identity-regexp "^https://github.com/${REPO}/\.github/workflows/build\.yml@refs/(heads/main|tags/v.*)$" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  >/dev/null || fail "signature does not match a build from ${REPO}"
echo "    ok — signed by ${REPO} CI"

echo "2/2 Verifying build provenance..."
if command -v gh >/dev/null 2>&1; then
  gh attestation verify "oci://${IMAGE}" --repo "$REPO" >/dev/null \
    || fail "provenance attestation did not verify"
  echo "    ok — SLSA provenance attests this image came from ${REPO}"
else
  echo "    skipped — gh CLI not installed (signature check above still passed)"
fi

echo
echo "Verified. Safe to deploy:"
echo "  VAULT_IMAGE=$IMAGE docker compose up -d"
