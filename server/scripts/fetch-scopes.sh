#!/usr/bin/env bash
# fetch-scopes.sh — extract canonical scopes.yaml from the lucos_auth_scopes image.
#
# The image reference is single-sourced from the Dockerfile (the FROM … AS scopes
# line), so updating the tag in one place keeps Docker builds and local dev in sync.
#
# Usage (from server/ directory):
#   ./scripts/fetch-scopes.sh
#   go generate ./src            # via //go:generate directive in scopes.go
#
# The resulting scopes.yaml is committed to server/src/. Regenerate and commit
# whenever the lucos_auth_scopes image tag is bumped in the Dockerfile.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DOCKERFILE="$SERVER_ROOT/Dockerfile"

# Single-source the pinned image reference from the Dockerfile.
# Matches: FROM lucas42/lucos_auth_scopes:<tag>@sha256:<digest> AS scopes
SCOPES_IMAGE=$(grep -E '^FROM lucas42/lucos_auth_scopes' "$DOCKERFILE" | awk '{print $2}')

if [[ -z "$SCOPES_IMAGE" ]]; then
  echo "fetch-scopes: ERROR — could not find 'FROM lucas42/lucos_auth_scopes' line in $DOCKERFILE" >&2
  exit 1
fi

echo "fetch-scopes: fetching scopes.yaml from $SCOPES_IMAGE"

# FROM scratch images have no default CMD, so docker create requires one
# even though we only use docker cp and never run the container.
CID=$(docker create "$SCOPES_IMAGE" /scopes.yaml)
trap "docker rm -f '$CID' > /dev/null 2>&1 || true" EXIT
docker cp "$CID:/scopes.yaml" "$SERVER_ROOT/src/scopes.yaml"
docker rm "$CID" > /dev/null

echo "fetch-scopes: wrote $SERVER_ROOT/src/scopes.yaml"
