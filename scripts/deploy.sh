#!/usr/bin/env bash
# Build micro-auth release binary locally, package into a runtime image, and deploy via SSH.
# Usage: ./scripts/deploy.sh [user@server] [/path/to/project/on/server]
#
# Remote layout: REMOTE_PATH must contain docker-compose.server.yml and a .env copied from
# .env.example (INTERNAL_API_KEY must match arcgis-mcp-rs).
#
# Start micro-auth before arcgis-mcp-rs — this compose file creates the shared
# Docker network "arcgis-mcp" that mcp-rs joins as external.
set -euo pipefail

SERVER="${1:-ai.geopowered}"
REMOTE_PATH="${2:-/home/ubuntu/arcgis-soe-mcp/micro-auth}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_DIR"

echo "==> Building release binary..."
cargo build --release

echo "==> Building runtime image..."
export DOCKER_BUILDKIT=1
docker build -f Dockerfile -t micro-auth:latest .

echo "==> Transferring image to $SERVER..."
docker save micro-auth:latest | gzip | ssh "$SERVER" "sudo docker load"

echo "==> Syncing compose file to $SERVER..."
scp "$PROJECT_DIR/docker-compose.server.yml" "$SERVER:$REMOTE_PATH/docker-compose.server.yml"

echo "==> Starting containers on $SERVER..."
ssh "$SERVER" "cd '$REMOTE_PATH' && sudo docker compose -f docker-compose.server.yml up -d"

echo "==> Done."
