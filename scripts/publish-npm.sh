#!/usr/bin/env bash
# Publishes @x402check/client, then @x402check/mcp, to npm. Run it yourself: npm asks for your
# 2FA code at each publish. In this repository the MCP server depends on the client through
# file:../client; for the publish only, that becomes the client's published version, and the
# original package.json is restored afterwards (also on failure).
set -euo pipefail
cd "$(dirname "$0")/.."
npm whoami >/dev/null || { echo "Run npm login first."; exit 1; }
CLIENT_VERSION=$(node -p 'require("./packages/client/package.json").version')
MCP_VERSION=$(node -p 'require("./packages/mcp/package.json").version')

echo "== @x402check/client@$CLIENT_VERSION: test, build, publish"
(cd packages/client && npm ci && npm test && npm publish --access public)

echo "== @x402check/mcp@$MCP_VERSION: test, build, publish (depends on @x402check/client@^$CLIENT_VERSION)"
cd packages/mcp
npm ci && npm test
cp package.json package.json.publish-backup
trap 'mv package.json.publish-backup package.json' EXIT
npm pkg set "dependencies.@x402check/client=^$CLIENT_VERSION"
npm publish --access public

echo "Published. Check: npm view @x402check/mcp@$MCP_VERSION dependencies mcpName"
