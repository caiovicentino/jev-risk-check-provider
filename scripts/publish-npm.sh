#!/usr/bin/env bash
# Publishes @x402check/client, then @x402check/mcp, to npm, as AGENTS.md §3.6 describes. Run it in
# a terminal: npm's 2FA is the owner's passkey, and each publish prints a web link to approve.
#
# - The client is tested, packed, and its tarball published.
# - The MCP server depends on the client through file:../client in this repository. For the publish
#   only, that becomes "^<client version>" (so the client must be on the registry first: this waits
#   for it), its whole tree is pinned from the registry in an npm-shrinkwrap.json (the server holds a
#   payer key), check-publish verifies the package and then the packed tarball itself, and only that
#   tarball is published. package.json and package-lock.json are restored, and the shrinkwrap removed,
#   afterwards (also on failure): the shrinkwrap is never committed.
set -euo pipefail
cd "$(dirname "$0")/.."
npm whoami >/dev/null || { echo "Run npm login first."; exit 1; }
CLIENT_VERSION=$(node -p 'require("./packages/client/package.json").version')
MCP_VERSION=$(node -p 'require("./packages/mcp/package.json").version')

echo "== @x402check/client@$CLIENT_VERSION: test, pack, publish"
(
  cd packages/client
  npm ci
  npm run typecheck
  npm test
  tgz=$(npm pack --silent | tail -n 1)
  npm publish "$tgz" --access public
)

echo "== waiting for @x402check/client@$CLIENT_VERSION on the registry (staged publishing can hold it a few minutes)"
for _ in $(seq 1 60); do
  if [ "$(npm view "@x402check/client@$CLIENT_VERSION" version --prefer-online 2>/dev/null || true)" = "$CLIENT_VERSION" ]; then break; fi
  sleep 15
done
[ "$(npm view "@x402check/client@$CLIENT_VERSION" version --prefer-online 2>/dev/null || true)" = "$CLIENT_VERSION" ] \
  || { echo "@x402check/client@$CLIENT_VERSION is not on the registry yet: release it (Staged Packages) and run the MCP part again."; exit 1; }

echo "== @x402check/mcp@$MCP_VERSION: test, pin, check, pack, check the tarball, publish (depends on @x402check/client@^$CLIENT_VERSION)"
cd packages/mcp
npm ci
npm run typecheck
npm test
cp package.json package.json.publish-backup
cp package-lock.json package-lock.json.publish-backup
restore() {
  mv package.json.publish-backup package.json
  mv package-lock.json.publish-backup package-lock.json
  rm -f npm-shrinkwrap.json
}
trap restore EXIT
npm pkg set "dependencies.@x402check/client=^$CLIENT_VERSION"
npm install --package-lock-only --ignore-scripts --no-audit --no-fund
npm shrinkwrap
node scripts/check-publish.mjs
tgz=$(npm pack --silent | tail -n 1)
node scripts/check-publish.mjs --tarball "$tgz"
npm publish "$tgz" --access public

echo "Published. Check: npx -y --prefer-online @x402check/mcp@$MCP_VERSION --help, then tag client-v$CLIENT_VERSION and mcp-v$MCP_VERSION (AGENTS.md §3.6)."
