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

# The .tgz that `npm pack --json` packed, read from its JSON report on stdin: exactly one package,
# written to the current directory. The pack runs with --ignore-scripts, right after the package's
# own prepack (`npm run prepack`, the build: neither package has another pack-time script). A
# lifecycle script writes to npm's stdout, so its output would come before the report (which then
# cannot be parsed), or even after the file name (which is why the name is never taken from the
# last line npm prints).
packed_tgz() {
  node -e '
    let input = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => { input += chunk; });
    process.stdin.on("end", () => {
      let report;
      try { report = JSON.parse(input); } catch { report = undefined; }
      const entry = Array.isArray(report) && report.length === 1 ? report[0] : undefined;
      const name = entry !== null && typeof entry === "object" ? entry.filename : undefined;
      const packed = typeof name === "string" && /^[A-Za-z0-9._@-]+\.tgz$/.test(name) && require("node:fs").statSync(name, { throwIfNoEntry: false })?.isFile() === true;
      if (!packed) {
        console.error("npm pack --json did not report exactly one .tgz in this directory");
        process.exit(1);
      }
      process.stdout.write(name);
    });
  '
}

npm whoami >/dev/null || { echo "Run npm login first."; exit 1; }
CLIENT_VERSION=$(node -p 'require("./packages/client/package.json").version')
MCP_VERSION=$(node -p 'require("./packages/mcp/package.json").version')

echo "== @x402check/client@$CLIENT_VERSION: test, pack, publish"
(
  cd packages/client
  npm ci
  npm run typecheck
  npm test
  npm run prepack
  tgz=$(npm pack --json --ignore-scripts | packed_tgz)
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
# The lock links ../client: drop that entry so the client resolves from the registry (npm keeps a link otherwise).
node -e '
  const fs = require("node:fs");
  const lock = JSON.parse(fs.readFileSync("package-lock.json", "utf8"));
  for (const key of Object.keys(lock.packages)) if (key === "node_modules/@x402check/client" || key === "../client" || key.startsWith("../client/")) delete lock.packages[key];
  fs.writeFileSync("package-lock.json", JSON.stringify(lock, null, 2) + "\n");
'
npm install --package-lock-only --ignore-scripts --no-audit --no-fund
npm shrinkwrap
node scripts/check-publish.mjs
npm run prepack
tgz=$(npm pack --json --ignore-scripts | packed_tgz)
node scripts/check-publish.mjs --tarball "$tgz"
npm publish "$tgz" --access public

echo "Published. Check: npx -y --prefer-online @x402check/mcp@$MCP_VERSION --help, then tag client-v$CLIENT_VERSION and mcp-v$MCP_VERSION (AGENTS.md §3.6)."
