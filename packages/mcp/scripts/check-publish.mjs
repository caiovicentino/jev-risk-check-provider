// prepublishOnly guard: a local `file:` / `link:` / `workspace:` dependency works in this
// checkout but breaks for everyone installing from npm. Refuse to publish until it is replaced
// with the published version (e.g. "@x402check/client": "^0.1.0").
import { readFileSync } from "node:fs";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const deps = { ...pkg.dependencies, ...pkg.optionalDependencies, ...pkg.peerDependencies };
const local = Object.entries(deps).filter(([, spec]) => /^(file|link|workspace|portal):/.test(String(spec)));
if (local.length > 0) {
  console.error(`Refusing to publish ${pkg.name}@${pkg.version}: local dependencies ${local.map(([name, spec]) => `${name}@${spec}`).join(", ")}.`);
  console.error('Replace them with published versions first, e.g. "@x402check/client": "^0.1.0" (publish @x402check/client first).');
  process.exit(1);
}
