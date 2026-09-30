// Vendors the MetaMask Snap's transaction / typed-data / message decoders into
// @x402check/client (packages/client/src/decode/), where the signing guard uses them.
// The Snap's source stays the single source of truth: edit snap/src, then run
//
//   node scripts/sync-decoders.mjs          # write the vendored copies
//   node scripts/sync-decoders.mjs --check  # exit 1 if they drifted (run by the tests)
//
// The only transformation: relative import specifiers gain ".js" (the client compiles
// with NodeNext module resolution; the Snap bundles with "bundler" resolution).
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const FROM = join(ROOT, "snap", "src");
const TO = join(ROOT, "packages", "client", "src", "decode");
export const FILES = ["util.ts", "eip712.ts", "simulation.ts", "tx.ts", "typed.ts", "personal.ts", "request.ts", "decode.ts"];

export function vendored(file) {
  const source = readFileSync(join(FROM, file), "utf8");
  const body = source.replace(/(from\s+["'])(\.{1,2}\/[^"']+?)(["'])/g, (m, pre, spec, post) => (spec.endsWith(".js") ? m : `${pre}${spec}.js${post}`));
  return `// Vendored from snap/src/${file} by scripts/sync-decoders.mjs. Edit the Snap source and re-sync.\n${body}`;
}

const check = process.argv.includes("--check");
let drift = 0;
if (!check) mkdirSync(TO, { recursive: true });
for (const file of FILES) {
  const want = vendored(file);
  const path = join(TO, file);
  if (check) {
    if (!existsSync(path) || readFileSync(path, "utf8") !== want) {
      console.error(`drift: packages/client/src/decode/${file} differs from snap/src/${file}`);
      drift++;
    }
  } else {
    writeFileSync(path, want);
  }
}
if (check && drift > 0) process.exit(1);
console.log(check ? "decoders in sync" : `vendored ${FILES.length} files into packages/client/src/decode`);
