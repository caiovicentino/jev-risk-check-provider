// prepublishOnly guard (AGENTS.md §3.6). It refuses to publish:
// - a local `file:` / `link:` / `workspace:` dependency: it works in this checkout but breaks for
//   everyone installing from npm. Replace it with the published version first (e.g.
//   "@x402check/client": "^0.1.0", after publishing @x402check/client);
// - a tarball holding anything but package.json, README.md, LICENSE and the compiled dist/
//   (JavaScript and type declarations), one missing an entry point, or one whose dist/ does not
//   match src/ module for module. The package is built first, then listed with
//   `npm pack --dry-run`, so what is checked is what would be published.
import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const PACKAGE_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");
/** What the tarball may hold. */
const ALLOWED = /^(?:package\.json|README\.md|LICENSE|dist\/[A-Za-z0-9_-]+\.(?:js|d\.ts))$/;
/** The entry points: `main`, `types` and `bin`. */
const REQUIRED = ["package.json", "README.md", "LICENSE", "dist/server.js", "dist/server.d.ts", "dist/index.js"];

/** The dependencies that resolve only in this checkout, as "name@spec". */
export function localDependencies(pkg) {
  const deps = { ...pkg.dependencies, ...pkg.optionalDependencies, ...pkg.peerDependencies };
  return Object.entries(deps)
    .filter(([, spec]) => /^(file|link|workspace|portal):/.test(String(spec)))
    .map(([name, spec]) => `${name}@${spec}`);
}

/** What is wrong with the files a tarball would hold (empty when it may be published). */
export function tarballProblems(files, modules) {
  const problems = [];
  for (const file of files) if (!ALLOWED.test(file)) problems.push(`unexpected file in the tarball: ${file}`);
  for (const file of REQUIRED) if (!files.includes(file)) problems.push(`missing from the tarball: ${file}`);
  if (modules) {
    for (const module of modules) {
      for (const built of [`dist/${module}.js`, `dist/${module}.d.ts`]) if (!files.includes(built)) problems.push(`src/${module}.ts is not built into ${built}`);
    }
    for (const file of files) {
      const module = /^dist\/([A-Za-z0-9_-]+)\.(?:js|d\.ts)$/.exec(file)?.[1];
      if (module && !modules.includes(module)) problems.push(`${file} has no source in src/ (a stale build)`);
    }
  }
  return problems;
}

/** The files `npm pack` would publish now (no scripts run: dist/ as it is). */
export function packedFiles(dir = PACKAGE_DIR) {
  const out = execFileSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], { cwd: dir, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  const [report] = JSON.parse(out);
  return report.files.map((file) => file.path).sort();
}

/** The modules of src/: each .ts file, without its extension. */
export function sourceModules(dir = PACKAGE_DIR) {
  return readdirSync(join(dir, "src"))
    .filter((file) => file.endsWith(".ts") && !file.endsWith(".d.ts"))
    .map((file) => file.slice(0, -3))
    .sort();
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const pkg = JSON.parse(readFileSync(join(PACKAGE_DIR, "package.json"), "utf8"));
  const local = localDependencies(pkg);
  if (local.length > 0) {
    console.error(`Refusing to publish ${pkg.name}@${pkg.version}: local dependencies ${local.join(", ")}.`);
    console.error('Replace them with published versions first, e.g. "@x402check/client": "^0.1.0" (publish @x402check/client first).');
    process.exit(1);
  }
  // Build first, so the listing is the tarball that would be published (build output to stderr).
  execFileSync("npm", ["run", "build"], { cwd: PACKAGE_DIR, stdio: ["ignore", 2, 2] });
  const problems = tarballProblems(packedFiles(), sourceModules());
  if (problems.length > 0) {
    console.error(`Refusing to publish ${pkg.name}@${pkg.version}:`);
    for (const problem of problems) console.error(`- ${problem}`);
    process.exit(1);
  }
  console.log(`${pkg.name}@${pkg.version}: no local dependency; the tarball holds package.json, README.md, LICENSE and a dist/ built from src/.`);
}
