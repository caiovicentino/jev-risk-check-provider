// Publish guard (AGENTS.md §3.6), in two modes:
// - `node scripts/check-publish.mjs` (also npm's prepublishOnly): builds the package, then checks
//   what `npm pack --dry-run` lists and ./npm-shrinkwrap.json;
// - `node scripts/check-publish.mjs --tarball <file.tgz>`: checks a packed tarball itself, which is
//   what `npm publish <file.tgz>` uploads (that command runs no prepublishOnly, and a later `npm pack`
//   rebuilds): its listing (`tar -tzf`, and `tar -tvzf` for each entry's type: regular files only),
//   and the package.json and npm-shrinkwrap.json inside it (`tar -xzOf`).
// Both refuse:
// - a local `file:` / `link:` / `workspace:` dependency: it works in this checkout but breaks for
//   everyone installing from npm. Replace it with the published version first (e.g.
//   "@x402check/client": "^0.1.0", after publishing @x402check/client);
// - a tarball holding anything but package.json, README.md, LICENSE, npm-shrinkwrap.json and the
//   compiled dist/ (JavaScript and type declarations), one missing an entry point, or one whose
//   dist/ does not match src/ module for module;
// - a tarball without an npm-shrinkwrap.json that pins the whole installed tree from the registry
//   (this server holds a payer key: a dependency that floats at install time is a way in):
//   lockfileVersion 3 with no legacy section; every package, development ones included, resolved
//   to its canonical registry tarball with a sha512 integrity; nothing users install marked dev;
//   no install script outside INSTALL_SCRIPTS. It is made at publish time, once the client is on
//   npm (AGENTS.md §3.6), and never committed.
import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const PACKAGE_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");
/** What the tarball may hold. */
const ALLOWED = /^(?:package\.json|README\.md|LICENSE|npm-shrinkwrap\.json|dist\/[A-Za-z0-9_-]+\.(?:js|d\.ts))$/;
const REGISTRY = "https://registry.npmjs.org/";
/** The entry points: `main`, `types` and `bin`. */
const REQUIRED = ["package.json", "README.md", "LICENSE", "dist/server.js", "dist/server.d.ts", "dist/index.js"];
/** One sha512 Subresource Integrity hash (64 bytes in base64), and nothing else. */
const SHA512 = /^sha512-[A-Za-z0-9+/]{86}==$/;
/** A registry package name, scoped or not. */
const PACKAGE_NAME = /^(?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;
/** A semver version: nothing in it can change the path of the tarball URL built from it. */
const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
/** Where npm installs a package: node_modules/<name>, possibly nested in another package. */
const INSTALLED = /(?:^|\/)node_modules\/((?:@[^/]+\/)?[^/@][^/]*)$/;
/**
 * The packages whose install script npm-shrinkwrap.json may carry, and only as development entries:
 * npm skips a dependency's development entries, so these never run for users. Any other entry with
 * `hasInstallScript` is refused. Both come from tsx, the test runner (checked against the real tree
 * on 2026-10-16):
 * - esbuild: `postinstall: node install.js` checks the platform binary it ships as an optional dependency;
 * - fsevents (optional, macOS file watching): `install: node-gyp rebuild`.
 */
const INSTALL_SCRIPTS = new Set(["esbuild", "fsevents"]);

function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The dependencies that resolve only in this checkout, as "name@spec". */
export function localDependencies(pkg) {
  const deps = { ...pkg.dependencies, ...pkg.optionalDependencies, ...pkg.peerDependencies };
  return Object.entries(deps)
    .filter(([, spec]) => /^(file|link|workspace|portal):/.test(String(spec)))
    .map(([name, spec]) => `${name}@${spec}`);
}

/** What is wrong with the files a tarball would hold (empty when it may be published). `shrinkwrap`: a publish, which needs one. */
export function tarballProblems(files, modules, { shrinkwrap = false } = {}) {
  const problems = [];
  for (const file of files) if (!ALLOWED.test(file)) problems.push(`unexpected file in the tarball: ${file}`);
  for (const file of shrinkwrap ? [...REQUIRED, "npm-shrinkwrap.json"] : REQUIRED) if (!files.includes(file)) problems.push(`missing from the tarball: ${file}`);
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

/** The tarball the registry serves for name@version: https://registry.npmjs.org/<name>/-/<name without scope>-<version>.tgz. */
export function registryTarball(name, version) {
  return `${REGISTRY}${name}/-/${name.slice(name.lastIndexOf("/") + 1)}-${version}.tgz`;
}

/** Where npm finds dependency `name` of the package at `from` ("" is the root): the nearest node_modules/<name> up the tree. */
function locate(packages, from, name) {
  for (let base = from; ; ) {
    const at = `${base ? `${base}/` : ""}node_modules/${name}`;
    if (Object.hasOwn(packages, at)) return at;
    if (!base) return undefined;
    const up = base.lastIndexOf("/node_modules/");
    base = up > 0 ? base.slice(0, up) : "";
  }
}

/** What a package needs installed, as [name, optional]: its dependencies, optional dependencies and peers. */
function requirements(entry) {
  if (!isRecord(entry)) return [];
  const keys = (field) => Object.keys(isRecord(entry[field]) ? entry[field] : {});
  const meta = isRecord(entry.peerDependenciesMeta) ? entry.peerDependenciesMeta : {};
  return [
    ...keys("dependencies").map((name) => [name, false]),
    ...keys("optionalDependencies").map((name) => [name, true]),
    ...keys("peerDependencies").map((name) => [name, isRecord(meta[name]) && meta[name].optional === true]),
  ];
}

/** Why one installed entry is not pinned (none when it is), and whether its install script is refused. */
function entryProblems(path, entry, packages) {
  if (!isRecord(entry)) return [`${path} is not pinned to the registry: it is not a package entry`];
  const unpinned = (why) => [`${path} is not pinned to the registry: ${why}`];
  if (entry.link === true) return unpinned(`it is a link to ${String(entry.resolved)}`);
  const name = typeof entry.name === "string" ? entry.name : INSTALLED.exec(path)?.[1];
  if (name === undefined || !INSTALLED.test(path)) return unpinned("it is not an installed package (node_modules/<name>)");
  const problems = [];
  if (entry.inBundle === true) {
    // Its files come from the tarball of the package it is bundled in, which that entry pins.
    const up = path.lastIndexOf("/node_modules/");
    if (up <= 0 || !isRecord(packages[path.slice(0, up)])) problems.push(...unpinned("it is bundled, but not inside a package npm-shrinkwrap.json pins"));
  } else if (!PACKAGE_NAME.test(name) || typeof entry.version !== "string" || !VERSION.test(entry.version)) {
    problems.push(...unpinned("its name or version is not a registry package's"));
  } else {
    const canonical = registryTarball(name, entry.version);
    if (entry.resolved !== canonical) problems.push(...unpinned(`it resolves to ${String(entry.resolved ?? "nothing")}, not ${canonical}`));
    if (typeof entry.integrity !== "string" || !SHA512.test(entry.integrity)) problems.push(...unpinned("its integrity is not one sha512 hash"));
  }
  if (entry.hasInstallScript === true && !(INSTALL_SCRIPTS.has(name) && entry.dev === true)) {
    problems.push(`${path} runs an install script (hasInstallScript), and only these development entries may: ${[...INSTALL_SCRIPTS].join(", ") || "none"}`);
  }
  return problems;
}

/**
 * What is wrong with the npm-shrinkwrap.json a publish carries (empty when it pins the tree): it must
 * be lockfileVersion 3 with no legacy section, for this name and version, ask for exactly
 * package.json's dependencies, resolve every package (development ones included) to its canonical
 * registry tarball with a sha512 integrity, never mark dev a package users install, and carry no
 * install script outside INSTALL_SCRIPTS.
 */
export function shrinkwrapProblems(shrinkwrap, pkg) {
  if (!shrinkwrap) return ["no npm-shrinkwrap.json: the installed tree would float (AGENTS.md §3.6: npm install --package-lock-only, then npm shrinkwrap)"];
  const problems = [];
  if (shrinkwrap.lockfileVersion !== 3) {
    problems.push(`npm-shrinkwrap.json has lockfileVersion ${String(shrinkwrap.lockfileVersion)}: a publish needs lockfileVersion 3 (written by npm 9 and later), whose "packages" section is the only one npm reads`);
  }
  if ("dependencies" in shrinkwrap) problems.push('npm-shrinkwrap.json has a legacy "dependencies" section (lockfileVersion 1 or 2), which npm 6 and older install from instead of "packages"');
  if (shrinkwrap.name !== pkg.name || shrinkwrap.version !== pkg.version) problems.push(`npm-shrinkwrap.json is for ${shrinkwrap.name}@${shrinkwrap.version}, not ${pkg.name}@${pkg.version}`);
  const packages = isRecord(shrinkwrap.packages) ? shrinkwrap.packages : undefined;
  const root = packages && isRecord(packages[""]) ? packages[""] : undefined;
  if (!packages || !root) return [...problems, 'npm-shrinkwrap.json has no "packages" section with the package itself: it pins nothing'];
  if (root.version !== pkg.version || (root.name !== undefined && root.name !== pkg.name)) problems.push(`npm-shrinkwrap.json's root package is ${root.name}@${root.version}, not ${pkg.name}@${pkg.version}`);
  for (const field of ["dependencies", "optionalDependencies", "peerDependencies"]) {
    const wanted = isRecord(pkg[field]) ? pkg[field] : {};
    const asked = isRecord(root[field]) ? root[field] : {};
    for (const [name, spec] of Object.entries(wanted)) if (asked[name] !== spec) problems.push(`npm-shrinkwrap.json does not ask for ${name}@${spec} as package.json does`);
    for (const name of Object.keys(asked)) if (!Object.hasOwn(wanted, name)) problems.push(`npm-shrinkwrap.json asks for ${name}, which package.json does not`);
  }
  for (const [path, entry] of Object.entries(packages)) if (path !== "") problems.push(...entryProblems(path, entry, packages));
  // What users install: the root's dependencies and all they need. npm skips the entries a
  // dependency's shrinkwrap marks dev, so one of these marked dev would be resolved at install time.
  const queue = requirements(root).map(([name, optional]) => ["", name, optional]);
  const reached = new Set();
  while (queue.length > 0) {
    const [from, name, optional] = queue.pop();
    const at = locate(packages, from, name);
    if (at === undefined) {
      if (!optional) problems.push(`${from || "the package"} needs ${name}, which npm-shrinkwrap.json does not pin`);
      continue;
    }
    if (reached.has(at)) continue;
    reached.add(at);
    if (isRecord(packages[at]) && packages[at].dev === true) problems.push(`${at} is installed for users, but npm-shrinkwrap.json marks it dev: npm would resolve it at install time`);
    queue.push(...requirements(packages[at]).map(([dep, depOptional]) => [at, dep, depOptional]));
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

const TAR = { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], maxBuffer: 64 * 1024 * 1024 };

/** The entries of a .tgz, as `tar -tzf` lists them. */
export function tarballEntries(tgz) {
  return execFileSync("tar", ["-tzf", resolve(tgz)], TAR)
    .split("\n")
    .filter((line) => line !== "");
}

/**
 * The type of each entry of a .tgz, in the order `tar -tzf` lists them: the first character of its
 * `tar -tvzf` line, as both bsdtar and GNU tar print it ("-" a regular file, "d" a directory, "l" a
 * symbolic link, "h" a hard link, ...). Only the first character is read: the rest of the line
 * (owner, date) differs between tars and locales.
 */
export function tarballEntryTypes(tgz) {
  return execFileSync("tar", ["-tvzf", resolve(tgz)], TAR)
    .split("\n")
    .filter((line) => line !== "")
    .map((line) => line[0]);
}

/** What an entry type other than a regular file is, for the refusal. */
const ENTRY_KINDS = { d: "a directory", l: "a symbolic link", h: "a hard link", c: "a character device", b: "a block device", p: "a FIFO", s: "a socket" };

/** One entry of a .tgz, as `tar -xzOf` prints it; undefined when the tarball does not hold it. */
export function tarballText(tgz, entry) {
  try {
    return execFileSync("tar", ["-xzOf", resolve(tgz), entry], TAR);
  } catch {
    return undefined;
  }
}

function parsed(text) {
  try {
    return text === undefined ? undefined : JSON.parse(text);
  } catch {
    return undefined;
  }
}

/**
 * What is wrong with a packed .tgz (empty when it may be published): the checks above, applied to
 * what it holds. Every entry must be a regular file under package/, listed once: npm packs no
 * directory or link entries (checked on the published 0.3.1 tarball and on npm 10.9's pack of
 * nested directories), and a link under an expected name (package/dist/server.js) is refused.
 * `modules` are the modules its dist/ must hold (default: this checkout's src/).
 */
export function packedTarballProblems(tgz, modules = sourceModules()) {
  const problems = [];
  const files = [];
  const seen = new Set();
  const entries = tarballEntries(tgz);
  const types = tarballEntryTypes(tgz);
  if (types.length !== entries.length) problems.push(`tar lists ${entries.length} entries but ${types.length} entry types: the tarball cannot be checked entry by entry`);
  for (const [i, entry] of entries.entries()) {
    const type = types[i];
    if (seen.has(entry)) problems.push(`the tarball holds ${entry} more than once`);
    else if (!entry.startsWith("package/")) problems.push(`unexpected entry in the tarball, outside package/: ${entry}`);
    else if (type !== "-") problems.push(`the tarball holds ${entry} as ${ENTRY_KINDS[type] ?? `an entry of type "${String(type)}"`}: npm packs regular files only`);
    else files.push(entry.slice("package/".length));
    seen.add(entry);
  }
  problems.push(...tarballProblems(files, modules, { shrinkwrap: true }));
  const pkg = parsed(tarballText(tgz, "package/package.json"));
  if (!isRecord(pkg)) return [...problems, "the tarball's package/package.json cannot be read as JSON"];
  for (const local of localDependencies(pkg)) problems.push(`the tarball's package.json has a local dependency: ${local}`);
  if (files.includes("npm-shrinkwrap.json")) {
    const shrinkwrap = parsed(tarballText(tgz, "package/npm-shrinkwrap.json"));
    if (isRecord(shrinkwrap)) problems.push(...shrinkwrapProblems(shrinkwrap, pkg));
    else problems.push("the tarball's package/npm-shrinkwrap.json cannot be read as JSON");
  }
  return problems;
}

function refuse(what, problems) {
  console.error(`Refusing to publish ${what}:`);
  for (const problem of problems) console.error(`- ${problem}`);
  process.exit(1);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if (args.length > 0) {
    // A typo must not fall back to the checkout's checks, which say nothing of a tarball.
    if (args.length !== 2 || args[0] !== "--tarball") {
      console.error("usage: node scripts/check-publish.mjs [--tarball <file.tgz>]");
      process.exit(2);
    }
    const tgz = args[1];
    if (!existsSync(tgz)) refuse(tgz, ["no such file"]);
    const problems = packedTarballProblems(tgz);
    const pkg = parsed(tarballText(tgz, "package/package.json"));
    const what = isRecord(pkg) ? `${basename(tgz)} (${pkg.name}@${pkg.version})` : basename(tgz);
    if (problems.length > 0) refuse(what, problems);
    console.log(`${what}: no local dependency; the tarball holds, as regular files only, package.json, README.md, LICENSE, a dist/ for every module of src/ and an npm-shrinkwrap.json that pins every package from the registry.`);
  } else {
    const pkg = JSON.parse(readFileSync(join(PACKAGE_DIR, "package.json"), "utf8"));
    const local = localDependencies(pkg);
    if (local.length > 0) {
      console.error(`Refusing to publish ${pkg.name}@${pkg.version}: local dependencies ${local.join(", ")}.`);
      console.error('Replace them with published versions first, e.g. "@x402check/client": "^0.1.0" (publish @x402check/client first).');
      process.exit(1);
    }
    // Build first, so the listing is the tarball that would be published (build output to stderr).
    execFileSync("npm", ["run", "build"], { cwd: PACKAGE_DIR, stdio: ["ignore", 2, 2] });
    const shrinkwrapPath = join(PACKAGE_DIR, "npm-shrinkwrap.json");
    const shrinkwrap = existsSync(shrinkwrapPath) ? JSON.parse(readFileSync(shrinkwrapPath, "utf8")) : null;
    const problems = [...tarballProblems(packedFiles(), sourceModules(), { shrinkwrap: true }), ...shrinkwrapProblems(shrinkwrap, pkg)];
    if (problems.length > 0) refuse(`${pkg.name}@${pkg.version}`, problems);
    console.log(`${pkg.name}@${pkg.version}: no local dependency; the tarball holds package.json, README.md, LICENSE, a dist/ built from src/ and an npm-shrinkwrap.json that pins every installed package. After npm pack, check the .tgz itself: node scripts/check-publish.mjs --tarball <file.tgz>`);
  }
}
