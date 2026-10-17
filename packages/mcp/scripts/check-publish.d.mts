// Types for check-publish.mjs (its tests import it).
type Manifest = {
  name?: string;
  version?: string;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
};
export function localDependencies(pkg: Manifest): string[];
export function tarballProblems(files: readonly string[], modules?: readonly string[], options?: { shrinkwrap?: boolean }): string[];
/** https://registry.npmjs.org/<name>/-/<name without scope>-<version>.tgz */
export function registryTarball(name: string, version: string): string;
/** `shrinkwrap`: the parsed npm-shrinkwrap.json (any shape: it is judged), or null when there is none. */
export function shrinkwrapProblems(shrinkwrap: unknown, pkg: Manifest): string[];
export function packedFiles(dir?: string): string[];
export function sourceModules(dir?: string): string[];
/** The entries of a .tgz (`tar -tzf`). */
export function tarballEntries(tgz: string): string[];
/** Each entry's type, in `tarballEntries` order: the first character of its `tar -tvzf` line ("-" a regular file). */
export function tarballEntryTypes(tgz: string): string[];
/** One entry of a .tgz (`tar -xzOf`), or undefined when it does not hold it. */
export function tarballText(tgz: string, entry: string): string | undefined;
/** What is wrong with a packed .tgz: the same checks, on what it holds. `modules` default to this checkout's src/. */
export function packedTarballProblems(tgz: string, modules?: readonly string[]): string[];
