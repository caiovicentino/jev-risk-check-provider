// Types for check-publish.mjs (its tests import it).
type Manifest = { dependencies?: Record<string, string>; optionalDependencies?: Record<string, string>; peerDependencies?: Record<string, string> };

export function localDependencies(pkg: Manifest): string[];
export function tarballProblems(files: readonly string[], modules?: readonly string[], options?: { shrinkwrap?: boolean }): string[];
type Shrinkwrap = { name?: string; version?: string; packages?: Record<string, { version?: string; resolved?: string; integrity?: string; link?: boolean; dev?: boolean; dependencies?: Record<string, string> }> };
export function shrinkwrapProblems(shrinkwrap: Shrinkwrap | null, pkg: Manifest & { name?: string; version?: string }): string[];
export function packedFiles(dir?: string): string[];
export function sourceModules(dir?: string): string[];
