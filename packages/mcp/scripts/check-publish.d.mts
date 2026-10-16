// Types for check-publish.mjs (its tests import it).
type Manifest = { dependencies?: Record<string, string>; optionalDependencies?: Record<string, string>; peerDependencies?: Record<string, string> };

export function localDependencies(pkg: Manifest): string[];
export function tarballProblems(files: readonly string[], modules?: readonly string[]): string[];
export function packedFiles(dir?: string): string[];
export function sourceModules(dir?: string): string[];
