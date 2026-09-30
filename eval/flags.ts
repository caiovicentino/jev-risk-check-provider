// Command-line flags for the eval scripts. `--name value`: a missing flag, or a value that is not a
// finite number, gives the fallback. (Indexing argv with indexOf(...) + 1 read argv[0], the node
// binary's path, when the flag was absent: every run silently used NaN, e.g. seed 0 for 402.)
export function numberFlag(name: string, fallback: number, argv: readonly string[] = process.argv): number {
  const i = argv.indexOf(`--${name}`);
  if (i === -1) return fallback;
  const value = Number(argv[i + 1]);
  if (!Number.isFinite(value)) throw new Error(`--${name} needs a number, got ${String(argv[i + 1])}`);
  return value;
}
