let stored: Record<string, unknown> | null = null;
(globalThis as unknown as Record<string, unknown>).snap_manageState = async (
  req: { operation: string; newState?: Record<string, unknown> },
) => {
  if (req.operation === "get") return stored;
  if (req.operation === "update") {
    stored = req.newState ?? null;
    return null;
  }
  return null;
};
(globalThis as unknown as Record<string, unknown>).snap_getEntropy = async (
  seed: string,
) => {
  const bytes = Buffer.from(seed, "utf8").subarray(0, 32);
  return bytes.toString("hex").padEnd(64, "0");
};
export {};
