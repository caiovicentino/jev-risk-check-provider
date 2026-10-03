// The 2026-10-03 black-box evaluation: USDC's proxy (ZeppelinOS) keeps its implementation in the
// ZeppelinOS slot, not the EIP-1967 one, and text embedded in its bytecode was read as a PUSH20
// operand ("et a proxy implement" became a "linked address").
import { test } from "node:test";
import assert from "node:assert";
import { codeFacts, resolveIndirection, ZEPPELINOS_IMPLEMENTATION_SLOT, type CodeFacts } from "../src/code-fingerprint.js";

const text = Buffer.from("Cannot set a proxy implementation to a non-contract address").toString("hex");
// PUSH32 <ZeppelinOS slot>, SLOAD, …, DELEGATECALL, padding, then the revert string as data.
const proxyCode = `0x7f${ZEPPELINOS_IMPLEMENTATION_SLOT.slice(2)}54f4${"5b".repeat(200)}${text}`;

test("a ZeppelinOS proxy is named so, and embedded text is never a linked address", () => {
  const f = codeFacts(proxyCode);
  assert.equal(f.kind, "delegating");
  assert.equal(f.proxy, "zeppelinos");
  assert.deepEqual(f.linked ?? [], []);
});

test("its implementation is read from the ZeppelinOS slot", async () => {
  const proxy = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
  const impl = "0x2ce6311ddae708829bc0784c967b7d77d19fd779";
  const entries = new Map<string, CodeFacts>([[proxy, codeFacts(proxyCode)]]);
  const asked: string[] = [];
  await resolveIndirection(entries, async (requests) =>
    requests.map((r) => {
      if (r.method === "eth_getStorageAt") {
        asked.push(String(r.params[1]));
        return `0x000000000000000000000000${impl.slice(2)}`;
      }
      return "0x6080"; // the implementation's code (too small to fingerprint: irrelevant here)
    }),
  );
  assert.deepEqual(asked, [ZEPPELINOS_IMPLEMENTATION_SLOT]);
  assert.equal(entries.get(proxy)?.implementation, impl);
});
