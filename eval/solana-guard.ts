// The Solana signing guard (guardSolanaSigner) on REAL inputs: a real x402 payment built by the
// official x402 SVM client for a real 402 from production, and real drain patterns, with the
// real Solana mainnet RPC (lookup of the payee's token account) and real production checks.
//
//   npx tsx eval/solana-guard.ts
//
// Nothing is sent to the network and no funds move: the payment is built and signed through
// the guard, then discarded. Signer: the Solana probe wallet (~/.config/paysol/payer-sol.b58,
// never printed). Checks: prepaid credits (~/.config/paysol/x402check-credit-token), $0.001 each.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { base58 } from "@scure/base";
import {
  AccountRole,
  address,
  appendTransactionMessageInstructions,
  compileTransaction,
  createKeyPairSignerFromBytes,
  createSignableMessage,
  createTransactionMessage,
  generateKeyPairSigner,
  getTransactionDecoder,
  getBase64Encoder,
  pipe,
  setTransactionMessageFeePayerSigner,
  setTransactionMessageLifetimeUsingBlockhash,
  blockhash,
  type KeyPairSigner,
} from "@solana/kit";
import { ExactSvmScheme } from "@x402/svm/exact/client";
import { guardSolanaSigner, X402CheckBlockedError, type GuardVerdict } from "../packages/client/src/guard.js";
import { EVAL_EVIDENCE_DIR } from "./harness.js";

const BASE = process.env.X402CHECK_BASE ?? "https://x402check.xyz";
const RPC = process.env.SOLANA_RPC_URL ?? "https://api.mainnet-beta.solana.com";
const USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

type Row = { case: string; expected: string; action: string; code: string | null; signed: boolean; checked: Array<{ wallet: string; interaction?: string; payment?: unknown }>; reason: string | null; ms: number };

function row(name: string, expected: string, verdict: GuardVerdict | undefined, signed: boolean, t0: number, error?: string): Row {
  return {
    case: name,
    expected,
    action: verdict?.action ?? (error ? "error" : "none"),
    code: verdict?.code ?? null,
    signed,
    checked: (verdict?.checks ?? []).map((c) => ({ wallet: c.request.wallet, ...(c.request.interaction ? { interaction: c.request.interaction.type } : {}), ...(c.request.payment ? { payment: c.request.payment } : {}) })),
    reason: (verdict?.reasons[0] ?? error ?? null)?.slice(0, 200) ?? null,
    ms: Date.now() - t0,
  };
}

async function main(): Promise<void> {
  const signer = await createKeyPairSignerFromBytes(base58.decode(readFileSync(`${homedir()}/.config/paysol/payer-sol.b58`, "utf8").trim()));
  const creditToken = readFileSync(`${homedir()}/.config/paysol/x402check-credit-token`, "utf8").trim();
  let last: GuardVerdict | undefined;
  const guarded = guardSolanaSigner(signer, { baseUrl: BASE, creditToken, solanaRpcUrl: RPC, timeoutMs: 30_000, onVerdict: (v) => void (last = v) });
  const rows: Row[] = [];

  // 1. A real x402 payment: production's 402, built and signed by the official x402 SVM client.
  {
    const challenge = await fetch(`${BASE}/v1/risk-check`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ wallet: USDC, chain: "solana" }) });
    const required = JSON.parse(Buffer.from(challenge.headers.get("PAYMENT-REQUIRED") ?? "", "base64").toString("utf8")) as { accepts: Array<Record<string, unknown> & { network: string }> };
    const option = required.accepts.find((a) => a.network.startsWith("solana:5eykt"));
    if (!option) throw new Error("production offered no Solana mainnet option");
    const t0 = Date.now();
    last = undefined;
    let signed = false;
    let error: string | undefined;
    try {
      const payload = await new ExactSvmScheme(guarded, { rpcUrl: RPC }).createPaymentPayload(2, option as never);
      // Signed by the probe (and not by the facilitator yet): decoded to prove the signature is there. Never sent.
      const wire = getTransactionDecoder().decode(getBase64Encoder().encode((payload.payload as { transaction: string }).transaction));
      signed = wire.signatures[signer.address] != null;
    } catch (err) {
      error = err instanceof X402CheckBlockedError ? undefined : String(err).slice(0, 200);
    }
    rows.push(row(`x402 payment to x402check's pay_to on Solana (${option.amount} base units of USDC)`, "allow", last, signed, t0, error));
  }

  const hash = blockhash((await generateKeyPairSigner()).address);
  const tx = (feePayer: KeyPairSigner, instructions: unknown[]) =>
    pipe(
      createTransactionMessage({ version: 0 }),
      (m) => setTransactionMessageFeePayerSigner(feePayer, m),
      (m) => setTransactionMessageLifetimeUsingBlockhash({ blockhash: hash, lastValidBlockHeight: 1n }, m),
      (m) => appendTransactionMessageInstructions(instructions as Parameters<typeof appendTransactionMessageInstructions>[0], m),
    );
  const attempt = async (name: string, expected: string, run: () => Promise<unknown>) => {
    const t0 = Date.now();
    last = undefined;
    let signed = false;
    let error: string | undefined;
    try {
      await run();
      signed = true;
    } catch (err) {
      error = err instanceof X402CheckBlockedError ? undefined : String(err).slice(0, 200);
    }
    rows.push(row(name, expected, last, signed, t0, error));
  };
  const le64 = (n: bigint) => Array.from({ length: 8 }, (_, i) => Number((n >> BigInt(8 * i)) & 0xffn));

  // 2. The wallet handed to a program (System Assign): the classic Solana owner-change drain.
  const program = (await generateKeyPairSigner()).address;
  await attempt("System Assign of the wallet to an unknown program", "block (local)", async () =>
    guarded.signTransactions([
      compileTransaction(tx(signer, [{ programAddress: address("11111111111111111111111111111111"), accounts: [{ address: signer.address, role: AccountRole.WRITABLE_SIGNER }], data: Uint8Array.from([1, 0, 0, 0, ...base58.decode(program)]) }])),
    ] as never),
  );

  // 3. An unlimited USDC approval to a fresh wallet (the approve-then-drain pattern), checked in production.
  const delegate = (await generateKeyPairSigner()).address;
  const ata = (await generateKeyPairSigner()).address;
  await attempt("unlimited SPL approval to a fresh wallet", "block", async () =>
    guarded.signTransactions([
      compileTransaction(
        tx(signer, [
          {
            programAddress: address("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
            accounts: [
              { address: ata, role: AccountRole.WRITABLE },
              { address: delegate, role: AccountRole.READONLY },
              { address: signer.address, role: AccountRole.READONLY_SIGNER },
            ],
            data: Uint8Array.from([4, ...le64((1n << 64n) - 1n)]),
          },
        ]),
      ),
    ] as never),
  );

  // 4. A transaction disguised as a message to sign.
  const disguised = compileTransaction(tx(signer, [{ programAddress: address("11111111111111111111111111111111"), accounts: [{ address: signer.address, role: AccountRole.WRITABLE_SIGNER }, { address: delegate, role: AccountRole.WRITABLE }], data: Uint8Array.from([2, 0, 0, 0, ...le64(10n ** 9n)]) }]));
  await attempt("a SOL transfer disguised as a message", "block (local)", async () => guarded.signMessages([createSignableMessage(disguised.messageBytes as unknown as Uint8Array)] as never));

  const report = {
    timestamp: new Date().toISOString(),
    base: BASE,
    solana_rpc: RPC,
    note: "nothing was sent to the network; the x402 payment was built and signed through the guard, then discarded",
    rows,
    agreement: `${rows.filter((r) => r.action === r.expected.split(" ")[0]).length}/${rows.length}`,
  };
  mkdirSync(EVAL_EVIDENCE_DIR, { recursive: true });
  writeFileSync(`${EVAL_EVIDENCE_DIR}/solana-guard-report.json`, JSON.stringify(report, null, 2));
  for (const r of rows) console.log(`${r.action.padEnd(12)} signed=${String(r.signed).padEnd(5)} ${r.case} · ${r.checked.map((c) => `${c.wallet.slice(0, 8)}… ${c.interaction ?? ""}`).join(", ") || "no check"} · ${r.reason ?? ""} (${r.ms} ms)`);
  console.log(JSON.stringify({ agreement: report.agreement }));
}

main().catch((err) => {
  console.error(String(err).slice(0, 400));
  process.exit(1);
});
