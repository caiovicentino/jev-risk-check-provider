// The 2026-10-17 review of the MCP package (low): concurrent calls to the same payee and site each
// bought a paid x402check check (the gate) before one of them signed, and the others were then
// refused, each having paid for a check that could not lead to a payment. The payer now takes the
// record for a payee and site in the same step that finds it free (no await between them), before
// the payee is checked: a concurrent call is refused before it buys a check. The record is given
// back when its call signs nothing, and a call signs only while the record is still its own. Stubs
// only: throwaway keys, no network, no money.
import assert from "node:assert/strict";
import { before, describe, test } from "node:test";
import { generatePrivateKey } from "viem/accounts";
import { createPayer, PaymentRefused, type PaymentAuthorizer } from "../src/payer.js";
import { json, makeIssuer, type Issuer } from "./helpers.js";
import { b64, BLOCK, call, challenge, errorCode, LOW, paymentRequired, RESOURCE, session, waitFor, world, type ToolResult } from "./merchant.js";

/** The refusal while another call checks the payee (or asks the user), before it signs anything. */
const CHECKING =
  /^another call is about to sign an authorization for this payee and resource \(its check of the payee, or the user's decision, is under way\): nothing new is signed until that call signs nothing, or its authorization is accepted or expires$/;
const NOT_ACCEPTED = /^an authorization this server signed for this payee and resource was not accepted, and it can still be settled until \d{4}-\d{2}-\d{2}T[\d:.]+Z: nothing new is signed until then$/;
const GET: RequestInit = { method: "GET", redirect: "manual" };

let issuer: Issuer;
before(async () => {
  issuer = await makeIssuer();
});

/** A latch: `wait` resolves once `open` is called. */
function latch(): { open: () => void; wait: Promise<void> } {
  let open = (): void => undefined;
  const wait = new Promise<void>((resolve) => (open = resolve));
  return { open, wait };
}

/** A resource that never accepts a signed payment (it answers 402 again), and the authorizations it received. */
function withholding() {
  const signed: string[] = [];
  const fetch: typeof globalThis.fetch = async (input) => {
    const signature = (input as Request).headers.get("payment-signature");
    if (signature) signed.push(signature);
    return signature ? json(402, {}, { "PAYMENT-REQUIRED": b64(challenge()) }) : paymentRequired();
  };
  return { fetch, signed };
}

/** A call's result: its response, or what it was refused with. */
const settle = (p: Promise<Response>): Promise<Response | unknown> => p.then(
  (res) => res,
  (err: unknown) => err,
);
const refusedWith = (value: unknown, kind: string): value is PaymentRefused => value instanceof PaymentRefused && value.kind === kind;

describe("payer: a concurrent call to the same payee and site is refused before it buys a check", () => {
  test("three concurrent first calls run the check once and sign once (the reviewer's reproduction)", async () => {
    const merchant = withholding();
    const payer = createPayer({ privateKey: generatePrivateKey(), fetch: merchant.fetch });
    const decided = latch();
    let checks = 0;
    const authorize: PaymentAuthorizer = async () => {
      checks++;
      await decided.wait;
      return undefined;
    };
    const results: unknown[] = [];
    const calls = [0, 1, 2].map(() => settle(payer.payResource(RESOURCE, GET, { authorize })).then((v) => (results.push(v), v)));
    try {
      await waitFor(() => results.length >= 2 || checks >= 2, "two calls refused, or a second check started");
      assert.equal(checks, 1, "one check, for the call that may sign; before, each call bought its own");
    } finally {
      decided.open();
    }
    await Promise.all(calls);
    const refused = results.filter((r) => refusedWith(r, "authorization_outstanding")) as PaymentRefused[];
    assert.equal(refused.length, 2);
    for (const r of refused) assert.match(r.message, CHECKING);
    assert.deepEqual(
      results.filter((r) => r instanceof Response).map((r) => (r as Response).status),
      [402],
      "the one call that signed got the resource's answer",
    );
    assert.equal(merchant.signed.length, 1);
    assert.equal(checks, 1);
  });

  test("a call that signs nothing gives the key back: refused by its check, or cancelled during it", async () => {
    for (const how of ["refused", "cancelled"] as const) {
      const merchant = withholding();
      const payer = createPayer({ privateKey: generatePrivateKey(), fetch: merchant.fetch });
      const decided = latch();
      const controller = new AbortController();
      let checking = false;
      const first = settle(
        payer.payResource(RESOURCE, GET, {
          authorize: async () => {
            checking = true;
            await decided.wait;
            return how === "refused" ? "block" : undefined;
          },
          signal: controller.signal,
        }),
      );
      try {
        await waitFor(() => checking, "the first call's check to start");
        // While it runs, another call is refused without a check of its own.
        let asked = false;
        const second = await settle(payer.payResource(RESOURCE, GET, { authorize: async () => ((asked = true), undefined) }));
        assert.ok(refusedWith(second, "authorization_outstanding"), how);
        assert.match((second as PaymentRefused).message, CHECKING);
        assert.equal(asked, false, `${how}: the refused call bought no check`);
        if (how === "cancelled") controller.abort();
      } finally {
        decided.open();
      }
      assert.ok(refusedWith(await first, how === "refused" ? "not_authorized" : "cancelled"), how);
      assert.equal(merchant.signed.length, 0, `${how}: nothing was signed`);
      // The key was given back: the next call checks, signs and sends its own.
      const next = await payer.payResource(RESOURCE, GET, { authorize: async () => undefined });
      assert.equal(next.status, 402, how);
      assert.equal(merchant.signed.length, 1, how);
    }
  });
});

describe("payer: a call signs only while the record is still its own", () => {
  /** Runs `body` with the clock moved forward by `seconds` (only Date.now: timers are untouched). */
  async function later<T>(seconds: number, body: () => Promise<T>): Promise<T> {
    const realNow = Date.now;
    Date.now = () => realNow() + seconds * 1000;
    try {
      return await body();
    } finally {
      Date.now = realNow;
    }
  }

  test("a record that lapsed during a long check, and that another call took meanwhile, is not signed over", async () => {
    // The record a call takes before its check holds the key for at most 15 minutes. A check (or a
    // user's decision) that outlasts it lets another call take the key; the first call must then
    // sign nothing, so one key still never holds two settleable authorizations.
    const merchant = withholding();
    const payer = createPayer({ privateKey: generatePrivateKey(), fetch: merchant.fetch });
    const decidedA = latch();
    const decidedB = latch();
    let startedA = false;
    let startedB = false;
    const a = settle(payer.payResource(RESOURCE, GET, { authorize: async () => ((startedA = true), await decidedA.wait, undefined) }));
    try {
      await waitFor(() => startedA, "A's check to start");
      await later(901, async () => {
        const b = settle(payer.payResource(RESOURCE, GET, { authorize: async () => ((startedB = true), await decidedB.wait, undefined) }));
        await waitFor(() => startedB, "B's check to start: A's record had lapsed");
        decidedA.open();
        const resultA = await a;
        assert.ok(refusedWith(resultA, "authorization_outstanding"), "A's check ended after B took the key: A signs nothing");
        assert.match((resultA as PaymentRefused).message, CHECKING);
        decidedB.open();
        const resultB = await b;
        assert.equal((resultB as Response).status, 402, "B signed and sent its authorization");
      });
    } finally {
      decidedA.open();
      decidedB.open();
    }
    assert.equal(merchant.signed.length, 1);
  });

  test("a record that lapsed during a long check, with the key still free, is taken again for the signature", async () => {
    const merchant = withholding();
    const payer = createPayer({ privateKey: generatePrivateKey(), fetch: merchant.fetch });
    const decided = latch();
    let started = false;
    const a = settle(payer.payResource(RESOURCE, GET, { authorize: async () => ((started = true), await decided.wait, undefined) }));
    try {
      await waitFor(() => started, "A's check to start");
      await later(901, async () => {
        decided.open();
        assert.equal(((await a) as Response).status, 402, "A signed: nobody else held the key");
        // A's signed authorization holds the key again: the next call signs nothing.
        const next = await settle(payer.payResource(RESOURCE, GET, { authorize: async () => undefined }));
        assert.ok(refusedWith(next, "authorization_outstanding"));
        assert.match((next as PaymentRefused).message, NOT_ACCEPTED);
      });
    } finally {
      decided.open();
    }
    assert.equal(merchant.signed.length, 1);
  });
});

describe("x402check_pay: concurrent calls buy one check", () => {
  const message = (r: ToolResult): string => String((r.structuredContent?.error as { message?: string } | undefined)?.message);
  const outcome = (r: ToolResult): string => `${String(r.structuredContent?.outcome)}${errorCode(r) ? `/${errorCode(r)}` : ""}`;

  test("while one call's check runs, the others are refused without a check, and the call that was checked pays", async () => {
    const checking = latch();
    const w = world(issuer, {
      onCheck: async () => {
        await checking.wait;
        return undefined;
      },
      merchant: (c) => (c.paid ? json(402, {}, { "PAYMENT-REQUIRED": b64(challenge()) }) : paymentRequired()),
    });
    const s = await session({ payerKey: generatePrivateKey(), fetch: w.fetch });
    try {
      const done: ToolResult[] = [];
      const calls = [0, 1, 2].map(() => call(s.client, "x402check_pay", { url: RESOURCE }).then((r) => (done.push(r), r)));
      try {
        await waitFor(() => done.length >= 2 || w.checks.length >= 2, "two calls refused, or a second check bought", 5000);
        assert.equal(w.checks.length, 1, "one check is bought; before, every concurrent call bought one");
      } finally {
        checking.open();
      }
      await Promise.all(calls);
      for (const r of done.slice(0, 2)) {
        assert.equal(outcome(r), "refused/authorization_outstanding");
        assert.equal(r.structuredContent?.payment_sent, false);
        assert.match(message(r), CHECKING);
        assert.match(r.text, /^x402check_pay: REFUSED\. Nothing was signed or paid\./);
        assert.match(r.text, /Next: nothing new was signed\. Another payment from this server to this payee on this site is under way/);
      }
      assert.equal(outcome(done[2] as ToolResult), "payment_rejected");
      assert.equal(w.checks.length, 1);
      assert.equal(w.payments().length, 1);
    } finally {
      await s.close();
    }
  });

  test("a call whose payee is blocked gives the key back: the next call is checked and pays", async () => {
    const checking = latch();
    let n = 0;
    const w = world(issuer, {
      decide: () => (n++ === 0 ? BLOCK : LOW),
      onCheck: async () => {
        await checking.wait;
        return undefined;
      },
    });
    const s = await session({ payerKey: generatePrivateKey(), fetch: w.fetch });
    try {
      const first = call(s.client, "x402check_pay", { url: RESOURCE });
      let during: ToolResult;
      try {
        await waitFor(() => w.checks.length === 1, "the first call's check to start");
        during = await call(s.client, "x402check_pay", { url: RESOURCE });
      } finally {
        checking.open();
      }
      assert.equal(outcome(during), "refused/authorization_outstanding");
      assert.equal(outcome(await first), "refused/blocked");
      const next = await call(s.client, "x402check_pay", { url: RESOURCE });
      assert.equal(outcome(next), "paid", next.text);
      assert.equal(w.checks.length, 2, "the blocked call's check and the next call's");
      assert.equal(w.payments().length, 1);
    } finally {
      await s.close();
    }
  });
});
