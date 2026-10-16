// The associated token account derivation (deploy/svm-ata.ts) against @solana/spl-token's
// getAssociatedTokenAddressSync. On 2026-10-16, after the move to @noble/curves 2, it matched
// spl-token on 400 random owners and mints (both token programs); these vectors keep it pinned.
import { test } from "node:test";
import assert from "node:assert/strict";
import { associatedTokenAccount, isAssociatedTokenAccount } from "../deploy/svm-ata.js";
import { base58Decode } from "../src/address-codec.js";

const TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
// [owner, mint, token program, the ATA spl-token derives]
const VECTORS: ReadonlyArray<readonly [string, string, string, string]> = [
  ["EmHUnteENbaYEHE8CCvsgvPRGrkgXxKoUcL2cSjPGtJ6", "DK8qoUUQPKQtygta2wRAUswqfoaQjay4meQAq3MpdYHJ", TOKEN, "4kzKtDfPkCbcftSJnbwRsv1FSPKPMuLgYSMfZjzSv3WL"],
  ["DKNaKXRTihNjrhUUPP5U3nocTfczq6mFXTCxkbAxvg5H", "BTFxwZcBpJHSNzhUaZreT2PSergSSb8HLm37qbpfocbS", TOKEN_2022, "2ZhH8USTqu3xe3SiaHhNrYv1QvUJFiJiFoxuSvYKmb5z"],
  ["Coe25kf65jPdW3fFvugToMpQcjoaMf58avKe52hrcgdj", "F6ywbETTW89U56Js7jKVeGRMp53bgSqef4BcNX3txv3g", TOKEN, "9u79TyKJT2HbvwkZNmbfupZepU7n3XcGMuTPYGaRFmY6"],
  ["7GfNSWpWGrtEJCgJY7xigkiQH6AAimBfTF2qYYY4EnzZ", "7m2CJRk5hKUsjcpQiE4zV96WYCCajrpiNs2dXBEeczbv", TOKEN_2022, "94LmXeXGumrzPvB2LeZKXuLoouFpAHbH4wMS5q6tLUhv"],
];

test("the derived associated token account is the one spl-token derives", () => {
  for (const [owner, mint, program, ata] of VECTORS) {
    assert.deepEqual(associatedTokenAccount(owner, mint, program), base58Decode(ata), `${owner} / ${mint}`);
    assert.equal(isAssociatedTokenAccount(ata, owner, mint, program), true);
    // Another owner's account, or the same owner under the other token program, is not it.
    assert.equal(isAssociatedTokenAccount(ata, VECTORS[(VECTORS.findIndex((v) => v[3] === ata) + 1) % VECTORS.length]![0], mint, program), false);
    assert.equal(isAssociatedTokenAccount(ata, owner, mint, program === TOKEN ? TOKEN_2022 : TOKEN), false);
  }
  assert.equal(associatedTokenAccount("not-base58!", VECTORS[0]![1], TOKEN), null);
});
