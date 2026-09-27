import { createServer } from "node:http";
import { verifyVoucher, type Voucher } from "./voucher.js";

const PORT = Number(process.env.FACILITATOR_PORT ?? 8788);
const PROVIDER_CHECK_URL = process.env.PROVIDER_CHECK_URL ?? "http://localhost:8787/v1/risk-check";
const MIN_SCORE = 65;

type VerifyRequest = {
  voucher: Voucher;
  signature: string;
  payer_public_pem: string;
  operation_context: string;
  payer_domain?: string;
  screening?: { sanctions: "clean" | "flagged" | "unknown" };
  authorization?: { pre_authorized: boolean; source?: string };
};

type RiskCheckResult = {
  checked: boolean;
  score?: number;
  tier?: string;
  provider?: string;
  categories?: string[];
  jws?: string;
  jwks_url?: string;
  checked_at?: string;
  expires_at?: string;
};

const server = createServer(async (req, res) => {
  if (req.method !== "POST" || req.url !== "/verify") {
    res.statusCode = 404;
    res.end(JSON.stringify({ error: "not_found" }));
    return;
  }
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  let body: VerifyRequest;
  try {
    body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    res.statusCode = 400;
    res.end(JSON.stringify({ isValid: false, invalidReason: "malformed_request" }));
    return;
  }

  const voucherCheck = verifyVoucher(body.voucher, body.signature, body.payer_public_pem);
  if (!voucherCheck.ok) {
    res.statusCode = 200;
    res.end(JSON.stringify({ isValid: false, invalidReason: voucherCheck.reason }));
    return;
  }

  const checkRes = await fetch(PROVIDER_CHECK_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      wallet: body.voucher.payer,
      chain: "solana",
      domain: body.payer_domain,
      context: body.operation_context,
      aud: body.voucher.resource,
      screening: body.screening,
      authorization: body.authorization,
    }),
  });
  const riskCheck = (await checkRes.json()) as RiskCheckResult;

  if (!riskCheck.checked) {
    res.statusCode = 200;
    res.end(JSON.stringify({ isValid: false, invalidReason: "risk-check-unavailable" }));
    return;
  }
  if ((riskCheck.score ?? 0) < MIN_SCORE) {
    res.statusCode = 200;
    res.end(JSON.stringify({ isValid: false, invalidReason: "risk-check-failed", extensions: { "risk-check": riskCheck } }));
    return;
  }
  res.statusCode = 200;
  res.end(JSON.stringify({ isValid: true, payer: body.voucher.payer, extensions: { "risk-check": riskCheck } }));
});

server.listen(PORT, () => console.log(`facilitator :${PORT} (verify + risk-check gate, min_score=${MIN_SCORE})`));
