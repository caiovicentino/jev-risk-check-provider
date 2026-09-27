import { createServer } from "node:http";
import type { RiskCheckExtensionInfo } from "../src/types.js";

const PORT = Number(process.env.RESOURCE_PORT ?? 8789);
const PROVIDER_DISCOVERY = process.env.PROVIDER_DISCOVERY ?? "http://localhost:8787/.well-known/risk-check.json";
const MERCHANT_ACCOUNT = "MerchLab5xPVWDwpRAnN9rPLxnRD8UsG3TDtKtPoi3oiS";

const extension: { "risk-check": { info: RiskCheckExtensionInfo } } = {
  "risk-check": {
    info: {
      required: true,
      risk_check_url: PROVIDER_DISCOVERY,
      min_score: 65,
      categories: ["intent_risk", "behavioral"],
    },
  },
};

const server = createServer((req, res) => {
  if (req.method === "GET" && req.url === "/data") {
    const verified = req.headers["x-payment-verified"] === "1";
    if (verified) {
      res.statusCode = 200;
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ data: "market data feed payload", served_at: new Date().toISOString() }));
      return;
    }
    res.statusCode = 402;
    res.setHeader("Content-Type", "application/json");
    res.end(
      JSON.stringify({
        x402Version: 2,
        error: "Payment required",
        resource: { url: "http://localhost:8789/data", description: "market data feed", mimeType: "application/json" },
        accepts: [
          {
            scheme: "voucher-demo",
            network: "solana:devnet",
            amount: "50000",
            payTo: MERCHANT_ACCOUNT,
            maxTimeoutSeconds: 60,
            extra: { currency: "USDC-demo" },
          },
        ],
        extensions: extension,
      }),
    );
    return;
  }
  res.statusCode = 404;
  res.end(JSON.stringify({ error: "not_found" }));
});

server.listen(PORT, () => console.log(`resource-server :${PORT} (requires risk-check, min_score=65)`));
