import { GatewayJevClient } from "../src/backends/gateway.js";
import { generateRedTeamCorpus } from "../eval/redteam-cases.js";

const rt = generateRedTeamCorpus(300, 31337);
const id = process.argv[2] ?? "rt-71";
const c = rt.find((x) => x.id === id);
if (!c) {
  console.error("not found");
  process.exit(1);
}
const providerDecision = process.argv[3] ?? "RISKY";
const op = JSON.stringify({
  wallet: c.request.wallet,
  chain: c.request.chain,
  domain: c.request.domain,
  context: c.request.context,
});
const client = new GatewayJevClient();
const r = await client.systemOne(
  { role: "independent risk reviewer", operation: op, provider_verdict: { decision: providerDecision, score: 25 } },
  {
    verdict_check: {
      type: "choice",
      instructions: "A risk provider examined this operation and returned the verdict shown. Is that verdict correct?",
      criteria: {
        verdict_correct: "The verdict matches what a careful independent reviewer would conclude",
        verdict_wrong: "The verdict is clearly wrong (opposite or badly miscalibrated)",
        cannot_determine: "Not enough information to judge the verdict",
      },
    },
  },
);
console.log(JSON.stringify(r, null, 2));
