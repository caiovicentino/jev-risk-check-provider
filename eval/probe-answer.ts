import { GatewayJevClient } from "../src/backends/gateway.js";
import { buildQuestions, buildState } from "../src/jev.js";
import { CASES } from "./cases.js";

const client = new GatewayJevClient();
const ids = process.argv.slice(2);
const cases = ids.length > 0 ? CASES.filter((c) => ids.includes(c.id)) : CASES.slice(0, 1);
for (const c of cases) {
  const r = await client.systemOne(buildState(c.request), buildQuestions());
  console.log(`=== ${c.id} (expected=${c.expected}) ===`);
  console.log(JSON.stringify(r.answers, null, 1));
}
