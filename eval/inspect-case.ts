import { generateRedTeamCorpus } from "./redteam-cases.js";
import { generateCorpus } from "./scale-cases.js";

const ids = process.argv.slice(2);
const rt = generateRedTeamCorpus(300, 31337);
const scale = generateCorpus({ perCategory: 20, seed: 555001 });
for (const id of ids) {
  const c = rt.find((x) => x.id === id) ?? scale.find((x) => x.id === id);
  if (!c) {
    console.log(`--- ${id}: not found`);
    continue;
  }
  const request = "strategy" in c ? c.request : c.request;
  console.log(`--- ${id} | ${"strategy" in c ? `${c.family}/${c.strategy}` : `scale/${c.category}`}`);
  if (request.domain) console.log(`   domain: ${request.domain}`);
  console.log(`   context: ${(request.context ?? "(none)").slice(0, 140)}`);
}
