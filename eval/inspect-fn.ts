import { generateCorpus } from "./scale-cases.js";

const ids = ["scale-impersonation-49", "scale-injection-7", "scale-injection-15", "scale-injection-41", "scale-injection-44"];
const corpus = generateCorpus({ perCategory: 60, seed: 20260927 });
for (const id of ids) {
  const c = corpus.find((x) => x.id === id);
  console.log(`--- ${id}`);
  console.log(`domain: ${c?.request.domain ?? "-"}`);
  console.log(`context: ${(c?.request.context ?? "-").slice(0, 180)}`);
}
