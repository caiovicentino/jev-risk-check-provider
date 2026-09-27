import { generateText } from "ai";

const candidates = ["openai/gpt-4.1-mini", "anthropic/claude-3-5-haiku", "google/gemini-2.0-flash"];
for (const model of candidates) {
  try {
    const r = await generateText({ model, prompt: 'Reply with exactly: OK' });
    console.log(`available: ${model} -> ${r.text.trim().slice(0, 20)}`);
  } catch (err) {
    console.log(`unavailable: ${model} -> ${String(err).slice(0, 120)}`);
  }
}
