import { experimental_evaluate as evaluate } from "ai";
import type { JevQuestions, JevLike, Usage } from "../jev.js";
import type { Answer } from "../types.js";

export type GatewayConfig = {
  model?: string | undefined;
  evaluateImpl?: EvaluateFn | undefined;
};

type GatewayQuestion =
  | { type: "boolean"; instructions: string | object; criteria?: Record<string, string | null> }
  | { type: "choice"; instructions: string | object; criteria: Record<string, string | null> }
  | { type: "score"; instructions: string | object; criteria: string[] };

type GatewayAnswer = {
  type: "boolean" | "choice" | "score";
  probability?: number;
  choice?: string;
  probabilities?: Record<string, number>;
  score?: number;
};

export type EvaluateFn = (args: {
  model: string;
  state: object;
  questions: Record<string, GatewayQuestion>;
  maxRetries?: number;
  abortSignal?: AbortSignal;
}) => Promise<{
  answers: Record<string, GatewayAnswer>;
  usage?: { inputTokens?: number | undefined; outputTokens?: number | undefined };
  response?: { modelId?: string | undefined } | undefined;
}>;

function toGatewayQuestions(questions: JevQuestions): Record<string, GatewayQuestion> {
  const mapped: Record<string, GatewayQuestion> = {};
  for (const [id, q] of Object.entries(questions)) {
    if (q.type === "noul") {
      const entry: { type: "boolean"; instructions: string | object; criteria?: Record<string, string | null> } = {
        type: "boolean",
        instructions: q.instructions,
      };
      if (q.criteria) entry.criteria = q.criteria as Record<string, string | null>;
      mapped[id] = entry;
    } else if (q.type === "choice") {
      mapped[id] = { type: "choice", instructions: q.instructions, criteria: q.criteria as Record<string, string | null> };
    } else {
      mapped[id] = { type: "score", instructions: q.instructions, criteria: q.criteria as string[] };
    }
  }
  return mapped;
}

function toAnswers(raw: Record<string, GatewayAnswer>): Record<string, Answer> {
  const answers: Record<string, Answer> = {};
  for (const [id, a] of Object.entries(raw)) {
    if (a.type === "boolean") {
      answers[id] = { type: "noul", noul: a.probability ?? 0 };
    } else if (a.type === "choice") {
      const probabilities = a.probabilities ?? {};
      const spread = Object.values(probabilities);
      const confidence = spread.length > 0 ? Math.max(...spread) : 0;
      answers[id] = {
        type: "choice",
        choice: a.choice ?? "unclassifiable",
        probabilities,
        confidence,
        ...(spread.length === 0 ? { noCalibration: true } : {}),
      };
    } else {
      const probabilities = a.probabilities ?? {};
      const spread = Object.values(probabilities);
      const confidence = spread.length > 0 ? Math.max(...spread) : 0;
      answers[id] = {
        type: "score",
        score: a.score ?? 2,
        legend: {},
        probabilities,
        confidence,
        noCalibration: true,
      };
    }
  }
  return answers;
}

/**
 * The model's total budget, retries included. A verdict must come back before the SDK's 10 s
 * timeout: past it the caller has given up, and a late verdict would only be charged for.
 */
export const MODEL_DEADLINE_MS = 8000;

export class GatewayJevClient implements JevLike {
  private readonly model: string;
  private readonly evaluateImpl: EvaluateFn;

  constructor(config: GatewayConfig = {}) {
    this.model = config.model ?? "typesafe-ai/jev";
    this.evaluateImpl = config.evaluateImpl ?? (evaluate as unknown as EvaluateFn);
  }

  async systemOne(state: object, questions: JevQuestions): Promise<{ answers: Record<string, Answer>; usage: Usage; modelId?: string | undefined }> {
    const result = await this.evaluateImpl({
      model: this.model,
      state,
      questions: toGatewayQuestions(questions),
      maxRetries: 2,
      abortSignal: AbortSignal.timeout(MODEL_DEADLINE_MS),
    });
    return {
      answers: toAnswers(result.answers as Record<string, GatewayAnswer>),
      usage: { inputTokens: result.usage?.inputTokens ?? 0, outputTokens: result.usage?.outputTokens ?? 0 },
      // The alias ('typesafe-ai/jev') resolves to a revision the vendor may change: record which one answered.
      ...(result.response?.modelId ? { modelId: result.response.modelId } : {}),
    };
  }
}
