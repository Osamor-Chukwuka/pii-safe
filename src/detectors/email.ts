import type { PIIDetector } from "../core/types.js";

const EMAIL_REGEX = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b/gi;

export const emailDetector: PIIDetector = {
  id: "email",
  detect(input) {
    return Array.from(input.matchAll(EMAIL_REGEX), (match) => ({
      type: "email",
      start: match.index ?? 0,
      end: (match.index ?? 0) + match[0].length,
      confidence: 0.98
    }));
  }
};
