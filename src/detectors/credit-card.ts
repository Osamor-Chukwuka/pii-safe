import type { PIIDetector } from "../core/types.js";
import { isValidLuhn } from "../utils/luhn.js";

const CARD_REGEX = /\b(?:\d[ -]?){13,19}\b/g;

export const creditCardDetector: PIIDetector = {
  id: "credit-card",
  detect(input) {
    return Array.from(input.matchAll(CARD_REGEX))
      .filter((match) => isValidLuhn(match[0]))
      .map((match) => ({
        type: "credit-card",
        start: match.index ?? 0,
        end: (match.index ?? 0) + match[0].length,
        confidence: 0.99
      }));
  }
};
