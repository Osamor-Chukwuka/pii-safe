import type { PIIDetector } from "../core/types.js";
import { normalizeFieldName } from "../core/path.js";

const BVN_LABEL_REGEX = /\bBVN\s*[:#-]?\s*\d{11}\b/gi;
const NIN_LABEL_REGEX = /\bNIN\s*[:#-]?\s*\d{11}\b/gi;
const ELEVEN_DIGITS_REGEX = /\b\d{11}\b/g;

function lastFieldName(path: readonly (string | number)[]): string | undefined {
  for (let index = path.length - 1; index >= 0; index -= 1) {
    const segment = path[index];
    if (typeof segment === "string") {
      return normalizeFieldName(segment);
    }
  }

  return undefined;
}

export const nigeriaDetector: PIIDetector = {
  id: "nigeria",
  detect(input, context) {
    const findings = [
      ...Array.from(input.matchAll(BVN_LABEL_REGEX), (match) => ({
        type: "bvn",
        start: match.index ?? 0,
        end: (match.index ?? 0) + match[0].length,
        confidence: 0.9
      })),
      ...Array.from(input.matchAll(NIN_LABEL_REGEX), (match) => ({
        type: "nin",
        start: match.index ?? 0,
        end: (match.index ?? 0) + match[0].length,
        confidence: 0.9
      }))
    ];

    const field = lastFieldName(context.path);
    if (field !== "bvn" && field !== "nin") {
      return findings;
    }

    return [
      ...findings,
      ...Array.from(input.matchAll(ELEVEN_DIGITS_REGEX), (match) => ({
        type: field,
        start: match.index ?? 0,
        end: (match.index ?? 0) + match[0].length,
        confidence: 0.92
      }))
    ];
  }
};
