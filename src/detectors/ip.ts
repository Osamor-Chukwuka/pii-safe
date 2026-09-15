import type { PIIDetector } from "../core/types.js";

const IPV4_REGEX =
  /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;
const IPV6_REGEX = /\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}\b/gi;

export const ipDetector: PIIDetector = {
  id: "ip",
  detect(input) {
    return [
      ...Array.from(input.matchAll(IPV4_REGEX), (match) => ({
        type: "ip-address",
        start: match.index ?? 0,
        end: (match.index ?? 0) + match[0].length,
        confidence: 0.94
      })),
      ...Array.from(input.matchAll(IPV6_REGEX), (match) => ({
        type: "ip-address",
        start: match.index ?? 0,
        end: (match.index ?? 0) + match[0].length,
        confidence: 0.88
      }))
    ];
  }
};
