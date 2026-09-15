import type { DetectorMatch, PIIDetector } from "../core/types.js";

const JWT_REGEX = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g;
const URL_CREDENTIALS_REGEX = /\b[a-z][a-z0-9+.-]*:\/\/[^/\s:@]+:[^/\s@]+@[^/\s]+/gi;
const BEARER_REGEX = /\bBearer\s+[A-Za-z0-9._~+/-]{16,}={0,2}\b/gi;
const NAMED_SECRET_REGEX =
  /\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|secret|client[_-]?secret|password)\s*[:=]\s*["']?[A-Za-z0-9._~+/-]{8,}={0,2}["']?/gi;
const KEY_PREFIX_REGEX = /\b(?:sk|pk|rk|ghp|gho|github_pat|xoxb|xoxp)_[A-Za-z0-9_-]{16,}\b/g;

function matches(regex: RegExp, input: string, type: string, confidence: number): DetectorMatch[] {
  return Array.from(input.matchAll(regex), (match) => ({
    type,
    start: match.index ?? 0,
    end: (match.index ?? 0) + match[0].length,
    confidence
  }));
}

export const secretsDetector: PIIDetector = {
  id: "secrets",
  detect(input) {
    return [
      ...matches(JWT_REGEX, input, "jwt", 0.98),
      ...matches(URL_CREDENTIALS_REGEX, input, "url-credentials", 0.96),
      ...matches(BEARER_REGEX, input, "token", 0.95),
      ...matches(NAMED_SECRET_REGEX, input, "secret", 0.9),
      ...matches(KEY_PREFIX_REGEX, input, "api-key", 0.92)
    ];
  }
};
