import { normalizeFieldName } from "../core/path.js";
import type { DetectorMatch, PIIDetector } from "../core/types.js";
import { isValidLuhn } from "../utils/luhn.js";

const SSN_REGEX = /\b(?!000|666|9\d\d)(\d{3})[- ]?(?!00)(\d{2})[- ]?(?!0000)(\d{4})\b/g;
const NPI_REGEX = /\b\d{10}\b/g;
const MRN_LABEL_REGEX = /\b(?:MRN|medical\s+record(?:\s+number)?|patient\s+id)\s*[:#-]?\s*([A-Z0-9][A-Z0-9-]{5,20})\b/gi;

export const healthDetector: PIIDetector = {
  id: "health",
  detect(input, context) {
    return [
      ...ssnMatches(input),
      ...npiMatches(input, context.path),
      ...medicalRecordMatches(input)
    ];
  }
};

function ssnMatches(input: string): DetectorMatch[] {
  return Array.from(input.matchAll(SSN_REGEX), (match) => ({
    type: "ssn",
    start: match.index ?? 0,
    end: (match.index ?? 0) + match[0].length,
    confidence: 0.9
  }));
}

function npiMatches(input: string, path: readonly (string | number)[]): DetectorMatch[] {
  const contextSuggestsNpi = path.some((segment) => typeof segment === "string" && normalizeFieldName(segment) === "npi");

  return Array.from(input.matchAll(NPI_REGEX))
    .filter((match) => isValidNpi(match[0]) && (contextSuggestsNpi || hasNpiLabel(input, match.index ?? 0)))
    .map((match) => ({
      type: "npi",
      start: match.index ?? 0,
      end: (match.index ?? 0) + match[0].length,
      confidence: contextSuggestsNpi ? 0.96 : 0.9
    }));
}

function medicalRecordMatches(input: string): DetectorMatch[] {
  return Array.from(input.matchAll(MRN_LABEL_REGEX)).map((match) => {
    const record = match[1] as string;
    const matchStart = match.index ?? 0;
    const captureStart = matchStart + match[0].lastIndexOf(record);

    return {
      type: "medical-record-number",
      start: captureStart,
      end: captureStart + record.length,
      confidence: 0.88
    };
  });
}

function isValidNpi(value: string): boolean {
  return isValidLuhn(`80840${value.slice(0, 9)}${value.slice(9)}`);
}

function hasNpiLabel(input: string, start: number): boolean {
  const before = input.slice(Math.max(0, start - 12), start);
  return /\bNPI\s*[:#-]?\s*$/i.test(before);
}
