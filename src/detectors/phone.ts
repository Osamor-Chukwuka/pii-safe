import type { PIIDetector } from "../core/types.js";

const PHONE_REGEX = /(?:\+?\d[\d ().-]{7,}\d)/g;

function digitCount(value: string): number {
  return value.replace(/\D/g, "").length;
}

function hasVariedDigits(value: string): boolean {
  const digits = value.replace(/\D/g, "");
  return new Set(digits).size > 2;
}

function isBareElevenDigitNumber(value: string): boolean {
  return /^\d{11}$/.test(value.trim());
}

export const phoneDetector: PIIDetector = {
  id: "phone",
  detect(input) {
    return Array.from(input.matchAll(PHONE_REGEX))
      .filter((match) => {
        const digits = digitCount(match[0]);
        return digits >= 10 && digits <= 15 && hasVariedDigits(match[0]) && !isBareElevenDigitNumber(match[0]);
      })
      .map((match) => ({
        type: "phone",
        start: match.index ?? 0,
        end: (match.index ?? 0) + match[0].length,
        confidence: 0.82
      }));
  }
};
