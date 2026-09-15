import { createPIIGuard } from "./guard.js";
import type { GuardOptions, PIIGuard } from "./types.js";

export type GuardInput = PIIGuard | GuardOptions;

export function resolveGuard(input?: GuardInput): PIIGuard {
  if (isGuard(input)) {
    return input;
  }

  return createPIIGuard(input);
}

function isGuard(input: GuardInput | undefined): input is PIIGuard {
  return (
    input !== undefined &&
    typeof input === "object" &&
    "sanitize" in input &&
    "scan" in input &&
    "redact" in input
  );
}
