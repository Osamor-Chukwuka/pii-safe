import { builtInDetectors } from "../detectors/index.js";
import { DEFAULT_REPLACEMENT } from "./defaults.js";
import { mergeAllowPolicy } from "./policy.js";
import { redactString, redactValue } from "./redact.js";
import { createScanConfig, scanValue } from "./scan.js";
import type { GuardOptions, PIIGuard, RedactOptions, RedactionReport, SanitizeResult, ScanOptions } from "./types.js";

export function createPIIGuard(options: GuardOptions = {}): PIIGuard {
  const scanConfig = createScanConfig(options, builtInDetectors);
  const redactionConfig = {
    ...scanConfig,
    mode: options.mode ?? "replace",
    replacement: options.replacement ?? DEFAULT_REPLACEMENT,
    tokenSalt: options.tokenSalt
  };

  return {
    scan(value: unknown, scanOptions?: ScanOptions): RedactionReport {
      return scanValue(value, scanConfig, scanOptions);
    },
    redact<T>(value: T, redactOptions?: RedactOptions): SanitizeResult<T> {
      return redactValue(value, redactionConfig, redactOptions);
    },
    sanitize<T>(value: T, redactOptions?: RedactOptions): SanitizeResult<T> {
      return this.redact(value, redactOptions);
    },
    sanitizeString(input: string, redactOptions?: RedactOptions): SanitizeResult<string> {
      const config = {
        ...redactionConfig,
        mode: redactOptions?.mode ?? redactionConfig.mode,
        replacement: redactOptions?.replacement ?? redactionConfig.replacement
      };

      return redactString(
        input,
        [],
        config,
        redactOptions?.includeRawFindings ?? redactionConfig.includeRawFindings,
        mergeAllowPolicy(redactionConfig.allowPolicy, redactOptions)
      );
    }
  };
}
