import type { GuardOptions, PIIGuard, RedactOptions, RedactionReport, SanitizeResult, ScanOptions } from "./types.js";

export function createPIIGuard(_options: GuardOptions = {}): PIIGuard {
  return {
    scan(_value: unknown, _scanOptions?: ScanOptions): RedactionReport {
      return { findings: [] };
    },
    redact<T>(value: T, _redactOptions?: RedactOptions): SanitizeResult<T> {
      return { value, findings: [] };
    },
    sanitize<T>(value: T, redactOptions?: RedactOptions): SanitizeResult<T> {
      return this.redact(value, redactOptions);
    }
  };
}
