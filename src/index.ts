export { createPIIGuard } from "./core/guard.js";
export {
  creditCardDetector,
  emailDetector,
  nigeriaDetector,
  phoneDetector,
  secretsDetector
} from "./detectors/index.js";
export type {
  DetectorContext,
  DetectorMatch,
  Finding,
  GuardOptions,
  PIIDetector,
  PIIGuard,
  RedactOptions,
  RedactionMode,
  RedactionReport,
  SanitizeResult,
  ScanOptions,
  Span
} from "./core/types.js";
