export type RedactionMode = "replace" | "mask" | "tokenize";

export type PathSegment = string | number;

export type BuiltInFindingType =
  | "api-key"
  | "bvn"
  | "credit-card"
  | "email"
  | "bank-routing-number"
  | "iban"
  | "ip-address"
  | "jwt"
  | "medical-record-number"
  | "nin"
  | "npi"
  | "phone"
  | "secret"
  | "sensitive-field"
  | "token"
  | "url-credentials";

export type BuiltInDetectorId =
  | "credit-card"
  | "email"
  | "finance"
  | "health"
  | "ip"
  | "nigeria"
  | "phone"
  | "secrets";

export type PIIType = BuiltInFindingType | (string & {});
export type DetectorId = BuiltInDetectorId | (string & {});

export interface Span {
  start: number;
  end: number;
}

export interface Finding {
  type: string;
  detector: string;
  path: string;
  confidence: number;
  redacted?: boolean;
  span?: Span;
  length?: number;
  raw?: string;
}

export interface DetectorContext {
  path: readonly PathSegment[];
}

export interface DetectorMatch {
  type: string;
  start: number;
  end: number;
  confidence?: number;
}

export interface PIIDetector {
  id: string;
  detect(input: string, context: DetectorContext): DetectorMatch[];
}

export interface GuardOptions {
  /**
   * Custom detectors are appended after the built-in detector set.
   */
  detectors?: PIIDetector[];
  sensitiveFields?: string[];
  mode?: RedactionMode;
  replacement?: string;
  tokenSalt?: string;
  includeRawFindings?: boolean;
  allowTypes?: PIIType[];
  allowDetectors?: DetectorId[];
  allowFields?: string[];
}

export interface ScanOptions {
  includeRawFindings?: boolean;
  allowTypes?: PIIType[];
  allowDetectors?: DetectorId[];
  allowFields?: string[];
}

export interface RedactOptions extends ScanOptions {
  mode?: RedactionMode;
  replacement?: string;
}

export interface RedactionReport {
  findings: Finding[];
}

export interface SanitizeResult<T> extends RedactionReport {
  value: T;
}

export interface PIIGuard {
  scan(value: unknown, options?: ScanOptions): RedactionReport;
  redact<T>(value: T, options?: RedactOptions): SanitizeResult<T>;
  sanitize<T>(value: T, options?: RedactOptions): SanitizeResult<T>;
  sanitizeString(input: string, options?: RedactOptions): SanitizeResult<string>;
}
