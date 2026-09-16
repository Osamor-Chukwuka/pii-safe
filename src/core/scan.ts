import { DEFAULT_SENSITIVE_FIELDS } from "./defaults.js";
import { formatPath, normalizeFieldName } from "./path.js";
import { createAllowPolicy, isAllowedField, isAllowedMatch, mergeAllowPolicy, type AllowPolicy } from "./policy.js";
import type { Finding, GuardOptions, PIIDetector, PathSegment, RedactionReport, ScanOptions } from "./types.js";

export interface ScanConfig {
  detectors: PIIDetector[];
  sensitiveFields: Set<string>;
  includeRawFindings: boolean;
  allowPolicy: AllowPolicy;
}

export function createSensitiveFieldSet(fields: readonly string[] = []): Set<string> {
  return new Set([...DEFAULT_SENSITIVE_FIELDS, ...fields].map(normalizeFieldName));
}

export function createScanConfig(options: GuardOptions, builtInDetectors: PIIDetector[]): ScanConfig {
  return {
    detectors: [...builtInDetectors, ...(options.detectors ?? [])],
    sensitiveFields: createSensitiveFieldSet(options.sensitiveFields),
    includeRawFindings: options.includeRawFindings ?? false,
    allowPolicy: createAllowPolicy(options)
  };
}

export function isSensitiveField(field: string, fields: ReadonlySet<string>): boolean {
  return fields.has(normalizeFieldName(field));
}

export function scanValue(value: unknown, config: ScanConfig, options: ScanOptions = {}): RedactionReport {
  const findings: Finding[] = [];
  const includeRaw = options.includeRawFindings ?? config.includeRawFindings;
  const policy = mergeAllowPolicy(config.allowPolicy, options);
  const seen = new WeakSet<object>();

  walk(value, [], findings, config, includeRaw, policy, seen);

  return { findings };
}

export function scanString(
  input: string,
  path: readonly PathSegment[],
  config: ScanConfig,
  includeRaw: boolean,
  policy: AllowPolicy
): Finding[] {
  return config.detectors.flatMap((detector) =>
    detector.detect(input, { path }).map((match) => {
      const allowed = isAllowedMatch(match.type, detector.id, policy);
      const finding: Finding = {
        type: match.type,
        detector: detector.id,
        path: formatPath(path),
        confidence: match.confidence ?? 0.8,
        redacted: !allowed,
        span: {
          start: match.start,
          end: match.end
        },
        length: match.end - match.start
      };

      if (includeRaw) {
        finding.raw = input.slice(match.start, match.end);
      }

      return finding;
    })
  );
}

export function createFieldFinding(
  value: unknown,
  path: readonly PathSegment[],
  includeRaw: boolean,
  redacted = true
): Finding {
  const finding: Finding = {
    type: "sensitive-field",
    detector: "field-name",
    path: formatPath(path),
    confidence: 0.95,
    redacted
  };

  if (typeof value === "string") {
    finding.length = value.length;
    if (includeRaw) {
      finding.raw = value;
    }
  }

  return finding;
}

function walk(
  value: unknown,
  path: PathSegment[],
  findings: Finding[],
  config: ScanConfig,
  includeRaw: boolean,
  policy: AllowPolicy,
  seen: WeakSet<object>
): void {
  if (typeof value === "string") {
    findings.push(...scanString(value, path, config, includeRaw, policy));
    return;
  }

  if (value === null || typeof value !== "object") {
    return;
  }

  if (seen.has(value)) {
    return;
  }

  seen.add(value);

  if (value instanceof URL) {
    findings.push(...scanString(value.toString(), path, config, includeRaw, policy));
    return;
  }

  if (isHeaders(value)) {
    value.forEach((headerValue, headerName) => {
      const childPath = [...path, headerName];
      if (isSensitiveField(headerName, config.sensitiveFields)) {
        findings.push(createFieldFinding(headerValue, childPath, includeRaw, !isAllowedField(headerName, policy)));
      }
      findings.push(...scanString(headerValue, childPath, config, includeRaw, policy));
    });
    return;
  }

  if (value instanceof Error) {
    findings.push(...scanString(value.message, [...path, "message"], config, includeRaw, policy));
    if (typeof value.stack === "string") {
      findings.push(...scanString(value.stack, [...path, "stack"], config, includeRaw, policy));
    }
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => walk(item, [...path, index], findings, config, includeRaw, policy, seen));
    return;
  }

  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    const childPath = [...path, key];
    if (isSensitiveField(key, config.sensitiveFields)) {
      findings.push(createFieldFinding(child, childPath, includeRaw, !isAllowedField(key, policy)));
    }
    walk(child, childPath, findings, config, includeRaw, policy, seen);
  }
}

function isHeaders(value: object): value is Headers {
  return typeof Headers !== "undefined" && value instanceof Headers;
}
