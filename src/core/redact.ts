import { DEFAULT_REPLACEMENT } from "./defaults.js";
import { createFieldFinding, isSensitiveField, scanString, type ScanConfig } from "./scan.js";
import { stableToken } from "./tokenize.js";
import type { Finding, PathSegment, RedactOptions, RedactionMode, SanitizeResult } from "./types.js";

interface RedactConfig extends ScanConfig {
  mode: RedactionMode;
  replacement: string;
  tokenSalt: string | undefined;
}

export function redactValue<T>(value: T, config: RedactConfig, options: RedactOptions = {}): SanitizeResult<T> {
  const findings: Finding[] = [];
  const includeRaw = options.includeRawFindings ?? config.includeRawFindings;
  const mode = options.mode ?? config.mode;
  const replacement = options.replacement ?? config.replacement;
  const seen = new WeakMap<object, unknown>();
  const redacted = redactAny(value, [], findings, { ...config, mode, replacement }, includeRaw, seen);

  return {
    value: redacted as T,
    findings
  };
}

export function redactString(
  input: string,
  path: readonly PathSegment[],
  config: RedactConfig,
  includeRaw = config.includeRawFindings
): SanitizeResult<string> {
  const findings = scanString(input, path, config, includeRaw);
  const sorted = [...findings].sort((left, right) => (right.span?.start ?? 0) - (left.span?.start ?? 0));
  let value = input;

  for (const finding of sorted) {
    if (!finding.span) {
      continue;
    }

    const raw = input.slice(finding.span.start, finding.span.end);
    value =
      value.slice(0, finding.span.start) +
      replacementFor(raw, finding.type, config.mode, config.replacement, config.tokenSalt) +
      value.slice(finding.span.end);
  }

  return { value, findings };
}

function redactAny(
  value: unknown,
  path: PathSegment[],
  findings: Finding[],
  config: RedactConfig,
  includeRaw: boolean,
  seen: WeakMap<object, unknown>
): unknown {
  if (typeof value === "string") {
    const result = redactString(value, path, config, includeRaw);
    findings.push(...result.findings);
    return result.value;
  }

  if (value === null || typeof value !== "object") {
    return value;
  }

  if (seen.has(value)) {
    return seen.get(value);
  }

  if (value instanceof URL) {
    const clone = new URL(value.toString());
    seen.set(value, clone);

    if (clone.username !== "" || clone.password !== "") {
      findings.push(...redactString(value.toString(), path, config, includeRaw).findings);
      clone.username = replacementFor(value.username, "url-credentials", config.mode, config.replacement, config.tokenSalt);
      clone.password = "";
    }

    return clone;
  }

  if (isHeaders(value)) {
    const clone = new Headers();
    seen.set(value, clone);

    value.forEach((headerValue, headerName) => {
      const childPath = [...path, headerName];
      if (isSensitiveField(headerName, config.sensitiveFields)) {
        findings.push(createFieldFinding(headerValue, childPath, includeRaw));
        clone.set(headerName, replacementFor(headerValue, "sensitive-field", config.mode, config.replacement, config.tokenSalt));
        return;
      }

      const result = redactString(headerValue, childPath, config, includeRaw);
      findings.push(...result.findings);
      clone.set(headerName, result.value);
    });

    return clone;
  }

  if (value instanceof Error) {
    const clone = new Error();
    seen.set(value, clone);
    clone.name = value.name;

    const message = redactString(value.message, [...path, "message"], config, includeRaw);
    clone.message = message.value;
    findings.push(...message.findings);

    if (typeof value.stack === "string") {
      const stack = redactString(value.stack, [...path, "stack"], config, includeRaw);
      clone.stack = stack.value;
      findings.push(...stack.findings);
    }

    copyEnumerableProperties(value, clone, path, findings, config, includeRaw, seen);
    return clone;
  }

  if (Array.isArray(value)) {
    const clone: unknown[] = [];
    seen.set(value, clone);
    value.forEach((item, index) => {
      clone[index] = redactAny(item, [...path, index], findings, config, includeRaw, seen);
    });
    return clone;
  }

  const clone: Record<string, unknown> = {};
  seen.set(value, clone);

  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    const childPath = [...path, key];
    if (isSensitiveField(key, config.sensitiveFields)) {
      findings.push(createFieldFinding(child, childPath, includeRaw));
      clone[key] = redactWhole(child, "sensitive-field", config);
      continue;
    }

    clone[key] = redactAny(child, childPath, findings, config, includeRaw, seen);
  }

  return clone;
}

function redactWhole(value: unknown, type: string, config: RedactConfig): unknown {
  if (typeof value === "string") {
    return replacementFor(value, type, config.mode, config.replacement, config.tokenSalt);
  }

  if (Array.isArray(value)) {
    return value.map((item) => redactWhole(item, type, config));
  }

  if (value !== null && typeof value === "object") {
    return config.replacement;
  }

  return config.replacement;
}

function replacementFor(
  raw: string,
  type: string,
  mode: RedactionMode,
  replacement = DEFAULT_REPLACEMENT,
  tokenSalt?: string
): string {
  if (mode === "tokenize") {
    return stableToken(type, raw, tokenSalt);
  }

  if (mode === "mask") {
    return mask(raw);
  }

  return replacement;
}

function mask(raw: string): string {
  const visible = raw.replace(/\s/g, "");
  if (visible.length <= 4) {
    return "*".repeat(Math.max(visible.length, 1));
  }

  return `${visible.slice(0, 2)}${"*".repeat(Math.max(visible.length - 4, 4))}${visible.slice(-2)}`;
}

function copyEnumerableProperties(
  source: Error,
  target: Error,
  path: PathSegment[],
  findings: Finding[],
  config: RedactConfig,
  includeRaw: boolean,
  seen: WeakMap<object, unknown>
): void {
  for (const [key, child] of Object.entries(source as unknown as Record<string, unknown>)) {
    const childPath = [...path, key];
    if (isSensitiveField(key, config.sensitiveFields)) {
      findings.push(createFieldFinding(child, childPath, includeRaw));
      (target as unknown as Record<string, unknown>)[key] = redactWhole(child, "sensitive-field", config);
      continue;
    }

    (target as unknown as Record<string, unknown>)[key] = redactAny(child, childPath, findings, config, includeRaw, seen);
  }
}

function isHeaders(value: object): value is Headers {
  return typeof Headers !== "undefined" && value instanceof Headers;
}
