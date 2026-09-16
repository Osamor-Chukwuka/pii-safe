import { normalizeFieldName } from "./path.js";
import type { DetectorId, GuardOptions, PIIType, ScanOptions } from "./types.js";

export interface AllowPolicy {
  allowTypes: Set<string>;
  allowDetectors: Set<string>;
  allowFields: Set<string>;
}

export interface AllowPolicyOptions {
  allowTypes?: PIIType[];
  allowDetectors?: DetectorId[];
  allowFields?: string[];
}

export function createAllowPolicy(options: AllowPolicyOptions = {}): AllowPolicy {
  return {
    allowTypes: new Set(options.allowTypes ?? []),
    allowDetectors: new Set(options.allowDetectors ?? []),
    allowFields: new Set((options.allowFields ?? []).map(normalizeFieldName))
  };
}

export function mergeAllowPolicy(base: AllowPolicy, options: ScanOptions = {}): AllowPolicy {
  return {
    allowTypes: new Set([...base.allowTypes, ...(options.allowTypes ?? [])]),
    allowDetectors: new Set([...base.allowDetectors, ...(options.allowDetectors ?? [])]),
    allowFields: new Set([...base.allowFields, ...(options.allowFields ?? []).map(normalizeFieldName)])
  };
}

export function isAllowedMatch(type: string, detector: string, policy: AllowPolicy): boolean {
  return policy.allowTypes.has(type) || policy.allowDetectors.has(detector);
}

export function isAllowedField(field: string, policy: AllowPolicy): boolean {
  return policy.allowFields.has(normalizeFieldName(field));
}

export function hasAllowPolicy(options: GuardOptions | ScanOptions): boolean {
  return Boolean(
    options.allowTypes?.length ||
      options.allowDetectors?.length ||
      options.allowFields?.length
  );
}
