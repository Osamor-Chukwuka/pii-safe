import type { PathSegment } from "./types.js";

const IDENTIFIER = /^[A-Za-z_$][\w$]*$/;

export function formatPath(path: readonly PathSegment[]): string {
  if (path.length === 0) {
    return "$";
  }

  return path.reduce<string>((formatted, segment) => {
    if (typeof segment === "number") {
      return `${formatted}[${segment}]`;
    }

    if (IDENTIFIER.test(segment)) {
      return `${formatted}.${segment}`;
    }

    return `${formatted}[${JSON.stringify(segment)}]`;
  }, "$");
}

export function normalizeFieldName(field: string): string {
  return field.replace(/[\s_.-]+/g, "").toLowerCase();
}
