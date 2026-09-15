import { resolveGuard, type GuardInput } from "../core/resolve.js";

export type LogMethod = (...args: unknown[]) => unknown;

export type LoggerLike = Record<string, unknown>;

export interface SafeLoggerOptions {
  methods?: string[];
  guard?: GuardInput;
}

const DEFAULT_LOG_METHODS = [
  "trace",
  "debug",
  "info",
  "warn",
  "error",
  "fatal",
  "log"
];

export function safeLogger<TLogger extends LoggerLike>(
  logger: TLogger,
  guardOrOptions: GuardInput | SafeLoggerOptions = {}
): TLogger {
  const options = isSafeLoggerOptions(guardOrOptions) ? guardOrOptions : { guard: guardOrOptions };
  const guard = resolveGuard(options.guard);
  const methods = new Set(options.methods ?? DEFAULT_LOG_METHODS);

  return new Proxy(logger, {
    get(target, property, receiver) {
      const value = Reflect.get(target, property, receiver);

      if (typeof property !== "string" || !methods.has(property) || typeof value !== "function") {
        return value;
      }

      return (...args: unknown[]) => value.apply(target, args.map((arg) => guard.sanitize(arg).value));
    }
  });
}

export function sanitizeLogArgs(args: readonly unknown[], guardInput?: GuardInput): unknown[] {
  const guard = resolveGuard(guardInput);
  return args.map((arg) => guard.sanitize(arg).value);
}

function isSafeLoggerOptions(input: GuardInput | SafeLoggerOptions): input is SafeLoggerOptions {
  return typeof input === "object" && input !== null && ("methods" in input || "guard" in input);
}
