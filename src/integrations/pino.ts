import { resolveGuard, type GuardInput } from "../core/resolve.js";
import { sanitizeLogArgs } from "./logger.js";

export interface PinoPIIGuardOptions {
  guard?: GuardInput;
}

export function pinoPIIGuard(options: PinoPIIGuardOptions | GuardInput = {}) {
  const guard = resolveGuard(isPinoOptions(options) ? options.guard : options);

  return {
    serializers: {
      err: (error: unknown) => guard.sanitize(error).value,
      error: (error: unknown) => guard.sanitize(error).value,
      req: (request: unknown) => guard.sanitize(request).value,
      res: (response: unknown) => guard.sanitize(response).value
    },
    hooks: {
      logMethod(args: unknown[], method: (...methodArgs: unknown[]) => unknown) {
        return method.apply(this, sanitizeLogArgs(args, guard));
      }
    }
  };
}

export function createPinoSerializer(guardInput?: GuardInput) {
  const guard = resolveGuard(guardInput);
  return (value: unknown) => guard.sanitize(value).value;
}

function isPinoOptions(input: PinoPIIGuardOptions | GuardInput): input is PinoPIIGuardOptions {
  return typeof input === "object" && input !== null && "guard" in input;
}
