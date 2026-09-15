import { resolveGuard, type GuardInput } from "../core/resolve.js";

export type WinstonInfo = Record<string, unknown>;
export type WinstonFormatFactory = (transform: (info: WinstonInfo) => WinstonInfo) => () => unknown;

export function redactWinstonInfo<TInfo extends WinstonInfo>(info: TInfo, guardInput?: GuardInput): TInfo {
  const guard = resolveGuard(guardInput);
  return guard.sanitize(info).value;
}

export function createWinstonRedactionFormat(
  format: WinstonFormatFactory,
  guardInput?: GuardInput
): unknown {
  const guard = resolveGuard(guardInput);

  return format((info) => guard.sanitize(info).value as WinstonInfo)();
}
