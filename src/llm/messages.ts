import { resolveGuard, type GuardInput } from "../core/resolve.js";
import type { SanitizeResult } from "../core/types.js";

export interface LLMMessage {
  role: string;
  content?: unknown;
  name?: string;
  tool_call_id?: string;
  [key: string]: unknown;
}

export function sanitizePrompt(prompt: string, guardInput?: GuardInput): SanitizeResult<string> {
  return resolveGuard(guardInput).sanitizeString(prompt);
}

export function sanitizeMessages<TMessage extends LLMMessage>(
  messages: readonly TMessage[],
  guardInput?: GuardInput
): SanitizeResult<TMessage[]> {
  const result = resolveGuard(guardInput).sanitize(messages);
  return {
    value: result.value as TMessage[],
    findings: result.findings
  };
}

export function sanitizeMessage<TMessage extends LLMMessage>(
  message: TMessage,
  guardInput?: GuardInput
): SanitizeResult<TMessage> {
  return resolveGuard(guardInput).sanitize(message);
}
