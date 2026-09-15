import assert from "node:assert/strict";
import test from "node:test";
import {
  createPinoSerializer,
  createWinstonRedactionFormat,
  pinoPIIGuard,
  redactWinstonInfo,
  safeLogger,
  sanitizeMessages,
  sanitizePrompt
} from "../dist/index.js";

test("sanitizes LLM prompts and message arrays", () => {
  const prompt = sanitizePrompt("Write to ada@example.com");
  const messages = sanitizeMessages([
    { role: "user", content: "my phone is +1 415 555 2671" }
  ]);

  assert.equal(prompt.value, "Write to [REDACTED]");
  assert.equal(messages.value[0].content, "my phone is [REDACTED]");
});

test("wraps generic logger methods", () => {
  const calls = [];
  const logger = safeLogger({
    info(...args) {
      calls.push(args);
    }
  });

  logger.info("ada@example.com", { password: "secret" });

  assert.deepEqual(calls, [["[REDACTED]", { password: "[REDACTED]" }]]);
});

test("provides Pino serializer and hook helpers", () => {
  const serializer = createPinoSerializer();
  const pino = pinoPIIGuard();
  const args = [];

  assert.deepEqual(serializer({ apiKey: "secret" }), { apiKey: "[REDACTED]" });
  pino.hooks.logMethod.call({}, ["ada@example.com"], (...methodArgs) => args.push(methodArgs));
  assert.deepEqual(args, [["[REDACTED]"]]);
});

test("provides Winston transform helpers", () => {
  const info = redactWinstonInfo({ message: "ada@example.com", token: "secret" });
  const formatFactory = (transform) => () => ({
    transform
  });
  const redactionFormat = createWinstonRedactionFormat(formatFactory);

  assert.deepEqual(info, { message: "[REDACTED]", token: "[REDACTED]" });
  assert.deepEqual(redactionFormat.transform({ message: "ada@example.com" }), { message: "[REDACTED]" });
});
