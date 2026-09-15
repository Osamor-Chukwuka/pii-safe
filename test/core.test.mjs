import assert from "node:assert/strict";
import test from "node:test";
import { createPIIGuard } from "../dist/index.js";

test("redacts strings and omits raw findings by default", () => {
  const guard = createPIIGuard();
  const result = guard.sanitizeString("Email ada@example.com and card 4111 1111 1111 1111.");

  assert.equal(result.value, "Email [REDACTED] and card [REDACTED].");
  assert.deepEqual(
    result.findings.map((finding) => finding.type),
    ["email", "credit-card"]
  );
  assert.equal(result.findings.some((finding) => "raw" in finding), false);
});

test("can include raw findings only when requested", () => {
  const guard = createPIIGuard();
  const result = guard.scan("ada@example.com", { includeRawFindings: true });

  assert.equal(result.findings[0].raw, "ada@example.com");
});

test("redacts nested sensitive fields and detected values without mutating input", () => {
  const guard = createPIIGuard();
  const input = {
    user: {
      firstName: "Ada",
      profile: {
        contact: "Reach me at ada@example.com"
      }
    },
    tags: ["public", "api_key=piiguard_fixture_1234567890"]
  };

  const result = guard.sanitize(input);

  assert.equal(input.user.firstName, "Ada");
  assert.equal(result.value.user.firstName, "[REDACTED]");
  assert.equal(result.value.user.profile.contact, "Reach me at [REDACTED]");
  assert.equal(result.value.tags[1], "[REDACTED]");
  assert.equal(result.findings.some((finding) => finding.path === "$.user.firstName"), true);
});

test("supports deterministic tokenization", () => {
  const guard = createPIIGuard({ mode: "tokenize", tokenSalt: "project-a" });
  const one = guard.sanitizeString("ada@example.com ada@example.com").value;
  const two = guard.sanitizeString("ada@example.com").value;

  assert.match(one, /^\[EMAIL:[a-f0-9]{8}\] \[EMAIL:[a-f0-9]{8}\]$/);
  assert.equal(one.split(" ")[0], one.split(" ")[1]);
  assert.equal(two, one.split(" ")[0]);
});

test("supports custom detectors and custom sensitive fields", () => {
  const employeeDetector = {
    id: "employee-id",
    detect(input) {
      const match = /\bEMP-\d{4}\b/.exec(input);
      return match ? [{ type: "employee-id", start: match.index, end: match.index + match[0].length }] : [];
    }
  };
  const guard = createPIIGuard({
    detectors: [employeeDetector],
    sensitiveFields: ["motherMaidenName"]
  });

  const result = guard.sanitize({
    note: "employee EMP-1234",
    motherMaidenName: "Private"
  });

  assert.equal(result.value.note, "employee [REDACTED]");
  assert.equal(result.value.motherMaidenName, "[REDACTED]");
});

test("handles Error, Headers, and URL objects", () => {
  const guard = createPIIGuard();
  const error = new Error("failed for ada@example.com");
  error.authorization = "Bearer abcdefghijklmnopqrstuvwxyz";

  const headers = new Headers({
    authorization: "Bearer abcdefghijklmnopqrstuvwxyz",
    "x-note": "ada@example.com"
  });
  const url = new URL("https://user:pass@example.com/path");

  const errorResult = guard.sanitize(error);
  const headersResult = guard.sanitize(headers);
  const urlResult = guard.sanitize(url);

  assert.equal(errorResult.value.message, "failed for [REDACTED]");
  assert.equal(errorResult.value.authorization, "[REDACTED]");
  assert.equal(headersResult.value.get("authorization"), "[REDACTED]");
  assert.equal(headersResult.value.get("x-note"), "[REDACTED]");
  assert.equal(urlResult.value.username, "%5BREDACTED%5D");
  assert.equal(urlResult.value.password, "");
});

test("detects Nigerian BVN and NIN conservatively", () => {
  const guard = createPIIGuard();
  const result = guard.sanitize({
    bvn: "12345678901",
    note: "NIN: 10987654321",
    randomNumber: "12345678901"
  });

  assert.equal(result.value.bvn, "[REDACTED]");
  assert.equal(result.value.note, "[REDACTED]");
  assert.equal(result.value.randomNumber, "12345678901");
});
