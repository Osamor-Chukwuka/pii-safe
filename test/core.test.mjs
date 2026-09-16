import assert from "node:assert/strict";
import test from "node:test";
import { createPIIGuard } from "../dist/index.js";

test("redacts strings and omits raw findings by default", () => {
  const guard = createPIIGuard();
  const result = guard.sanitizeString("Email ada@example.com, IP 192.168.1.10, and card 4111 1111 1111 1111.");

  assert.equal(result.value, "Email [REDACTED], IP [REDACTED], and card [REDACTED].");
  assert.deepEqual(
    result.findings.map((finding) => finding.type),
    ["email", "credit-card", "ip-address"]
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

test("supports allowlists for types, detectors, and fields", () => {
  const guard = createPIIGuard();
  const result = guard.sanitize(
    {
      email: "ada@example.com",
      note: "email ada@example.com phone +1 415 555 2671",
      auth: "Bearer abcdefghijklmnopqrstuvwxyz"
    },
    {
      allowTypes: ["email"],
      allowFields: ["email"],
      allowDetectors: ["secrets"]
    }
  );

  assert.equal(result.value.email, "ada@example.com");
  assert.equal(result.value.note, "email ada@example.com phone [REDACTED]");
  assert.equal(result.value.auth, "Bearer abcdefghijklmnopqrstuvwxyz");
  assert.equal(result.findings.some((finding) => finding.type === "email" && finding.redacted === false), true);
  assert.equal(result.findings.some((finding) => finding.type === "phone" && finding.redacted === true), true);
  assert.equal(result.findings.some((finding) => finding.detector === "secrets" && finding.redacted === false), true);
});

test("requires field and type allowlists when a sensitive field contains detectable PII", () => {
  const guard = createPIIGuard();
  const fieldOnly = guard.sanitize({ email: "ada@example.com" }, { allowFields: ["email"] });
  const typeOnly = guard.sanitize({ email: "ada@example.com" }, { allowTypes: ["email"] });
  const both = guard.sanitize({ email: "ada@example.com" }, { allowFields: ["email"], allowTypes: ["email"] });

  assert.equal(fieldOnly.value.email, "[REDACTED]");
  assert.equal(typeOnly.value.email, "[REDACTED]");
  assert.equal(both.value.email, "ada@example.com");
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

test("detects conservative fintech identifiers", () => {
  const guard = createPIIGuard();
  const result = guard.sanitize({
    payment: "IBAN GB82 WEST 1234 5698 7654 32",
    note: "routing number 021000021",
    accountNumber: "1234567890"
  });

  assert.equal(result.value.payment, "IBAN [REDACTED]");
  assert.equal(result.value.note, "routing number [REDACTED]");
  assert.equal(result.value.accountNumber, "[REDACTED]");
  assert.equal(result.findings.some((finding) => finding.type === "iban"), true);
  assert.equal(result.findings.some((finding) => finding.type === "bank-routing-number"), true);
});

test("detects conservative health identifiers", () => {
  const guard = createPIIGuard();
  const result = guard.sanitize({
    npi: "1234567893",
    note: "NPI 1234567893 SSN 123-45-6789 MRN ABC-123456",
    randomNumber: "1234567893"
  });

  assert.equal(result.value.npi, "[REDACTED]");
  assert.equal(result.value.note, "NPI [REDACTED] SSN [REDACTED] MRN [REDACTED]");
  assert.equal(result.findings.some((finding) => finding.path === "$.randomNumber" && finding.type === "npi"), false);
  assert.equal(result.findings.some((finding) => finding.type === "npi"), true);
  assert.equal(result.findings.some((finding) => finding.type === "ssn"), true);
  assert.equal(result.findings.some((finding) => finding.type === "medical-record-number"), true);
});

test("allowlisted larger spans protect nested detector matches", () => {
  const guard = createPIIGuard();
  const iban = "GB82 WEST 1234 5698 7654 32";
  const npi = "1234567893";

  const result = guard.sanitizeString(`IBAN ${iban} NPI ${npi}`, {
    allowTypes: ["iban", "npi"]
  });

  assert.equal(result.value, `IBAN ${iban} NPI ${npi}`);
  assert.equal(result.findings.some((finding) => finding.type === "phone" && finding.redacted === true), false);
});
