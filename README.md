# pii-safe

[![npm version](https://img.shields.io/npm/v/pii-safe.svg)](https://www.npmjs.com/package/pii-safe)
[![GitHub](https://img.shields.io/badge/github-Osamor--Chukwuka%2Fpii--safe-181717.svg)](https://github.com/Osamor-Chukwuka/pii-safe)

Local-first PII redaction for LLM prompts, logs, and Node.js apps.

Links: [npm](https://www.npmjs.com/package/pii-safe) | [GitHub](https://github.com/Osamor-Chukwuka/pii-safe)

## Install

```bash
npm install pii-safe
```

## Why pii-safe?

pii-safe helps remove sensitive values before they reach LLM calls, logs, error reports, analytics, or other places where raw personal data should not go.

- Local-only detection, no external API calls.
- TypeScript-first API.
- Works with strings, nested objects, arrays, `Error`, `Headers`, and `URL`.
- Built-in LLM, generic logger, Pino, and Winston helpers.
- Returns both sanitized values and a findings report.
- Findings do not include raw PII by default.

## Quick Start

```ts
import { createPIIGuard } from "pii-safe";

const guard = createPIIGuard();

const result = guard.sanitize({
  email: "ada@example.com",
  note: "card 4111 1111 1111 1111"
});

console.log(result.value);
// { email: "[REDACTED]", note: "card [REDACTED]" }

console.log(result.findings);
// [{ type: "sensitive-field", detector: "field-name", path: "$.email", ... }]
```

## Core API

```ts
const guard = createPIIGuard(options);

guard.scan(value);
guard.redact(value);
guard.sanitize(value);
guard.sanitizeString(input);
```

`sanitize` and `redact` are equivalent. They return:

```ts
{
  value: sanitizedValue,
  findings: [
    {
      type: "email",
      detector: "email",
      path: "$.user.email",
      confidence: 0.98,
      span: { start: 0, end: 15 },
      length: 15
    }
  ]
}
```

Raw PII is never included in findings by default. You can opt in when debugging locally:

```ts
guard.scan("ada@example.com", { includeRawFindings: true });
```

## Options

```ts
const guard = createPIIGuard({
  mode: "replace",
  replacement: "[PRIVATE]",
  tokenSalt: "my-app",
  sensitiveFields: ["employeeId"],
  detectors: [customDetector],
  includeRawFindings: false
});
```

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `mode` | `"replace" \| "mask" \| "tokenize"` | `"replace"` | Controls how detected values are redacted. |
| `replacement` | `string` | `"[REDACTED]"` | Replacement text for replace mode. |
| `tokenSalt` | `string` | `undefined` | Salt used for deterministic tokenize mode. |
| `sensitiveFields` | `string[]` | built-in list | Extra object field names to redact wholesale. |
| `detectors` | `PIIDetector[]` | built-in detectors | Custom detectors appended after the built-ins. |
| `includeRawFindings` | `boolean` | `false` | Whether findings may include raw matched values. |
| `allowTypes` | `string[]` | `[]` | Finding types to detect but leave unredacted. |
| `allowDetectors` | `string[]` | `[]` | Detector IDs to detect but leave unredacted. |
| `allowFields` | `string[]` | `[]` | Sensitive field names to leave unredacted. |

## Redaction Modes

```ts
createPIIGuard({ mode: "replace" });
// ada@example.com -> [REDACTED]

createPIIGuard({ mode: "mask" });
// ada@example.com -> ad*********om

createPIIGuard({ mode: "tokenize", tokenSalt: "app-a" });
// ada@example.com -> [EMAIL:1a2b3c4d]
```

Tokenization is deterministic for the same value, type, and salt. It is useful when you want to correlate repeated values without storing the original value.

## Allowlists

Sometimes an LLM call needs one identifier while everything else should still be redacted. For example, a search prompt may need an email address but not a phone number, token, or password.

Use per-call allowlists:

```ts
const result = guard.sanitize(
  {
    email: "ada@example.com",
    phone: "+1 415 555 2671",
    token: "Bearer abcdefghijklmnopqrstuvwxyz"
  },
  {
    allowTypes: ["email"],
    allowFields: ["email"]
  }
);

console.log(result.value);
// {
//   email: "ada@example.com",
//   phone: "[REDACTED]",
//   token: "[REDACTED]"
// }
```

You can also set default allowlists on the guard:

```ts
const guard = createPIIGuard({
  allowTypes: ["email"],
  allowFields: ["email"]
});
```

Allowlist controls:

- `allowTypes`: allow a finding type, such as `email`, `iban`, or `npi`.
- `allowDetectors`: allow everything from a detector, such as `email`, `finance`, or `health`.
- `allowFields`: allow sensitive object fields by name, such as `email`.

For object fields, you may need both field and type allowlists:

```ts
guard.sanitize(
  { email: "ada@example.com" },
  { allowFields: ["email"], allowTypes: ["email"] }
);
```

Findings include `redacted: false` when a detected value was intentionally allowed.

## LLM Helpers

```ts
import { sanitizeMessages, sanitizePrompt } from "pii-safe";

const prompt = sanitizePrompt("Email ada@example.com about this ticket");

const messages = sanitizeMessages([
  { role: "user", content: "My phone is +1 415 555 2671" }
]);
```

Both helpers return `{ value, findings }`.

## Generic Logger

```ts
import { safeLogger } from "pii-safe";

const logger = safeLogger(console);

logger.info("User email: ada@example.com");
logger.error(new Error("Failed for ada@example.com"));
```

You can pass an existing guard or options:

```ts
const logger = safeLogger(console, {
  guard: createPIIGuard({ mode: "tokenize", tokenSalt: "logs" }),
  methods: ["info", "warn", "error"]
});
```

## Pino

```ts
import pino from "pino";
import { pinoPIIGuard } from "pii-safe";

const logger = pino({
  ...pinoPIIGuard()
});
```

You can also use the serializer directly:

```ts
import { createPinoSerializer } from "pii-safe";

const redact = createPinoSerializer();
```

## Winston

```ts
import winston from "winston";
import { createWinstonRedactionFormat } from "pii-safe";

const logger = winston.createLogger({
  format: createWinstonRedactionFormat(winston.format),
  transports: [new winston.transports.Console()]
});
```

## Built-In Detectors

Built-in detectors are deterministic and local-only:

- email
- phone
- credit card with Luhn validation
- IP address
- URL credentials
- JWT
- API keys and tokens
- Nigerian BVN/NIN where context is strong enough
- SSN
- IBAN with checksum validation
- context-labeled ABA routing numbers with checksum validation
- NPI with checksum validation
- context-labeled medical record numbers

Sensitive field names are also redacted, including:

```txt
email, phone, firstName, lastName, address, password, token, apiKey,
authorization, cookie, dob, ssn, bvn, nin, iban, routingNumber,
accountNumber, bankAccount, npi, mrn, medicalRecordNumber, patientId,
memberId, policyNumber
```

Field-name detection redacts the whole field value:

```ts
guard.sanitize({ firstName: "Ada", lastName: "Lovelace" }).value;
// { firstName: "[REDACTED]", lastName: "[REDACTED]" }
```

pii-safe does not currently detect personal names in free text:

```ts
guard.sanitizeString("My name is Ada Lovelace").value;
// "My name is Ada Lovelace"
```

Name detection is intentionally conservative because broad name matching can create many false positives.

## Supported Inputs

pii-safe handles:

- strings
- nested objects
- arrays
- `Error` objects
- `Headers`
- `URL`
- request-like bodies
- log method arguments

Inputs are cloned where needed. The original value is not mutated.

## Custom Detectors

```ts
import type { PIIDetector } from "pii-safe";

const ticketDetector: PIIDetector = {
  id: "ticket-id",
  detect(input) {
    const match = /\bTICKET-\d+\b/.exec(input);

    return match
      ? [
          {
            type: "ticket-id",
            start: match.index,
            end: match.index + match[0].length,
            confidence: 0.9
          }
        ]
      : [];
  }
};

const guard = createPIIGuard({
  sensitiveFields: ["employeeId"],
  detectors: [ticketDetector]
});
```

Detector matches use string spans:

```ts
{
  type: "ticket-id",
  start: 12,
  end: 23,
  confidence: 0.9
}
```

## Privacy Notes

- Detection happens locally in your process.
- No data is sent to pii-safe or any third-party service.
- Findings omit raw PII unless `includeRawFindings` is explicitly enabled.
- Avoid putting real PII or real secrets in tests, issues, examples, or bug reports.

## Limitations

No regex-based redaction library can guarantee perfect detection. pii-safe aims to be useful and conservative, but you should still review behavior for your application and data shape.

Known limitations:

- Free-text human names are not detected.
- Nigerian BVN/NIN detection is conservative to avoid redacting every 11-digit number.
- Phone detection may vary by region and formatting.
- Secret detection is heuristic and may miss uncommon provider formats.
- Some health and fintech identifiers need labels, field names, or checksums to avoid broad false positives.
- Diagnoses, procedure descriptions, insurance context, and free-text medical details may require domain-specific NLP or application context.

## Architecture

For a deeper codebase map, see [ARCHITECTURE.md](ARCHITECTURE.md).

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening an issue or pull request, and do not include real PII, credentials, or secrets in examples or tests.
