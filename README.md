# pii-guard

Local-first PII redaction for LLM prompts, logs, and Node.js apps.

```bash
npm install @chukwuka_osamor/pii-guard
```

## Core API

```ts
import { createPIIGuard } from "@chukwuka_osamor/pii-guard";

const guard = createPIIGuard();

const result = guard.sanitize({
  email: "ada@example.com",
  note: "card 4111 1111 1111 1111"
});

console.log(result.value);
// { email: "[REDACTED]", note: "card [REDACTED]" }

console.log(result.findings);
// [{ type, detector, path, confidence, span, length }]
```

Raw PII is never included in findings by default. You can opt in when debugging locally:

```ts
guard.scan("ada@example.com", { includeRawFindings: true });
```

## Redaction Modes

```ts
createPIIGuard({ mode: "replace" });  // [REDACTED]
createPIIGuard({ mode: "mask" });     // ad********om
createPIIGuard({ mode: "tokenize", tokenSalt: "app-a" }); // [EMAIL:...]
```

## LLM Helpers

```ts
import { sanitizeMessages, sanitizePrompt } from "@chukwuka_osamor/pii-guard";

const prompt = sanitizePrompt("Email ada@example.com about this ticket");

const messages = sanitizeMessages([
  { role: "user", content: "My phone is +1 415 555 2671" }
]);
```

## Generic Logger

```ts
import { safeLogger } from "@chukwuka_osamor/pii-guard";

const logger = safeLogger(console);

logger.info("User email: ada@example.com");
logger.error(new Error("Failed for ada@example.com"));
```

## Pino

```ts
import pino from "pino";
import { pinoPIIGuard } from "@chukwuka_osamor/pii-guard";

const logger = pino({
  ...pinoPIIGuard()
});
```

## Winston

```ts
import winston from "winston";
import { createWinstonRedactionFormat } from "@chukwuka_osamor/pii-guard";

const logger = winston.createLogger({
  format: createWinstonRedactionFormat(winston.format),
  transports: [new winston.transports.Console()]
});
```

## Detectors

Built-in detectors are deterministic and local-only:

- email
- phone
- credit card with Luhn validation
- IP address
- URL credentials
- JWT
- API keys and tokens
- Nigerian BVN/NIN where context is strong enough

Sensitive field names are also redacted, including:

```txt
email, phone, firstName, lastName, address, password, token, apiKey,
authorization, cookie, dob, ssn, bvn, nin
```

## Custom Detectors

```ts
const guard = createPIIGuard({
  sensitiveFields: ["employeeId"],
  detectors: [
    {
      id: "ticket-id",
      detect(input) {
        const match = /\bTICKET-\d+\b/.exec(input);
        return match
          ? [{ type: "ticket-id", start: match.index, end: match.index + match[0].length }]
          : [];
      }
    }
  ]
});
```

## Notes

PII Guard handles strings, nested objects, arrays, `Error` objects, `Headers`, `URL` objects, request-like bodies, and log arguments without mutating the original input.
