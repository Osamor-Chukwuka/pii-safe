# pii-safe Architecture

This document explains how pii-safe is organized and how values flow through scanning and redaction.

## Goals

pii-safe is designed to be:

- local-only, with no external detection API calls
- deterministic
- TypeScript-first
- conservative enough for logs and LLM pre-processing
- extensible through custom detectors and sensitive field names

## Source Layout

```txt
src/
  core/
    guard.ts       createPIIGuard public API
    scan.ts        traversal and finding generation
    redact.ts      cloning and redaction
    policy.ts      allowlist policy
    defaults.ts    default replacement and field names
    path.ts        path formatting and field normalization
    tokenize.ts    deterministic token generation
    types.ts       public TypeScript contracts
  detectors/
    email.ts
    phone.ts
    credit-card.ts
    ip.ts
    secrets.ts
    nigeria.ts
    finance.ts
    health.ts
    index.ts       built-in detector registry
  integrations/
    logger.ts      generic safeLogger wrapper
    pino.ts        Pino helpers
    winston.ts     Winston helpers
  llm/
    messages.ts    prompt and chat-message sanitizers
  utils/
    luhn.ts        Luhn checksum helper
```

## Public Flow

Most users start with:

```ts
const guard = createPIIGuard(options);
guard.sanitize(value, perCallOptions);
```

At a high level:

```txt
createPIIGuard()
  -> createScanConfig()
  -> scanValue() or redactValue()
  -> walk nested input
  -> run detectors on strings
  -> apply field-name policy
  -> apply allowlist policy
  -> clone and redact
  -> return { value, findings }
```

## Scanning

`scanValue` recursively walks:

- strings
- arrays
- plain objects
- `Error`
- `Headers`
- `URL`

For each string, `scanString` runs every detector and converts detector matches into findings:

```ts
{
  type: "email",
  detector: "email",
  path: "$.user.email",
  confidence: 0.98,
  redacted: true,
  span: { start: 0, end: 15 },
  length: 15
}
```

Field-name detection happens during traversal. If a key like `password`, `token`, or `email` is sensitive, pii-safe creates a `sensitive-field` finding and redacts the whole field unless that field is allowlisted.

## Redaction

`redactValue` uses the same traversal shape as scanning, but returns a cloned sanitized value.

Strings are redacted by span:

1. Detect findings.
2. Mark allowlisted findings as `redacted: false`.
3. Protect nested detector hits inside an allowed larger span.
4. Apply replacements from right to left so earlier spans stay stable.

Supported modes:

- `replace`: uses `replacement`, defaulting to `[REDACTED]`
- `mask`: keeps small visible edges
- `tokenize`: emits deterministic tokens like `[EMAIL:1a2b3c4d]`

## Allowlist Policy

Allowlist policy lives in `core/policy.ts`.

It supports:

- `allowTypes`
- `allowDetectors`
- `allowFields`

Guard-level allowlists and per-call allowlists are merged. This means per-call options can add exceptions for a specific LLM request without rebuilding the guard.

Example:

```ts
guard.sanitize(payload, {
  allowTypes: ["email"],
  allowFields: ["email"]
});
```

Custom detectors still work because allowlist values are strings, even though pii-safe exports built-in TypeScript unions for autocomplete.

## Detector Design

Detectors are small objects:

```ts
{
  id: "email",
  detect(input, context) {
    return [{ type: "email", start: 0, end: 15, confidence: 0.98 }];
  }
}
```

Guidelines:

- Return precise spans.
- Prefer validation checks when possible.
- Use context for ambiguous identifiers.
- Avoid broad matches for common numbers or words.
- Do not use network calls.

Examples:

- credit cards use Luhn validation
- IBAN uses country length and mod-97 validation
- ABA routing numbers require a label and checksum
- NPI requires checksum and field/label context
- BVN/NIN detection is conservative because many 11-digit numbers are not Nigerian identity numbers

## Integrations

Integrations are thin wrappers over the core API:

- `safeLogger` proxies selected logger methods and sanitizes arguments.
- `pinoPIIGuard` returns serializers and a log hook.
- `createWinstonRedactionFormat` wraps a Winston format factory.
- `sanitizePrompt`, `sanitizeMessage`, and `sanitizeMessages` sanitize LLM inputs.

Logger libraries are optional peer dependencies. pii-safe does not import Pino or Winston directly at runtime.

## Adding a Detector

1. Add a file in `src/detectors/`.
2. Export a `PIIDetector`.
3. Register it in `src/detectors/index.ts`.
4. Add built-in type and detector IDs in `src/core/types.ts` if it should be typed.
5. Add focused tests in `test/core.test.mjs`.
6. Update README detector documentation.

Use fake values only. Do not add real personal data, real credentials, or provider-looking secrets.
