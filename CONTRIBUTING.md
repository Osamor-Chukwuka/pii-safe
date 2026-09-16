# Contributing to pii-safe

Thanks for wanting to improve pii-safe. This package handles sensitive data, so contributions should be careful, local-first, and well tested.

## Ways to Contribute

- Report false positives or missed PII detections.
- Improve existing detectors.
- Add conservative new detectors.
- Improve TypeScript types, docs, examples, and integrations.
- Add tests for real-world logging or LLM sanitization patterns.

## Local Setup

```bash
npm install
npm test
```

Useful commands:

```bash
npm run build
npm test
npm pack --dry-run
```

## Contribution Workflow

If you are not a maintainer or collaborator, fork the repository first:

```bash
git clone https://github.com/YOUR_USERNAME/pii-safe.git
cd pii-safe
npm install
git checkout -b fix/descriptive-branch-name
```

Make your changes, then run:

```bash
npm test
git status
git add .
git commit -m "fix: describe the change"
git push origin fix/descriptive-branch-name
```

Open a pull request from your fork into `Osamor-Chukwuka/pii-safe:main`.

If you are a maintainer or collaborator with write access, you can create a branch directly in this repository:

```bash
git clone https://github.com/Osamor-Chukwuka/pii-safe.git
cd pii-safe
npm install
git checkout -b feat/descriptive-branch-name
```

Then push the branch and open a pull request:

```bash
npm test
git add .
git commit -m "feat: describe the change"
git push -u origin feat/descriptive-branch-name
```

## Development Guidelines

- Keep detection local-only. Do not add network calls or external detection APIs.
- Do not commit real secrets, tokens, credentials, or real personal data.
- Use obviously fake fixtures that do not match real provider secret formats.
- Prefer conservative detectors over noisy ones.
- Never include raw PII in findings by default.
- Preserve the public API unless a breaking change is intentional and documented.
- Add or update tests for behavior changes.

## Detector Guidelines

Good detectors should:

- Return precise spans.
- Include a stable `type`.
- Avoid broad matches that redact ordinary text.
- Use context when values are ambiguous.
- Prefer validation where possible, such as Luhn checks for credit cards.

If a detector could match common IDs, counters, timestamps, or random numbers, make it context-aware.

## Pull Request Checklist

Before opening a PR:

- Run `npm test`.
- Add tests for new behavior.
- Update README examples if the public API changes.
- Confirm `npm pack --dry-run` looks reasonable for packaging changes.
- Check that no fixture resembles a real provider token, API key, or credential.

## Commit Style

Use short, descriptive commit messages. Examples:

```txt
feat: add iban detector
fix: reduce phone false positives
docs: clarify logger wrapper usage
test: cover nested error sanitization
```

## Security Reports

Please do not open public issues for vulnerabilities. See [SECURITY.md](SECURITY.md).
