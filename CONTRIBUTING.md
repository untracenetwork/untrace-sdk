# Contributing to untrace-sdk

Thanks for helping. This repo is public and licensed under Apache-2.0.

## Before you open a pull request

1. Open an issue first for anything bigger than a typo, so we can agree on the change.
2. Fork the repo and branch off `main`.
3. Run the checks locally:

```bash
npm ci
npm run typecheck
npm test
npm run check:public
```

4. Keep the pull request small and focused. Describe what changed and why.
5. Pull requests merge into `main` after review and green CI.

## Rules

- Never commit secrets, tokens, `.env` files or real customer data. Use placeholders such as `untrace_sk_v1_...`.
- Match the existing style and keep public docs in plain language.
- By contributing, you agree your work is licensed under Apache-2.0 (see `LICENSE`).

## Security issues

Do not open a public issue for a vulnerability. Email contact@untrace.network instead.

## Questions

Open a GitHub issue or write to contact@untrace.network.

