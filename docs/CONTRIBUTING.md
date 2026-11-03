# Contributing

## Engineering standards

- Follow the internal architecture and security documents.
- Keep changes focused.
- Add tests with every behaviour change.
- Update API/CLI documentation when contracts change.
- Use migrations for schema changes.
- Do not commit secrets, generated build outputs, local credentials, or private test data.
- Preserve existing `.gitignore` entries and add missing protections.
- Do not introduce dependencies without review.

## Rust

- Format with rustfmt.
- Keep Clippy warnings resolved or explicitly justified.
- Prefer safe Rust.
- Document every `unsafe` block with its safety invariants.
- Use typed errors and avoid panics in normal request paths.
- Keep async tasks bounded and cancellation-aware.

## Frontend

- Use TypeScript strict mode.
- Keep API access in the shared client layer.
- Avoid duplicating permission logic as a source of truth; backend authorisation remains authoritative.
- Do not expose secrets in analytics or error-reporting integrations.
- Maintain accessible forms, dialogs, and navigation.

## Pull request checklist

- [ ] Scope matches an approved requirement.
- [ ] Tests added and passing.
- [ ] Security and authorisation considered.
- [ ] No secrets or sensitive data added.
- [ ] Migrations reviewed.
- [ ] Documentation updated.
- [ ] Formatting/lint/type checks pass.
- [ ] Failure and retry behaviour considered.
