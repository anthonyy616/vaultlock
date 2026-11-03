# Vaultbox

**Developer continuity for everything Git doesn't keep.**

Vaultbox securely backs up, restores, versions, and shares the development context that lives outside your Git repository — local configuration, `.env` files, AI-agent instructions, prompts, skills, private notes, and project tooling settings. Move to any machine, authenticate, restore what you need, and keep building.

> **Status:** early stage — internal design phase. The public specification will land here as implementation begins.

## Why Vaultbox?

Git versions source code, but the files that make a project actually *run* are often ignored — deliberately. They only ever exist on one laptop, and moving between machines is usually a manual, error-prone ritual of copying `.env` files around (or worse, pasting secrets into chat).

Vaultbox solves this with:

- **Project vaults** — explicitly selected files and directories backed up as immutable, versioned snapshots you can preview and restore.
- **Secrets manager** — structured, encrypted secret sets per project and environment (`development` / `staging` / `production`), with safe `.env` import, masked UI, and audit logging.
- **Team sharing** — users, organisations, workspaces, roles, and protected external links with expiry and revocation.
- **A real CLI** — the primary interface: authenticate, link a project, preview a backup, restore on a new machine.
- **Own your storage** — hosted vaultlock storage or your own S3-compatible bucket.

## Design principles

- **Explicit consent, never silent.** Sensitive data never leaves a device implicitly, ignored files are never auto-uploaded, and restores never silently overwrite existing files.
- **Secure defaults, deliberate actions.** Destructive operations require confirmation; restores are previewable and explain conflicts before writing.
- **Encryption you can reason about.** Envelope encryption with a reviewed key hierarchy; recoverability is a first-class feature, not an afterthought.
- **Least privilege everywhere.** The CLI and web app share one consistent permission model.

## What Vaultbox is *not*

- Not a Git or GitHub replacement — it complements source control.
- Not a general-purpose file sync service.
- Not a place for arbitrary remote script execution.

## Planned stack

| Layer     | Technology                                   |
|-----------|----------------------------------------------|
| Backend   | Rust (Axum, Tokio, SQLx, PostgreSQL)          |
| CLI       | Rust (Clap) — macOS, Windows, Linux           |
| Web app   | Next.js / TypeScript                          |
| Storage   | S3-compatible (hosted or customer-provided)   |
| Deployment| Docker (hosted + self-hosted)                 |

## Contributing

Implementation is still ramping up. Contributor guidelines are in [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md), and the shared terminology is in [`docs/GLOSSARY.md`](docs/GLOSSARY.md).

## License

Licensed under the [Apache License 2.0](LICENSE).
