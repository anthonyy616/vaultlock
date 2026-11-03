# Glossary

| Term | Definition |
|---|---|
| API/control plane | Service layer for identity, metadata, permissions, and orchestration |
| Data plane | File transfer and object processing path |
| DEK | Data encryption key used to encrypt content |
| KEK | Key-encryption key used to wrap another key |
| Envelope encryption | Encrypt data with a DEK and protect the DEK with a KEK |
| E2EE | End-to-end encryption where the service does not possess plaintext decryption keys |
| KMS | Key management service |
| Manifest | Structured snapshot description of paths and content references |
| Snapshot | Immutable logical state of a vault at a point in time |
| Chunk | Bounded content segment stored independently |
| Deduplication | Reuse of identical content rather than storing duplicate copies |
| `.vaultignore` | Project Vault-specific exclusion rules |
| Secret set | Versioned group of environment variables or configuration secrets |
| Device | Registered client installation that can authenticate independently |
| Workspace | Collaboration grouping inside an organisation |
| BOLA/IDOR | Broken object-level authorisation / insecure direct object reference |
| RPO | Recovery point objective: acceptable data-loss window |
| RTO | Recovery time objective: acceptable service recovery duration |
