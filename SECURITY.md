# Security Policy

## Reporting a Vulnerability

Do not disclose vulnerabilities or credentials in a public issue.

Report them privately to the repository owner using GitHub's private
vulnerability reporting feature. Include the affected revision, impact,
reproduction steps, and any suggested mitigation.

## Secret Handling Rules

- Never commit credentials, master keys, private keys, certificates containing
  private material, Firebase service-account files, or production connection
  strings.
- Store production secrets in an approved secret manager and inject them only
  at runtime.
- Treat every secret committed to Git as compromised, even after deletion.
- Rotate an exposed secret before rewriting Git history.
- Do not include plaintext, ciphertext, DEKs, or master-key material in logs,
  issues, test fixtures, or screenshots.

## Supported Versions

Until the first stable release, only the latest revision of `main` receives
security fixes.

## Known Security Work

The raw `MASTER_KEYS` environment configuration and in-memory master-key
rotation are development-only. They must be replaced by a durable external
KMS/HSM-backed provider before production use.

See [docs/security-incident-response.md](docs/security-incident-response.md)
for the active credential-exposure response plan.
