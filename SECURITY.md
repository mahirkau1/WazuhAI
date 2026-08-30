# Security Policy

## Scope

AegisAI Agent is currently a development/lab defensive-security project. It processes security telemetry and may contain sensitive event data.

## Reporting a vulnerability

Please do not publish credentials, API keys, private logs, database contents, host identifiers, or exploit details containing real sensitive data in a public issue. Report security concerns privately to the repository owner/maintainer when a private contact channel is available.

## Deployment guidance

- Keep `.env`, `aegis.db`, logs, and credentials out of Git.
- Use a dedicated least-privilege Wazuh Indexer account.
- Restrict dashboard access to trusted networks or localhost unless authentication/TLS is added.
- Use valid TLS certificates and certificate verification in production.
- Rotate any credential that may have been accidentally exposed.
- Review AI-generated findings before taking response actions.

