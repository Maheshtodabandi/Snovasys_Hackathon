# TrustVault threat register

This is a starter register. Update it to reflect the exact code, tests, and deployment you actually verified.

| Threat | Mitigation in starter | Remaining risk / follow-up |
|---|---|---|
| IDOR by guessing document IDs | Per-document check on download; 404 on denied download | Add route-by-route negative tests for every future endpoint |
| Revoked permission reused | Each download queries active grant state | Already-downloaded copies cannot be revoked |
| Public file URL exposure | Random storage key outside static directory | Production storage permissions and backups must be reviewed |
| Path traversal | Server-generated storage keys and resolved-path check | Test platform-specific symlink and filesystem cases |
| Fake file extension | Extension allowlist plus magic-byte checks | Add malware scanning and deeper format parsing |
| Oversized upload | Flask request limit and explicit size limit | Configure reverse-proxy limits too |
| CSRF | Flask-WTF CSRF protection | Keep tokens on all state-changing forms |
| Password disclosure | Argon2 password hashes | Add login rate limiting and password reset design |
| SQL injection | SQLAlchemy query expressions | Review any future raw SQL |
| Stored XSS in filename | Jinja autoescaping and safe attachment response | Keep HTML/SVG uploads disallowed |
| Audit event modification | HMAC event chain | A privileged attacker may rewrite the entire chain if they can access the key; export checkpoints externally |
| Audit event deletion | Hash links reveal gaps when later events remain | Deletion of the tail needs external checkpoints to detect |
| Admin overreach | Admin role does not grant document read in central check | Define and test break-glass procedure if one is added |
| Search leaks metadata | Results filtered to owned or actively granted documents for non-admin users | Add tests for search filters and all API endpoints |
| Account deactivation | User loader rejects inactive accounts | Test session and deployment-specific identity revocation |
| File/database inconsistency | Upload cleanup on database failure; soft delete | Delete operation needs a durable retry/recovery workflow |
| Secrets committed to Git | `.env` ignored and `.env.example` supplied | Run secret scanning before every public push |
| Missing audit for denied routes | Denied document download is audited | Extend audit coverage to all denials, including admin and grant routes |
| Permission race conditions | Current grant queried for each request | Add transaction/concurrency tests; define revocation commit as the cutoff |

## Accepted limitations

- A file already downloaded by an authorised user cannot be remotely erased.
- Local filesystem storage is for development; production requires private persistent storage, encrypted backups, monitoring and tested recovery.
- The audit chain needs independently controlled checkpoints to provide stronger evidence against privileged database tampering.
- The starter does not implement MFA, malware scanning, external identity federation, version history, or enterprise key management.
