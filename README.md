# TrustVault

TrustVault is a Flask/MySQL secure document-sharing starter with role-based access, per-document read/edit grants, revocation, private file storage, and audit events.

## Setup

1. Install Python 3.11+ and MySQL.
2. Create the `trustvault` database and a least-privilege application account.
3. Create a virtual environment and install `requirements.txt`.
4. Copy `.env.example` to `.env`; set unique, strong `SECRET_KEY` and `AUDIT_HMAC_KEY` values.
5. Set `DATABASE_URL` to your MySQL connection string. URL-encode special characters in the password.
6. Initialise the schema:

   ```bash
   flask --app app init-db
   ```

7. Create accounts interactively:

   ```bash
   flask --app app create-user
   ```

   Create separate `admin`, `owner`, and `viewer` accounts. There are no default demo passwords.
8. Run locally:

   ```bash
   python app.py
   ```

9. Run tests:

   ```bash
   pytest -v
   ```

## Security notes

- Private files are stored outside Flask's static directory.
- Every download checks the current database permission state.
- Read-only grants do not allow editing.
- Revoked grants are retained as audit history and no longer authorise access.
- CSRF protection is enabled for form routes.
- Audit hash chaining is tamper-evident, but is not independently immutable. Export checkpoints to separately controlled append-only storage for stronger evidence.
- Configure HTTPS, secure cookies, rate limiting, malware scanning, encrypted backups, external audit checkpoints, and production key management before deployment.
- Downloaded copies cannot be remotely revoked.
- This starter is not a security certification or a substitute for a deployment security review.

## Roles

- `admin`: manage administrative audit view and perform documented administrative operations; admin role does not automatically grant read access to all documents.
- `owner`: upload and manage their documents and grant/revoke access.
- `viewer`: access documents only when an active grant permits it.
