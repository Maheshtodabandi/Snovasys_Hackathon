# API and route access matrix

All routes except `/`, `/login`, and `/health` require authentication where indicated. Cookie-authenticated state-changing form routes use Flask-WTF CSRF protection.

| Method | Route | Access |
|---|---|---|
| GET | `/` | Public redirect |
| GET, POST | `/login` | Public; rate limiting should be added before deployment |
| POST | `/logout` | Authenticated |
| GET | `/dashboard` | Authenticated; permission-filtered search results |
| POST | `/documents/upload` | Owner or admin |
| GET | `/documents/<id>/download` | Owner or active read/edit grantee |
| POST | `/documents/<id>/delete` | Owner; administrator policy is explicit in route |
| POST | `/documents/<id>/permissions` | Document owner or admin |
| GET | `/documents/<id>/permissions` | Document owner or admin |
| POST | `/documents/<id>/permissions/<grant_id>/revoke` | Document owner or admin |
| GET | `/admin/audit` | Admin |
| GET | `/health` | Public health check |

Unauthorised document reads/downloads return 404 to reduce document-existence disclosure. Other role denials may return 403. Invalid uploads return 400 or 413. Production API schemas, rate limits, and structured error responses should be added before public deployment.
