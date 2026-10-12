# CABEPEDES Security Baseline v1.3.0

| Layer | Control |
|---|---|
| Access control | Server-side RBAC, deny-by-default API, Visitor read-only, Host validation, protected CRUD. |
| Authentication/session | PBKDF2-HMAC-SHA256 600k + per-account salt, rate limit, idle timeout, random session token, Secure/HttpOnly/SameSite=Strict cookie, CSRF token. |
| Input/API | JSON-only mutation endpoints, 512 KiB body cap, bounded field lengths, enum/date validation, server-managed ID Issue, collision check. |
| Browser security | CSP, frame denial, nosniff, Referrer-Policy, Permissions-Policy, COOP/CORP, HSTS on TLS, noindex and cross-domain policy restrictions. |
| Network | HTTP bound to loopback only; non-loopback HTTP redirects to HTTPS; TLS certificate generated locally for discovered LAN addresses; TLS 1.2+. |
| Data integrity | SHA-256 manifest for immutable release assets; mutable data excluded by design; atomic writes; `.bak` recovery; corrupt-file quarantine; restrictive file modes. |
| Notifications | Role-scoped notifications, bounded storage, read state per account, atomic persistence and backup recovery. |
| Logging/monitoring | Security audit log, event rate cap, auth failure alerts, active-client snapshot, periodic self-check, session cleanup. |
| Deployment persistence | Per-user macOS LaunchAgent with `RunAtLoad`, `KeepAlive`, stable `/bin/sh` launcher and explicit `launchctl enable`. |
| Performance | No npm/CDN runtime dependencies, server stdlib, bounded polling (30/45/20/15 sec), static allowlist, 61-record local compute. |

## Framework mapping
- OWASP Top 10:2025
- OWASP ASVS 5.0.0
- ISO/IEC 27001:2022
- NIST SP 800-53 Rev. 5 / minor release 5.2.0
- NIST CSF 2.0
- CWE / SANS-oriented secure coding
- PTES v1.0 process reference

This is a defensive control mapping, not a claim of formal certification or full compliance.
