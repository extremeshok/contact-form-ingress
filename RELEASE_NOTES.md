# Contact Form Ingress — Release Notes

## 1.1.0 — Configuration guard & proxy awareness

Highlights
- Request bootstrap now fails fast when placeholder secrets (form `secret`, `json_forward_secret`, SMTP host/user/pass) remain, preventing accidental production launches with insecure defaults.
- Health and config self-test endpoints surface the same fatal/warning lists to aid ops dashboards.
- Added proxy-aware IP resolution with trusted header/CIDR allow lists so rate limiting, dedupe, and logging reflect the real client IP when behind a load balancer.
- Added a PHP-based self-test harness (`php tests/run.php`) that covers bootstrap guards, proxy resolution, happy-path submissions, duplicate suppression, and rate limiting.
- Introduced a GitHub Actions workflow that lints PHP files and runs the self-test harness on every push/PR.
- Expanded docs to include configuration checklist, proxy guidance, and testing instructions.

## 1.0.1 — Initial public release

Highlights
- Single‑file PHP endpoint `ingress.php` with no third‑party PHP deps.
- Strong anti‑abuse: CSRF double‑submit, dwell‑time, honeypots, origin/referrer allow‑list, IP rate limit (SQLite), duplicate suppression, optional keyword denylist and email domain allow/block.
- Email via native SMTP sockets (TLS/SSL/none), automatic fallback chain, retries/backoff.
- Optional JSON forwarding (HMAC‑signed) with retry/backoff and SQLite queue.
- Diagnostics (token, health, version, SMTP probe, queue flush) gated via `extra_cmds`.
- Config self‑test (`?cmd=check`) to validate common misconfigurations.
- Optional CAPTCHAs: built‑in math puzzle, Cloudflare Turnstile, hCaptcha, Google reCAPTCHA v3 (with score, action, hostname checks).
- Examples: simple, full, no‑JS, JSON submit, Turnstile, hCaptcha, reCAPTCHA v3, built‑in CAPTCHA.
- OSS hygiene: MIT license, SECURITY.md, CONTRIBUTING.md, Code of Conduct, CI (lint + token smoke test).

Breaking changes
- Preferred config file is `config.ingress.php` (no `.env` support). Loader also respects `CONFIG_PATH` if set.

CLI helpers
- `php ingress.php flush-forwards` — process queued JSON forwards
- `php ingress.php purge-old` — purge old submissions/forwards/ratelimit rows
- `php ingress.php purge-logs` — remove debug log
- `php ingress.php rotate-logs [max_kib]` — keep last N KiB of debug log (default 256)

Notes
- See `examples/README.md` for example usage.
- See main `README.md` for full configuration and feature documentation.
