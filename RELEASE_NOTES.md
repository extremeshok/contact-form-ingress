# Contact Form Ingress — Release Notes

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

