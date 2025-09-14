# Contact Form Ingress (PHP, single file)

A secure, schema-less intake endpoint (`ingress.php`) for static websites. It receives JSON or form-encoded submissions, applies anti-spam checks, rate limiting and duplicate suppression, then notifies via SMTP and/or optionally forwards as signed JSON to a webhook such as n8n. No third‑party PHP libraries are used.

Quick start examples: see `examples/README.md` for a list of ready-to-run forms (simple, full, JSON submit, built-in CAPTCHA, and provider integrations).

### Features
- CSRF/bot token (double-submit cookie) with dwell-time check
- Origin/Referrer allow-list (CORS)
- Honeypots (website, fax) + optional token timestamp echo
- IP rate limiting + duplicate suppression (SQLite)
- SQLite persistence outside web root (dot-prefixed filenames)
- SMTP email via native sockets (supports secure: `tls` | `ssl` | `none` + fallback chain)
- Optional HMAC-signed JSON forward with retries/backoff, and queue (disabled by default)
- Optional async notify via `fastcgi_finish_request`
- Optional auto‑reply acknowledgement email to the submitter (disabled by default)

### Anti‑abuse layers
- Double‑submit token (cookie + posted token)
- Dwell‑time heuristic (minimum submit time)
- Honeypots (website, fax)
- Optional token timestamp echo (`require_ts_echo`)
- Domain allow‑list for Origin/Referrer
- SQLite IP rate limit (window + max per IP)
- Duplicate suppression window (same email+message hash)
- Optional keyword denylist (configurable fields)
- Optional email domain allow/block lists

## Quick Start

1) Place `ingress.php` on your server (same origin as your site if you use cookies).
2) Configure SMTP and recipients either by editing `$CFG` at the top of `ingress.php`, or by using `config.ingress.php` (recommended; see below).
3) Use one of the example pages in `/examples/`:
   - `simple-form.html` – a simple HTML form that posts to `/ingress.php`
   - `full-form.html` – a fuller form with topic/company fields, etc.
   - `nojs-form.html` – works without JavaScript (uses cookie token)
   - `json-submit.html` – a small page that posts JSON with `fetch()`
   - `turnstile-form.html` – Cloudflare Turnstile widget example
   - `hcaptcha-form.html` – hCaptcha widget example
   - `recaptcha-v3-form.html` – Google reCAPTCHA v3 example
   - `builtin-captcha-form.html` – built‑in math CAPTCHA (no third‑party)
   
   See `examples/README.md` for a quick how‑to table per example.

## Configuration Options

The script works out-of-the-box, but you must set SMTP to actually send mail. Configuration lives in `$CFG` inside `ingress.php`. To avoid editing the file, you can override via:

- `config.ingress.php` (recommended): create a PHP file next to `ingress.php` that returns an array of overrides. It is loaded automatically and deep‑merged.

Note: This project uses a single configuration mechanism: `config.ingress.php`.

### Example `config.ingress.php`

```php
<?php
return [
  'secret' => 'CHANGE_ME_LONG_RANDOM',
  'allowed_origins' => ['https://example.com','http://localhost'],
  'email' => [
    'to' => ['you@example.com'],
    'subject_prefix' => 'Example :: New enquiry — ',
  ],
  'smtp' => [
    'host' => 'smtp.example.com',
    'user' => 'you@example.com',
    'pass' => 'APP_PASSWORD',
    'port' => 587,
    'secure' => 'tls',
    'auth' => 'login',
    'helo' => 'example.com',
  ],
  // Optional webhook forward
  'json_forward_url' => '',
  'json_forward_secret' => '',

  // Optional CAPTCHA (choose one provider and enable)
  'captcha' => [
    'enabled'  => false,
    'provider' => 'turnstile', // 'turnstile' | 'hcaptcha' | 'recaptcha_v3'
    'site_key' => '',          // used by your frontend widget
    'secret'   => '',          // server-side secret used to verify
    'min_score'=> 0.5,         // only for recaptcha_v3
    'action'   => 'contact',   // reCAPTCHA v3 expected action
    'hostname' => '',          // reCAPTCHA v3 expected hostname (optional)
  ],

  // Optional auto‑reply (courtesy acknowledgement to submitter)
  'auto_reply' => [
    'enabled' => false,
    'subject' => 'Thanks — we received your message',
    'from'    => '', // optional; defaults to SMTP user
  ],

  // Optional email domain policy
  'email_domain_allow' => [], // e.g. ['company.com'] — if non‑empty, only allow these
  'email_domain_block' => [], // e.g. ['example.net'] — block these domains

  // Optional keyword denylist
  'keyword_denylist' => [], // e.g. ['viagra','casino','loan']
  'keyword_denylist_fields' => ['message','notes','enquiry','inquiry','description','request','offer'],
];
```

Examples index: see `examples/README.md` for quick how‑to notes per example.

### Other useful knobs
- `accept_payload`: `json` | `form` | `both` (default: `both`)
- `notify_targets`: CSV of `email`, `n8n` (default: `email`)
- `async_notify`: `'1'` to reply first (FastCGI only), then notify
- `allowed_origins`: CORS allow‑list; `http://localhost` allows any localhost port
- `site_keys`: optional allow‑list for a hidden `site_key` field
- `min_*` validators: name, email, phone, message lengths
- `allow_links_in_message`: false blocks common link protocols in message
- `debug`, `debug_log`, `debug_payload`: logging controls

## Diagnostics (disabled by default)

Enable via `$CFG['extra_cmds']`:

- `GET ?cmd=token` – mints CSRF cookie and returns token JSON
- `GET ?cmd=health` – storage sanity check
- `GET ?cmd=probe_smtp` – STARTTLS/auth probe (no email sent)
- `GET ?cmd=version` – script version & PHP
- `GET ?cmd=flush_queue` – process queued forwards (when queue enabled)
 - `GET ?cmd=check` – configuration self‑test (gated)

You can gate diagnostics with a key or IP allow list via `$CFG['extra_cmds']`.

### Endpoints (GET)
- `?cmd=token` — mints CSRF cookie and returns token JSON
- `?cmd=version` — version info (gated by `extra_cmds.version`)
- `?cmd=health` — storage sanity check (gated)
- `?cmd=probe_smtp` — SMTP STARTTLS/auth probe (gated)
- `?cmd=flush_queue` — flush queued forwards (gated)

## Queue (optional)

To queue failed JSON forwards in SQLite:

```
$CFG['forward_queue_enabled'] = true;
$CFG['forward_queue_on_fail'] = true;
```

Flush via GET (debug-gated): `/ingress.php?cmd=flush_queue`

Or via CLI (recommended for cron):

```
php /path/to/ingress.php flush-forwards
php /path/to/ingress.php purge-old
php /path/to/ingress.php purge-logs
```

## Cron Schedules (examples)

Run via the system cron on your server. Adjust paths as needed.

```
# Flush queued forwards every 10 minutes
*/10 * * * * php /var/www/site/ingress.php flush-forwards >/dev/null 2>&1

# Purge old records daily at 03:30 (uses retention_days)
30 3 * * * php /var/www/site/ingress.php purge-old >/dev/null 2>&1

# Purge debug log weekly on Sundays at 04:00
0 4 * * 0 php /var/www/site/ingress.php purge-logs >/dev/null 2>&1
```

## Embedding

See `sample-form.html` for a basic HTML form, or `sample-json.html` for a JSON example. The form auto-mints a CSRF cookie on load and adds a dwell-time hidden field on submit.

### CAPTCHA (optional)

This project already includes multiple anti-abuse layers (honeypots, dwell time, CSRF token, domain allow-list, rate-limit, dedupe, denylist). If you still receive spam, you can enable a CAPTCHA. Trade-offs: adds friction for users and depends on a third-party API.

Supported providers: Cloudflare Turnstile, hCaptcha, Google reCAPTCHA v3.

Built‑in option: a simple math CAPTCHA can be enabled via `builtin_captcha` and works without contacting third parties. The question and a signed token are returned on `?cmd=token`; clients must submit `captcha_answer` and `captcha_token`.

1) Set config in `config.ingress.php` (see example above) and set `'captcha.enabled' => true`.
2) On the frontend, render the provider’s widget and assign the returned token to a field named `captcha_token` (or the native fields `cf-turnstile-response`, `h-captcha-response`, `g-recaptcha-response` — all are accepted).
3) The server verifies the token via HTTPS and rejects the submission on failure.

Notes:
- For reCAPTCHA v3, set an appropriate `min_score` (e.g., 0.5–0.7), and optionally enforce `action` and `hostname`.
- The server uses `curl`; if missing, verification is skipped and fails.
 - The built‑in CAPTCHA is self‑contained and validated with an HMAC‑signed token.

## HTTP responses
- Content‑Type: `application/json` always
- On success: `{ "ok": true, "ref": "..." }`
- On error: `{ "ok": false, "error": "..." }`
- Response headers:
  - `X-Submission-Ref`: reference id
  - `X-Duplicate`: `1` when a duplicate was detected within the suppression window
  - `X-RateLimit-Remaining`: remaining submissions in the current window
  - `Retry-After`: seconds (set on `429 Too Many Requests`)

## Storage & files
- Submissions and rate limits are stored in a SQLite DB created outside the web root when possible (dot‑prefixed filenames).
- The path is derived from `$CFG['storage_dir']` and a random DB file recorded in `.db_name`.
- Debug log path defaults to `.intake.log` next to the script (configurable via `debug_log`).

## Forwarding (n8n/webhook)
- Signed JSON (HMAC SHA‑256) to `$CFG['json_forward_url']` with header `X-Signature`.
- Retries with backoff on transient errors (configurable timeouts/retries).
- Optional SQLite queue on failure with manual/cron flush.

## Security Notes

- Change `secret` to a long random string.
- Set `allowed_origins` to your site(s).
- Keep SMTP credentials safe. Avoid committing `config.ingress.php` to source control.
- The script blocks links in the message by default; you can allow them via `$CFG['allow_links_in_message']=true`.
- Optional keyword denylist lets you block submissions containing certain terms in common free‑text fields (set `keyword_denylist` and `keyword_denylist_fields`).

## Goals and Non-Goals

- Generic, secure, anti-spam, reliable, minimal dependencies
- No third‑party PHP libraries; uses native sockets for SMTP
- Works for a simple 1‑page static site as well as more bespoke frontends

## Contributing

Issues and PRs welcome. Please keep changes focused and small. Add tests or curl repro steps where practical.

## CI

GitHub Actions runs a basic CI: PHP lint and a smoke test against the token endpoint using PHP’s built-in server.

## License

MIT — see `LICENSE`.

## Security

Please see `SECURITY.md` for responsible disclosure guidelines.

## Project Name and File Naming

Project name: Contact Form Ingress (PHP)

- Cloudflare Turnstile quick snippet (optional):

```html
<!-- In your form page; replace YOUR_TURNSTILE_SITE_KEY -->
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<div class="cf-turnstile" data-sitekey="YOUR_TURNSTILE_SITE_KEY" data-callback="onTurnstileToken"></div>
<script>
  // Ensure your form has a hidden <input name="captcha_token">
  function onTurnstileToken(token){
    var el = document.querySelector('input[name="captcha_token"]');
    if (el) el.value = token;
  }
  // <input type="hidden" name="captcha_token">
  // Call onTurnstileToken from the widget's data-callback
  // Server will accept either captcha_token or cf-turnstile-response

</script>
```

- hCaptcha quick snippet (optional):

```html
<!-- In your form page; replace YOUR_HCAPTCHA_SITE_KEY -->
<script src="https://hcaptcha.com/1/api.js" async defer></script>
<div class="h-captcha" data-sitekey="YOUR_HCAPTCHA_SITE_KEY"></div>
<!-- Server will accept h-captcha-response automatically injected by the widget -->
```

- reCAPTCHA v3 quick snippet (optional):

```html
<!-- Replace YOUR_RECAPTCHA_SITE_KEY and keep action consistent -->
<script src="https://www.google.com/recaptcha/api.js?render=YOUR_RECAPTCHA_SITE_KEY"></script>
<script>
  grecaptcha.ready(function(){
    grecaptcha.execute('YOUR_RECAPTCHA_SITE_KEY', {action: 'contact'}).then(function(token){
      var el = document.querySelector('input[name="captcha_token"]');
      if (el) el.value = token;
    });
  });
  // <input type="hidden" name="captcha_token">
  // Server verifies token; for v3 it also checks score >= min_score
</script>
```
