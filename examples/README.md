# Examples

All examples assume your endpoint is at `/ingress.php` on the same origin.

| File | Purpose/Feature | Required Config | Quick Steps |
| --- | --- | --- | --- |
| `simple-form.html` | Minimal HTML form with CSRF (cookie+hidden), dwell time, honeypots | None | Open the page, it will mint `?cmd=token` automatically, then submit |
| `full-form.html` | Larger form (topic/company/role), schema‑less intake | None | Same as simple; shows additional fields merged into email/body |
| `nojs-form.html` | Works without JavaScript | None | Loads a pixel to mint cookie token; submit normally |
| `json-submit.html` | Post JSON via `fetch()` | None | Click “Send JSON”; auto‑mints cookie token |
| `turnstile-form.html` | Cloudflare Turnstile CAPTCHA | `captcha.enabled=true`, `provider='turnstile'`, set `site_key` and `secret` | Add Turnstile site key in the HTML, configure secrets in `config.ingress.php` |
| `hcaptcha-form.html` | hCaptcha CAPTCHA | `captcha.enabled=true`, `provider='hcaptcha'`, set `site_key` and `secret` | Add hCaptcha site key in the HTML, configure secrets in `config.ingress.php` |
| `recaptcha-v3-form.html` | Google reCAPTCHA v3 | `captcha.enabled=true`, `provider='recaptcha_v3'`, set `site_key`, `secret`, optionally `min_score`, `action`, `hostname` | Replace SITE KEY in HTML; configure server and ensure action/hostname match |
| `builtin-captcha-form.html` | Built‑in math CAPTCHA (no third‑party) | `builtin_captcha.enabled=true` | Page pulls `captcha_q`/`captcha_token` from `?cmd=token` and posts `captcha_answer` |

Notes
- Most examples use progressive enhancement (AJAX) to display JSON responses; forms also work when posted normally.
- If enabling a CAPTCHA provider, configure `captcha` in `config.ingress.php` and include the provider script/widget.
- For the built‑in CAPTCHA, the question and token come from `GET /ingress.php?cmd=token`.
