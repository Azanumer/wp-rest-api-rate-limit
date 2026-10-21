# WP REST API Rate Limit

Per-IP rate limiting for the WordPress REST API — zero dependencies, works on any host.

## Why

The REST API is a favorite target: `/wp/v2/users` for user enumeration, comment endpoints for spam, JWT/token routes for credential stuffing. A WAF helps, but this plugin stops the abuse at the application layer with proper `429` + `Retry-After` responses.

## Features

- **Two buckets** — a general limit for all routes, plus a stricter limit for auth-sensitive routes (`/wp/v2/users`, comments, JWT/token/auth)
- Proper **HTTP 429** with a **Retry-After** header (bots and clients back off correctly)
- **CIDR allow-list** (IPv4 + IPv6), admin bypass, per-day blocked-request counter
- One-click **counter reset**; full cleanup on uninstall
- Developer filter `wprl_client_ip` for sites behind a trusted proxy/Cloudflare — default is `REMOTE_ADDR` only, because blindly trusting `X-Forwarded-For` lets attackers rotate IPs

## Usage

Install, activate, go to **Settings → REST Rate Limit**. Defaults (120/min general, 30/min strict, 60s window) are sane for most sites — tighten the strict bucket if you see enumeration attempts in your logs.

## License

MIT — see [LICENSE](LICENSE).
