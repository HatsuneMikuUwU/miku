# Miku Worker

A Cloudflare Worker that provides WebSocket-based proxy access for VLESS, VMess, Trojan, and Shadowsocks. The worker also generates subscription links from a maintained proxy list while preserving the original Miku subscription API.

## Features

- VLESS, VMess, Trojan, and Shadowsocks protocol support.
- WebSocket transport with optional proxy chaining.
- XHTTP stream support for non-WebSocket clients.
- UDP relay support and DNS-over-HTTPS fallback.
- Subscription generation through `/api/v1/sub`.
- Client IP information through `/api/v1/myip`.
- CORS support for subscription and API responses.
- Country, protocol, port, format, domain, and result-limit filters.

## Subscription API

The subscription endpoint is:

```text
https://YOUR_WORKER_DOMAIN/api/v1/sub
```

Example:

```text
https://miku.hatsunemikuuwu.workers.dev/api/v1/sub?vpn=vless&cc=ID&domain=104.17.3.81&port=443&limit=100
```

### Query parameters

| Parameter | Description | Default |
| --- | --- | --- |
| `vpn` | Comma-separated protocols: `vless`, `vmess`, `trojan`, or `ss` | All protocols |
| `type` | Transport type: `ws` or `xhttp` | `ws` |
| `cc` | Comma-separated country codes, such as `ID,SG,US` | All countries |
| `domain` | Domain or IP used in generated client links | Current worker hostname |
| `port` | Comma-separated ports, such as `443,80` | `443,80` |
| `limit` | Maximum number of generated links | `10` |
| `format` | Output format: `raw`, `base64`, `b64`, `vless`, `sfa`, or `bfr` | `raw` |
| `prx-list` | Optional custom proxy-list URL | Repository proxy list |

The generated links use the worker UUID configured in `CONFIG.UUID`. If the worker UUID is changed, redeploy the worker before using new subscription links.

## Worker Routes

| Route | Description |
| --- | --- |
| `/vless` | VLESS endpoint |
| `/vmess` | VMess endpoint |
| `/trojan` | Trojan endpoint |
| `/ss` | Shadowsocks endpoint |
| `/vless/IP:PORT` | Protocol endpoint using a specific proxy address |
| `/sub` | Redirects to the subscription information page |
| `/api/v1/sub` | Generates subscription links |
| `/api/v1/myip` | Returns request IP and Cloudflare location data |

The protocol-specific routes accept a proxy suffix in the form `/PROTOCOL/IP-PORT`, `/PROTOCOL/IP:PORT`, or `/PROTOCOL/IP=PORT`.

## Configuration

Edit the `CONFIG` object in `miku_worker.js` before deployment when you need to change the worker credentials or relay behavior.

Important settings include:

- `UUID`: Shared credential root for VLESS, VMess, Trojan, and Shadowsocks.
- `SS_METHOD`: Shadowsocks encryption method.
- `UDP_RELAY`: UDP relay host, port, or WebSocket URL.
- `REJECT_UDP_443`: Whether UDP/443 should be rejected to force TCP fallback.
- `DNS_DOH_URLS`: DNS-over-HTTPS resolver endpoints.

The `miku_worker.js` file is the Wrangler entrypoint configured by `wrangler.toml`.

## Deployment

Install dependencies and deploy with Wrangler:

```bash
npm install
npx wrangler deploy
```

The project is configured with:

```toml
name = "miku"
main = "miku_worker.js"
compatibility_date = "2024-09-23"
compatibility_flags = ["nodejs_compat_v2"]
```

The subscription endpoint uses the public proxy list by default. A different proxy-list source can be supplied through the `prx-list` query parameter or the `PRX_BANK_URL` Worker binding.

## Local Checks

Run a syntax check before deployment:

```bash
node --check miku_worker.js
```

## License

This repository retains the licensing terms of the original project.
