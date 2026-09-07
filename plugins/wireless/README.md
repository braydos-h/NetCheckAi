# wireless

Wireless/Bluetooth assessment integration: bettercap, aircrack-ng, and
hcxtools for authorized WLAN testing. Radio-touching tools are
allowlist-gated with the BSSID (or BT device address) passed as the
`target_ip` argument — the operator must add the exact BSSID to
`exploit.allowed_targets` (never a wildcard).

Source: `plugins/wireless/plugin.yaml`, `plugins/wireless/plugin.py`

## Capabilities

Manifest capabilities: `mcp_tool`. Registers four MCP tools, all wrapped with
`@require_allowlist(target_param="target_ip", audit=True)` so the target-IP
allowlist lock + JSONL audit trail apply automatically:

- `wireless_recon(target_ip, interface="")` — passive recon sweep via
  bettercap (`wifi.recon on`, sleep `channel_timeout_seconds`, `wifi.show`).
  `target_ip` is the BSSID to focus on.
- `wireless_deauth(target_ip, client_mac="", interface="")` — send deauth
  frames via bettercap (`wifi.deauth <BSSID> [--client <mac>]`). Dangerous:
  only against networks you own or are contracted to test.
- `wireless_pmkid_capture(target_ip, interface="")` — capture PMKID frames
  with hcxdumptool (filtered to the BSSID); the `.pcapng` lands under the
  workspace for offline cracking (`hashcat -m 22000`).
- `wireless_crack_pmkid(target_ip, capture_path, wordlist="/usr/share/wordlists/rockyou.txt")` —
  crack a capture with aircrack-ng (`-w <wordlist> -b <BSSID>`); `target_ip`
  is the BSSID for audit-trail attribution. Missing captures refuse with
  `BLOCKED:`.

Every tool refuses with `BLOCKED:` unless `wireless.enabled` is true in
config (double-gate: `plugins.enabled` + section flag).

## Config keys

```yaml
wireless:
  enabled: false
  bettercap_path: bettercap
  aircrack_path: aircrack-ng
  hcxtools_path: hcxdumptool
  interface: wlan0mon
  channel_timeout_seconds: 30
```

| Key                      | Type   | Default                        | Meaning                                            |
|--------------------------|--------|--------------------------------|----------------------------------------------------|
| `enabled`                | `bool` | `false`                        | Section flag; every tool refuses without it        |
| `bettercap_path`         | `str`  | `bettercap`                    | bettercap binary (`shutil.which` resolved)         |
| `aircrack_path`          | `str`  | `aircrack-ng`                  | aircrack-ng binary (`shutil.which` resolved)       |
| `hcxtools_path`          | `str`  | `hcxdumptool`                  | hcxdumptool binary (`shutil.which` resolved)       |
| `interface`              | `str`  | `wlan0mon`                     | Monitor-mode interface (per-call override allowed) |
| `channel_timeout_seconds`| `int`  | `30`                           | Recon dwell time; tool timeout is this + 30s       |

## Credentials / env vars

None. No secret is read from config or environment.

## Usage example

Opt in (manifest ships `enabled: false`):

```yaml
plugins:
  enabled:
    - wireless

wireless:
  enabled: true
  interface: wlan0mon

exploit:
  allowed_targets:
    - 02:00:00:AA:BB:CC
```

Against your own lab AP (BSSID allowlisted above):

- `wireless_recon(target_ip="02:00:00:AA:BB:CC")`
- `wireless_pmkid_capture(target_ip="02:00:00:AA:BB:CC")`
- `wireless_crack_pmkid(target_ip="02:00:00:AA:BB:CC", capture_path="pmkid_020000AABBCC.pcapng")`

## Safety / advisory-only notes

- **Authorized testing only.** Deauth and capture only against networks you
  own or are explicitly contracted to test; never against unauthorized or
  shared networks.
- The BSSID-as-`target_ip` convention keeps the standard allowlist lock in
  play: an unlisted BSSID is refused before any radio command runs.
- No log clearing, timestomping, EDR/AV defeat, DoS against unauthorized
  networks, or malware distribution.
- External binaries (bettercap, aircrack-ng, hcxdumptool) and a monitor-mode
  interface must exist on the operator box; failures surface a clear error
  (argv-list invocation, no shell).
