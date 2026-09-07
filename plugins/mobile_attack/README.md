# mobile_attack

Mobile testing integration: apktool/jadx for local APK static analysis and
Frida (`frida`, `frida-ps`) for remote device instrumentation. Local APK work
never touches a target; device-touching tools are allowlist-gated with the
device IP/host as the target.

Source: `plugins/mobile_attack/plugin.yaml`, `plugins/mobile_attack/plugin.py`

## Capabilities

Manifest capabilities: `mcp_tool`. Registers four MCP tools:

- `mobile_apk_decompile(apk_path, decompiler="apktool")` — decompile a local
  APK with apktool (`d -f -o <stem>_apktool`) or jadx (`-d <stem>_jadx`).
  `@audit_tool` (local-only, no target touch). Refuses with `BLOCKED:` unless
  `mobile_attack.enabled` is true, the APK exists (relative paths resolve
  under the workspace), and the decompiler exits 0.
- `mobile_apk_inspect(apk_path)` — grep a decompiled APK tree for insecure
  `http://` endpoints and hardcoded secrets (`password`/`secret`/`api_key`/
  `token`); skips image/`.so`/`.dex` files; caps output at 100 findings.
  `@audit_tool`. Given a raw `.apk` it asks you to run
  `mobile_apk_decompile` first.
- `mobile_frida_attach(target_ip, app_id, script_path="")` — attach a Frida
  script to a running app on a remote device (`frida -H
  <target_ip>:<frida_server_port> <app_id> [-l <script>]`).
  `@require_allowlist(target_param="target_ip", audit=True)` — the device
  IP/host must be in `exploit.allowed_targets`.
- `mobile_frida_list_apps(target_ip)` — list running apps via `frida-ps -H
  <target_ip>:<frida_server_port>`.
  `@require_allowlist(target_param="target_ip", audit=True)`.

All four tools refuse with `BLOCKED:` unless `mobile_attack.enabled` is true
(double-gate: `plugins.enabled` + section flag). The frida-server must already
be running on the device.

## Config keys

```yaml
mobile_attack:
  enabled: false
  frida_server_host: ""
  frida_server_port: 27042
  apktool_path: apktool
  jadx_path: jadx
  local_analysis_only: true
```

| Key                   | Type   | Default   | Meaning                                                     |
|-----------------------|--------|-----------|-------------------------------------------------------------|
| `enabled`             | `bool` | `false`   | Section flag; every tool refuses without it                 |
| `frida_server_host`   | `str`  | `""`      | Manifest-declared; device host comes from `target_ip` instead |
| `frida_server_port`   | `int`  | `27042`   | Frida-server port on the device                             |
| `apktool_path`        | `str`  | `apktool` | apktool binary (`shutil.which` resolved)                    |
| `jadx_path`           | `str`  | `jadx`    | jadx binary (`shutil.which` resolved)                       |
| `local_analysis_only` | `bool` | `true`    | Manifest-declared posture flag; not read at call time       |

## Credentials / env vars

None. No secret is read from config or environment. The device-side
frida-server is assumed already authenticated/running by the operator.

## Usage example

Opt in (manifest ships `enabled: false`):

```yaml
plugins:
  enabled:
    - mobile_attack

mobile_attack:
  enabled: true
  frida_server_port: 27042

exploit:
  allowed_targets:
    - 127.0.0.1
```

Local analysis (no target touch):

- `mobile_apk_decompile(apk_path="app.apk")`
- `mobile_apk_inspect(apk_path="app_apktool")`

Device instrumentation (authorized device only):

- `mobile_frida_list_apps(target_ip="127.0.0.1")`
- `mobile_frida_attach(target_ip="127.0.0.1", app_id="com.example.app")`

## Safety / advisory-only notes

- **Authorized testing only.** Instrument only devices you own or are
  explicitly authorized to test.
- Local APK tools use `@audit_tool` (audit trail only); device tools use
  `@require_allowlist()` so the target-IP allowlist lock + JSONL audit trail
  apply automatically.
- No log clearing, timestomping, EDR/AV defeat, DoS, or malware distribution.
- External binaries (`frida`, `frida-ps`, `apktool`, `jadx`) must be installed
  separately; missing binaries surface a clear error, never a shell fallback
  (argv-list invocation, no shell).
