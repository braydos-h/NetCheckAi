# firmware_analysis

Firmware analysis plugin: unpacks local IoT firmware images with binwalk for
offline analysis. **Local file analysis only** — no target IP, no network.
Emulation is local too; only if a future variant treats an emulated host as a
target must it switch to `@require_allowlist()` on the emulated target IP.

Source: `plugins/firmware_analysis/plugin.yaml`, `plugins/firmware_analysis/plugin.py`

## Capabilities

Manifest capabilities: `mcp_tool`. Registers one MCP tool, wrapped with
`@audit_tool` (audit trail only, no target touch):

- `unpack_firmware(firmware_path, output_dir="")` — run `binwalk -e -C
  <out> <firmware>` on a local firmware image (argv-list, no shell, 120s
  timeout). Returns `FIRMWARE_UNPACK:` with the output directory (defaults to
  `<firmware>.extracted` next to the image) and up to 50 extracted filenames.
  Returns a clear error when the file is missing, binwalk is not installed,
  binwalk fails, or the run times out — never raises.

## Config keys

None. The manifest declares no `config_section` and the tool reads no config
block or enable flag. Loading is controlled by the standard plugin
enablement (the manifest ships `enabled: true`; disable via
`plugins.disabled`).

## Credentials / env vars

None. No secret is read from config or environment.

## Usage example

The plugin loads by default (manifest `enabled: true`). To disable:

```yaml
plugins:
  disabled:
    - firmware_analysis
```

With binwalk installed on the operator box (`apt install binwalk`), against a
locally obtained image:

- `unpack_firmware(firmware_path="firmware.bin")`
- `unpack_firmware(firmware_path="firmware.bin", output_dir="unpacked")`

## Safety / advisory-only notes

- **Authorized testing only.** Analyze only firmware you own or are
  explicitly authorized to assess (your own devices, vendor-provided images).
- **Local-only.** The firmware path is on the operator box; the tool opens no
  network connection and contacts no target.
- Requires a separately installed `binwalk`; the plugin adds no dependency
  (stdlib `subprocess` only).
