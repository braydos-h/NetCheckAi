# example_recon_report

Reference plugin: the minimum safe shape for a BreachPilot plugin. It
contributes a read-only recon-report attack module plus a trivial
target-locked MCP tool, demonstrating the full plugin contract
(`create_plugin()` factory, manifest loaded from the sibling `plugin.yaml`,
`register()` contributing an attack module and an MCP tool factory). Copy
this plugin as the starting point for new ones.

Source: `plugins/example_recon_report/plugin.yaml`, `plugins/example_recon_report/plugin.py`

## Capabilities

Manifest capabilities: `attack_module`, `mcp_tool`.

- Attack module `example_plugin_recon_report` — read-only recon summary,
  target-locked to `ctx.target_ip`. `applicability()` returns the baseline
  `10`, so it is always selectable but ranks below any module with a real
  service/port/CVE match. `run()` returns an `info`-status dict only; it
  never sets `shell_type` or `privilege_level` because it achieves no
  foothold.
- MCP tool `plugin_info(target_ip)` — returns the static string
  `PLUGIN_INFO: example_recon_report v0.1.0 target=<target_ip>`. Stacks
  `@mcp.tool()` over `@require_allowlist()` exactly like
  `tools/mcp_tools/recon.py`, so the target-IP allowlist lock + JSONL audit
  trail apply automatically.

## Config keys

None. The manifest declares no `config_section` and neither the module nor
the tool reads config. Loading is controlled by the standard plugin
enablement (the manifest ships `enabled: false`).

## Credentials / env vars

None. No secret is read from config or environment, and the tool emits no
credentials.

## Usage example

Opt in (manifest ships `enabled: false`):

```yaml
plugins:
  enabled:
    - example_recon_report

exploit:
  allowed_targets:
    - 127.0.0.1
```

Then, against an authorized target:

- `plugin_info(target_ip="127.0.0.1")`

The `example_plugin_recon_report` module appears in module listings with the
baseline score of 10.

## Safety / advisory-only notes

- **Authorized testing only.** Like all plugins, use only against systems you
  own or are explicitly authorized to assess.
- Read-only and target-locked: no commands execute against the target, no
  shell or privilege is claimed, and the MCP tool passes through the standard
  allowlist + audit decorators.
- No log clearing, timestomping, EDR/AV defeat, DoS, or malware distribution.
- Pure stdlib; no new dependency. New plugins should preserve this shape:
  default-disabled manifest, safety decorators on every MCP tool, and
  workspace-contained artifacts.
