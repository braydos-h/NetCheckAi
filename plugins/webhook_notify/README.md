# webhook_notify

Outbound-only run-status notifications. POSTs a JSON event to an
operator-configured webhook URL (Slack/Discord-compatible) when a run hits a
subscribed milestone so the operator does not have to poll the WebUI.

Source: `plugins/webhook_notify/plugin.yaml`, `plugins/webhook_notify/plugin.py`

## Capabilities

Manifest capabilities: `event_subscriber`, `config`. Registers **no MCP
tools** — it registers an event subscriber via
`PluginRegistry.register_event_subscriber`. The subscriber fires AFTER the
event is persisted to JSONL and pushed to live WebSocket subscribers, so a
slow or down webhook endpoint never blocks the run. Dispatch runs off the
asyncio event-loop thread with a bounded queue/worker pool; `emit()` only
enqueues.

## Config keys

```yaml
webhook_notify:
  enabled: false
  url: ""
  events:
    - finding
    - state
  timeout_seconds: 5
  max_retries: 3
  backoff_seconds: 2.0
  max_payload_chars: 8192
```

| Key               | Type          | Default              | Meaning                                              |
|-------------------|---------------|----------------------|------------------------------------------------------|
| `enabled`         | `bool`        | `false`              | Master switch; subscriber returns immediately unless true |
| `url`             | `str`         | `""`                 | Webhook endpoint. Empty = silent no-op (logged once) |
| `events`          | `list[str]`   | `[finding, state]`   | Event types forwarded; empty list = send nothing     |
| `timeout_seconds` | `int`         | `5`                  | Per-attempt HTTP POST timeout                        |
| `max_retries`     | `int`         | `3`                  | Bounded retries with exponential backoff, then drop  |
| `backoff_seconds` | `float`       | `2.0`                | Base backoff between retries (doubles per attempt)   |
| `max_payload_chars` | `int`       | `8192`               | Payload cap; oversized event JSON is truncated       |

The section is read lazily on each event, so editing `config.yaml` mid-run
is picked up without a restart.

## Credentials / env vars

None. The webhook `url` is a secret held in config: it is never logged in
plaintext (failures log only the URL host via `_url_host`, and the audit
redactor masks `url`/`webhook_url` args).

## Usage example

Opt in via the plugins list (manifest ships `enabled: false`):

```yaml
plugins:
  enabled:
    - webhook_notify

webhook_notify:
  enabled: true
  url: "http://127.0.0.1:8080/hook"
  events:
    - finding
    - state
```

When a `finding` or `state` event fires, the subscriber POSTs the event JSON
to `url` (up to `max_payload_chars`), retrying with backoff and then
dropping with a WARNING. A down endpoint, missing URL, empty event filter,
or oversized payload degrades to a logged no-op — the run always proceeds.

## Safety / advisory-only notes

- **Authorized testing only.** Use only against systems you own or are
  explicitly authorized to assess.
- **Outbound-only.** One HTTP POST per event; no target touch, no inbound
  surface, event fields treated as data (never executed).
- Config read failures can never break `emit()` — a bad config section
  falls back to defaults (disabled).
- Pure stdlib (`urllib` + `time.sleep` backoff); no new dependency.
