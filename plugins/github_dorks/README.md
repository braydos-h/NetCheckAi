# github_dorks

Authorized-target code-leak discovery via the GitHub Code Search API. Runs a
curated set of dork queries against a target organization's public repos to
find leaked credentials/secrets pre-recon. Advisory-only: returns file paths,
repo names, and capped match metadata — never fetches raw file content and
never touches the target's infrastructure.

Source: `plugins/github_dorks/plugin.yaml`, `plugins/github_dorks/plugin.py`

## Capabilities

Manifest capabilities: `mcp_tool`, `config`. Registers one MCP tool
(`search_github_dorks`) and a `github_dorks` config section.

The curated dork set (`_DEFAULT_DORKS`, `{org}` interpolated):

- `org:{org} password`, `API_KEY`, `SECRET`, `BEGIN PRIVATE KEY`,
  `AWS_ACCESS_KEY`, `extension:env`, `filename:.npmrc`,
  `filename:.dockercfg`, `filename:id_rsa`

## Config keys

No dedicated config block is required. The token is shared with the existing
CVE-lookup GitHub config:

```yaml
cve_lookup:
  github:
    token_env: GITHUB_TOKEN
```

The plugin also registers a `github_dorks` config section (known to
`ConfigValidator`, no unknown-key warning):

| Key       | Type   | Default | Meaning                   |
|-----------|--------|---------|---------------------------|
| `enabled` | `bool` | `false` | Plugin-scoped enable flag |

## Credentials / env vars

- `GITHUB_TOKEN` (default name; override via `cve_lookup.github.token_env`) —
  the GitHub Code Search API is auth-gated and returns 401 without a token.
  Read from the environment, never logged.

## Usage example

The plugin ships with `enabled: true` in its manifest, but the tool refuses
with `BLOCKED:` until the token env var is set (two-gate: manifest opt-in +
token present). To disable entirely:

```yaml
plugins:
  disabled:
    - github_dorks
```

Once the token is set, the agent can call (authorized target orgs only):

- `search_github_dorks(org="example-org")` — runs every curated dork and
  returns `{"org", "results": [{dork, matches, total_count}], "summary"}`
  as JSON. `org` is validated to `[A-Za-z0-9_-]`, 1–39 chars, so a
  prompt-injected org cannot smuggle arbitrary query text into the API. One
  dork failing (e.g. rate-limit) is recorded per-dork and does not abort the
  rest.

## Safety / advisory-only notes

- **Authorized testing only.** Run dorks only against organizations you own
  or are explicitly authorized to assess.
- **Advisory-only.** Never touches the target's infrastructure and never
  fetches raw file content; fetching a leaked file is a separate, audited
  step the agent takes deliberately.
- The tool uses `@ctx.audit_tool`, so every call lands in the JSONL audit
  trail.
- GitHub repo/file names and snippets are untrusted third-party text: the
  plugin returns structured JSON only (path + repo + capped metadata, no raw
  code), strips control characters and caps strings at 200 chars (`_clean`),
  and never auto-executes returned strings.
- Pure stdlib (`urllib`); no new dependency.
