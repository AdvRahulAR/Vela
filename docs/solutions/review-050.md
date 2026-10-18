# Review of the 0.5.0 controls (nine gaps)

An independent review of the new compliance controls found nine gaps. Each one has a test in `tests/review-050.test.ts`.

| # | Gap | Root cause | Fix |
|---|---|---|---|
| 1 | `client.get()`, `client.delete()` and `client._client.*` passed the SDK wrapper | The read-only allowlist matched method *names* at any depth | Safe names count only on resources; the root and `_` internals are blocked |
| 2 | `redact` values were restored by the legacy `unmask(text, result)` path | Only the session's restorer filtered redactions | `Restorer` drops them, so every path does |
| 3 | `parsed_arguments` and Responses custom-tool and code deltas were restored despite `toolArguments: 'placeholders'` | The tool-argument list was a blocklist of known keys | Known text events are content; everything else is a tool argument |
| 4 | `metadata.id` / `metadata.data` and free-form keys skipped the residual pass, even under `block` | Skip decided by key name alone | Skip only real base64 blobs; mask free-form keys |
| 5 | Signed thinking blocks were rewritten; MCP credentials blocked every MCP request | The residual pass treated everything as text | Thinking blocks unchanged when the client only saw placeholders; MCP credentials are explicit exceptions |
| 6 | One failed audit write broke the chain forever; tail truncation went unnoticed | The chain advanced before the write; truncation can't be self-detected | Advance after a successful write; `expectHead` / `--head` |
| 7 | SDK wrappers wrote no audit events | The control was built into the gateway only | `auditedMethod` shares the trail with every wrapped method |
| 8 | `CREDITCARD: block` was accepted and did nothing | Validation checked only the format of type names | Types must be produced by Vela, an enabled pack, a custom detector or `extraEntityTypes` |
| 9 | Unlimited token guessing on the proxy | The rate limiter ran after authentication | Failed logins are limited per client address |

**Lessons, now in CLAUDE.md:** decide by value, not by name (invariant 3), and every surface gets every control (invariant 5).
