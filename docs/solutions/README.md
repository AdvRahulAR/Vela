# Solutions log

One note per fixed gap: what leaked or broke, why, the invariant that now prevents it, and the test that guards it. Read these before changing an integration; add one after every fix (see `CLAUDE.md`).

| Note | Gaps | Release |
|---|---|---|
| [unmasked-routes.md](unmasked-routes.md) | F1, F2: routes, bodies and SDK methods forwarded unmasked; allowlists and the residual pass | 0.4.1 |
| [audit-and-policy.md](audit-and-policy.md) | F3, F4: audit evidence, declarative policy | 0.5.0 |
| [restoration-and-identifiers.md](restoration-and-identifiers.md) | F5, F7: tool-call restoration, checksum-valid ciphertext | 0.5.0 |
| [proxy-and-keys.md](proxy-and-keys.md) | F8, F9: proxy authentication, tenants, key providers | 0.5.0 |
