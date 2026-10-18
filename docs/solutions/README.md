# Solutions log

One note per fixed gap: what leaked or broke, why, the invariant that now prevents it, and the test that guards it. Read these before changing an integration; add one after every fix (see `CLAUDE.md`).

| Note | Gap | Release |
|---|---|---|
| [unmasked-routes.md](unmasked-routes.md) | Proxy, fetch interceptor and SDK wrappers forwarded unrecognised routes and bodies unmasked | 0.4.1 |
