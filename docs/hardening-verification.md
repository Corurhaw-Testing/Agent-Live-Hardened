# Hardening verification record

Baseline: `40c751a4b10ab3e169e6e6c3b6c50ec762353cb5`.
Development branch: `hardening/identity-boundaries`.
Environment: Python 3.12, Linux, private disposable local databases.

| Requirement | Evidence |
| --- | --- |
| Preserve v1 hashes/schema | Original known example digest test and matching bundled schema tests |
| Bounded imports | File byte, depth, string, collection, aggregate data, cyclic, invalid UTF-8, and non-JSON tests |
| Authorized operations | Denied subject scopes/permissions; preferences cannot replace UUID, keys, lineage, or continuity |
| Coordinated writers | Two real spawned processes start at a barrier; one commit and one revision conflict |
| Transactional failure | Invalid edits and duplicate events leave revision/history unchanged |
| Persistent reload | Separate store instance and separately installed wheel demo reload state |
| Rollback checkpoint | Restored older database is rejected against a separately retained newer checkpoint |
| Authenticity | Host-pinned Ed25519 key, signature verification, rehashed tampering, malformed signatures |
| Import continuity | Signed predecessor check, stale-revision replay rejection, no silent key rotation |
| CLI verification | Signed positive case, unsigned failure, explicit empty key fails closed |

The first resource-limit test run against the baseline failed for the missing
limits, then passed after implementation. Existing behavior tests remain in the
suite. Complete suite: **43 tests passed**, including the signing extra.

Additional checks:

- `git diff --check`: passed.
- Built `persistent_agent-0.2.0-py3-none-any.whl` with pip wheel.
- Installed the wheel and ran the host-store demo outside the source checkout:
  save, reload, checkpoint verification, and stale-write rejection passed.
- Installed-wheel CLI reproduced the original template digest:
  `sha256:1513a95e1273ebefb523aa2beb5bb1f78688fdef13276a28b3e3c0b34d3504eb`.

Python 3.10 execution and remote GitHub Actions remain unverified locally. The
existing CI matrix still targets Python 3.10 and 3.12, now with signing installed.
No deployment or live identity data was used. Limits and remaining host security
responsibilities are documented in `hardening.md`.
