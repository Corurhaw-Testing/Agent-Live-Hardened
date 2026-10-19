# Experimental identity-boundary hardening

This development line starts at Agent-Live commit
`40c751a4b10ab3e169e6e6c3b6c50ec762353cb5`. It adds host integration
primitives without changing schema version 1.1 or the v1 hash encoding.
The original example digest remains compatible.

## Trust boundary

The host authenticates users/workloads and builds `Principal` objects from its
own policy. Never deserialize a Principal from model output, memory, an incoming
request body, or the identity's descriptive `capabilities`/`preferences` fields.
These Python objects are a boundary between an authenticated service and its
storage API, not an isolation mechanism against arbitrary code in that process.

The library contains no HTTP listener, dashboard, model worker, or task executor.
Web proxy, browser rendering, SSRF/egress, and tool execution controls belong to
those future components. No cloud infrastructure or live identity is provisioned.

## Bounded records

All records, including extension fields, are subject to these fixed budgets:

| Budget | Limit |
| --- | --- |
| UTF-8 input / canonical payload | 4 MiB |
| Nested objects/arrays | 32 levels |
| Entries per object/array | 10,000 |
| Characters per string/key | 65,536 |
| Traversed value nodes | 100,000 |
| Integer magnitude | 4,096 bits |

File reads stop after the byte limit plus one byte. A quote-aware nesting check
runs before JSON parsing. Iterative structure checks run before schema checking,
deep copies, and hashing. Invalid UTF-8, cycles, duplicate keys, NaN/Infinity, and
non-JSON Python objects are rejected. Pretty-printed snapshot output must also
fit the byte limit. A large legacy record may now be rejected intentionally;
archive/partition it using a reviewed migration rather than disabling all limits.

## Transactional host integration

Install with `python -m pip install '.[signing]'` for signature support.

```python
from pathlib import Path
from persistent_agent import IdentityRecord, IdentityStore, Principal

record = IdentityRecord.load("examples/agent-identity.example.json")
agent_id = record.data["agent_identity"]["agent_id"]
# Demo only: provision a unique UUID for a real independently initialized agent.
# The host obtains this subject and permission grant from trusted authentication.
actor = Principal("authenticated-owner", frozenset({agent_id}),
                  frozenset({"create", "read", "preferences", "append_event"}))

private_dir = Path("/path/to/private/durable/state")  # create/protect separately
store = IdentityStore(private_dir / "identity.sqlite3")
first = store.create(record, actor=actor)  # explicit local bootstrap, once only
second = store.update_preferences(agent_id, {"verbosity": "concise"},
    actor=actor, expected_revision=first.revision)
restored = store.read(agent_id, actor=actor, checkpoint=second.checkpoint)
assert restored.record.data["agent_identity"]["self_model"]["preferences"]["verbosity"] == "concise"
```

Updates replace preferences, update the display name, or append an unsigned
event. They cannot mutate identity UUID, keys, lineage, continuity policy, or
existing events. The event schema still applies; appended events must set
`signed_by_agent` to false because this API does not verify individual event
signatures. Those legacy record flags are descriptive assertions, not proof.

`BEGIN IMMEDIATE` serializes cooperating SQLite writers. Every update compares
the expected revision inside the same transaction that inserts the new snapshot
and audit metadata. One racing stale writer gets `RevisionConflict`; it must
reload and reconcile rather than blindly retrying. Validation failures roll back
without adding a revision. New snapshots link `previous_state_hash` to their
predecessor, and previous snapshots remain available in the database.

`history()` returns up to 100 metadata rows by default, with `after_revision`
pagination and a maximum page size of 1,000. It records actor, operation, revision,
time, and hashes without copying memory text into the audit output.

Use SQLite on private local storage with correct filesystem locking. NFS/shared
network filesystems and multi-host storage are not supported by this design.
New database files use mode 0600; protect the parent directory, existing files,
journals, exports, and backups. The database is not encrypted. Historical rows
retain old memory content: a retention/redaction workflow is still required
before using this store for data subject to deletion obligations.

## Signatures and authenticated import

The optional `cryptography` backend verifies Ed25519 signatures. No private keys
are generated, read, stored, or committed by this package. The host/keystore
signs `signature_payload(record)` after setting the recorded public key and
predecessor hash. The signature field uses `ed25519-v1:` followed by strict
base64 of the 64-byte signature. The message has a versioned domain prefix plus
the existing canonical bytes; it is not a signature over just the digest.

```python
from persistent_agent import verify_signature

# Obtain independently through the host's trusted enrollment/configuration.
pinned_key = "ed25519:" + "...64 lowercase hex characters..."
verify_signature(record, expected_public_key=pinned_key)

# actor needs import_signed permission for this UUID.
accepted = store.import_signed(record, actor=actor,
    expected_public_key=pinned_key, expected_revision=None)  # initial enrollment
```

For subsequent imports, pass the current revision. The signed record's
`previous_state_hash` must match the current snapshot. The existing enrolled
public key must match the host-pinned key; this API does not silently rotate
keys. Key rotation, fork authorization, and recovery need separate reviewed host
workflows. `create()` is an explicitly trusted local bootstrap and clears imported
signature metadata; external inputs requiring authenticity use `import_signed()`.

The CLI can require authentication with:

```console
python -m persistent_agent validate identity.json --verify-key ed25519:PUBLIC_KEY_HEX
```

Default `validate` still checks schema/hash consistency, not signer identity.
`signed_at` is excluded by the legacy canonical encoding and is informational;
signature verification does not authenticate that timestamp or establish
freshness. Store a revision/hash checkpoint separately from the database and pass
it to `read()` to detect restoration of a database older than that checkpoint or
a changed checkpoint row. A first-time enrollment cannot establish freshness
without an independent trust source.

## Remaining responsibilities

- A database owner can rewrite/delete rows. This is application-maintained
  history, not a cryptographically protected append-only service.
- Whole-database rollback cannot be detected without an external checkpoint.
- Low-level `IdentityRecord.dump()` remains a single-writer snapshot utility;
  multi-writer runtimes must use `IdentityStore` consistently.
- `with_state_hash()` deliberately rehashes edits and clears signatures; it does
  not authenticate or authorize those edits.
- Imported text is data. Do not promote memories/preferences into privileged
  instructions, permissions, shell commands, SQL, or executable browser HTML.
- Host policy, private durable storage, backups, key enrollment, retention, and
  incident response remain required.

## Verification

```console
python -m pip install '.[signing]'
python -m unittest -v
python -m pip wheel --no-deps --wheel-dir dist .
```

Regression cases cover import budgets, original digest compatibility, denied
identity/operation scopes, stale revisions, two real racing processes, failed-edit
rollback, restored-database checkpoint rejection, pinned-key authentication,
forged/rehashed state, malformed signatures, and replayed signed imports.
