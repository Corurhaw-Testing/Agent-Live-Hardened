# Persistent identity and host integration

For the experimental revision-checked multi-writer store, bounded imports, and
optional signed import workflow, see [hardening.md](hardening.md). The simple
save/reload example below remains a low-level single-writer interface.

The durable identity is the record's UUID and associated state. A process label
such as `/root` identifies a runtime role and is not a durable agent UUID.

The record contains self-model information, relationships, autobiographical
events, source provenance, continuity policy, lineage and integrity metadata.
Runtime/model changes can preserve identity when the host applies its continuity
policy. Independent forks need distinct UUIDs and explicit parent lineage.

## Save and reload

```python
from persistent_agent import IdentityRecord

record = IdentityRecord.load("identity.json")
# Apply authorized edits to record.data here.
record.with_state_hash().dump("identity.json")
```

Load the same durable file after restarting the host. Save to a private durable
volume, with a single writer and backups. Local atomic replacement protects
against a partially written snapshot; it does not provide a distributed lock.

The schema is bundled in the installed package. UUIDs, timestamps, required
sections, duplicate event/relationship identifiers and stored hashes are checked.
The executable example supplies a complete record, but its UUID is only for
demonstration. Provision a real agent once and preserve its identifier.

## Hash and signing boundary

The v1 payload is sorted-key UTF-8 JSON with state_hash, signature and signed_at
set to null. NaN and Infinity are rejected. Existing valid v1 example digests
remain compatible. This is a project encoding, not RFC 8785.

The host must keep private keys external and implement signature verification,
authorized migration/fork/recovery, append-only history and rollback detection
where those properties are required. Hash consistency alone does not prove key
ownership or authenticate a record.

## Deployment boundary

This repository publishes a runnable snapshot package and automated build
checks. It contains no model inference worker or autonomous task loop. A model
runtime can integrate the saved record as identity and memory state. Repository
publication does not bind a ChatGPT session automatically to that record.
