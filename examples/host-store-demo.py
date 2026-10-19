"""Run with an installed package: python examples/host-store-demo.py.

Uses synthetic template data and an automatically removed temporary database.
The host supplies authorization; real deployments use a private durable path.
"""
from pathlib import Path
import tempfile

from persistent_agent import IdentityRecord, IdentityStore, Principal, RevisionConflict


def main():
    record = IdentityRecord.load(Path(__file__).with_name("agent-identity.example.json"))
    agent_id = record.data["agent_identity"]["agent_id"]
    actor = Principal("demo-owner", frozenset({agent_id}),
                      frozenset({"create", "read", "preferences"}))
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "identity.sqlite3"
        store = IdentityStore(path)
        first = store.create(record, actor=actor)
        updated = store.update_preferences(agent_id, {"verbosity": "concise"},
                                           actor=actor, expected_revision=first.revision)
        reloaded = IdentityStore(path).read(agent_id, actor=actor, checkpoint=updated.checkpoint)
        assert reloaded.revision == 2
        try:
            store.update_preferences(agent_id, {}, actor=actor, expected_revision=1)
        except RevisionConflict:
            print("OK: saved, reloaded, checkpoint verified, stale writer rejected")
        else:
            raise AssertionError("stale writer unexpectedly succeeded")


if __name__ == "__main__":
    main()
