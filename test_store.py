from copy import deepcopy
import multiprocessing
from pathlib import Path
import tempfile
import sqlite3
import unittest
from uuid import uuid4

from test_identity import ROOT
from persistent_agent import IdentityRecord, IdentityValidationError
from persistent_agent.store import IdentityStore, Principal, RevisionConflict, AuthorizationError


def concurrent_update(path, agent_id, revision, barrier, queue):
    store = IdentityStore(path)
    actor = Principal("worker", frozenset({agent_id}), frozenset({"read", "preferences"}))
    barrier.wait(timeout=10)
    try:
        store.update_preferences(agent_id, {"worker": multiprocessing.current_process().name},
                                 actor=actor, expected_revision=revision)
        queue.put("saved")
    except RevisionConflict:
        queue.put("conflict")


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name) / "state.sqlite3"
        self.record = IdentityRecord.load(ROOT / "examples/agent-identity.example.json")
        self.agent_id = self.record.data["agent_identity"]["agent_id"]
        self.actor = Principal("host-user", frozenset({self.agent_id}),
                               frozenset({"create", "read", "preferences", "append_event", "display_name"}))
        self.store = IdentityStore(self.path)
        self.initial = self.store.create(self.record, actor=self.actor)

    def test_explicit_creation_cannot_replace_an_identity(self):
        with self.assertRaises(RevisionConflict):
            self.store.create(self.record, actor=self.actor)

    def test_denied_read_and_write_leave_state_unchanged(self):
        for actor in [Principal("other", frozenset(), self.actor.permissions),
                      Principal("reader", self.actor.agent_ids, frozenset({"read"}))]:
            with self.assertRaises(AuthorizationError):
                self.store.update_preferences(self.agent_id, {"x": 1}, actor=actor, expected_revision=1)
        with self.assertRaises(AuthorizationError):
            self.store.read(self.agent_id, actor=Principal("other", frozenset(), frozenset({"read"})))
        self.assertEqual(self.store.read(self.agent_id, actor=self.actor).revision, 1)

    def test_stale_writer_and_restart_checkpoint(self):
        updated = self.store.update_preferences(self.agent_id, {"theme": "dark"}, actor=self.actor, expected_revision=1)
        self.assertEqual(updated.revision, 2)
        with self.assertRaises(RevisionConflict):
            self.store.update_preferences(self.agent_id, {"theme": "light"}, actor=self.actor, expected_revision=1)
        reloaded = IdentityStore(self.path).read(self.agent_id, actor=self.actor,
                                               checkpoint=(2, updated.record.state_hash()))
        self.assertEqual(reloaded.record.data["agent_identity"]["self_model"]["preferences"], {"theme": "dark"})
        with self.assertRaises(RevisionConflict):
            self.store.read(self.agent_id, actor=self.actor, checkpoint=(3, updated.record.state_hash()))

    def test_property_update_cannot_change_identity_or_policy(self):
        original = deepcopy(self.initial.record.data["agent_identity"])
        updated = self.store.update_preferences(self.agent_id, {"agent_id": "attacker", "permissions": ["admin"]},
                                                actor=self.actor, expected_revision=1)
        actual = updated.record.data["agent_identity"]
        for field in ["agent_id", "cryptographic_identity", "lineage", "continuity"]:
            self.assertEqual(actual[field], original[field])

    def test_event_append_and_audit(self):
        event = deepcopy(self.record.data["agent_identity"]["autobiographical_memory"]["event_log"][0])
        event["event_id"] = str(uuid4())
        event["signed_by_agent"] = False
        updated = self.store.append_event(self.agent_id, event, actor=self.actor, expected_revision=1)
        self.assertEqual(len(updated.record.data["agent_identity"]["autobiographical_memory"]["event_log"]), 2)
        history = self.store.history(self.agent_id, actor=self.actor)
        self.assertEqual([(x["revision"], x["actor"], x["operation"]) for x in history],
                         [(1, "host-user", "create"), (2, "host-user", "append_event")])
        self.assertEqual(updated.record.data["agent_identity"]["integrity"]["previous_state_hash"], self.initial.record.state_hash())

    def test_cannot_assert_event_signature_without_verification(self):
        event = deepcopy(self.record.data["agent_identity"]["autobiographical_memory"]["event_log"][0])
        event["event_id"] = str(uuid4()); event["signed_by_agent"] = True
        with self.assertRaises(IdentityValidationError):
            self.store.append_event(self.agent_id, event, actor=self.actor, expected_revision=1)

    def test_invalid_edit_rolls_back(self):
        with self.assertRaises(IdentityValidationError):
            self.store.update_display_name(self.agent_id, 3, actor=self.actor, expected_revision=1)
        self.assertEqual(self.store.read(self.agent_id, actor=self.actor).revision, 1)

    def test_checkpoint_detects_restored_old_database(self):
        old_copy = Path(self.folder.name) / "backup.sqlite3"
        with sqlite3.connect(self.path) as source, sqlite3.connect(old_copy) as backup:
            source.backup(backup)
        latest = self.store.update_display_name(self.agent_id, "new name", actor=self.actor, expected_revision=1)
        restored = IdentityStore(old_copy)
        with self.assertRaises(RevisionConflict):
            restored.read(self.agent_id, actor=self.actor, checkpoint=latest.checkpoint)

    def test_duplicate_event_and_oversized_edit_do_not_add_revision(self):
        event = self.record.data["agent_identity"]["autobiographical_memory"]["event_log"][0]
        event = deepcopy(event); event["signed_by_agent"] = False
        with self.assertRaises(IdentityValidationError):
            self.store.append_event(self.agent_id, event, actor=self.actor, expected_revision=1)
        with self.assertRaises(IdentityValidationError):
            self.store.update_display_name(self.agent_id, "x" * 65537, actor=self.actor, expected_revision=1)
        self.assertEqual(len(self.store.history(self.agent_id, actor=self.actor)), 1)

    def test_two_processes_cannot_overwrite_each_other(self):
        ctx = multiprocessing.get_context("spawn")
        barrier = ctx.Barrier(2); queue = ctx.Queue()
        workers = [ctx.Process(target=concurrent_update, args=(str(self.path), self.agent_id, 1, barrier, queue)) for _ in range(2)]
        for worker in workers: worker.start()
        try:
            results = [queue.get(timeout=20) for _ in workers]
            for worker in workers:
                worker.join(timeout=10)
                self.assertEqual(worker.exitcode, 0)
            self.assertCountEqual(results, ["saved", "conflict"])
            self.assertEqual(self.store.read(self.agent_id, actor=self.actor).revision, 2)
        finally:
            for worker in workers:
                if worker.is_alive(): worker.terminate(); worker.join()
            queue.close()
