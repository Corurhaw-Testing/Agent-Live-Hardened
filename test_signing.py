import base64
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
import os
import subprocess
import sys

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:
    Ed25519PrivateKey = None

from test_identity import ROOT
from persistent_agent import IdentityRecord, IdentityValidationError
from persistent_agent.signing import signature_payload, verify_signature
from persistent_agent.store import IdentityStore, Principal, RevisionConflict, AuthorizationError


@unittest.skipIf(Ed25519PrivateKey is None, "install persistent-agent[signing]")
class SigningTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.public = "ed25519:" + self.key.public_key().public_bytes_raw().hex()
        data = deepcopy(IdentityRecord.load(ROOT / "examples/agent-identity.example.json").data)
        data["agent_identity"]["cryptographic_identity"]["public_key"] = self.public
        self.record = self.sign(IdentityRecord(data))

    def sign(self, record):
        record = record.with_state_hash()
        record.data["agent_identity"]["integrity"]["signature"] = "ed25519-v1:" + base64.b64encode(
            self.key.sign(signature_payload(record))).decode("ascii")
        return record

    def test_pinned_key_and_signature(self):
        verify_signature(self.record, expected_public_key=self.public)
        other = "ed25519:" + Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
        with self.assertRaises(IdentityValidationError):
            verify_signature(self.record, expected_public_key=other)

    def test_cli_verifies_a_signed_record(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "signed.json"
            self.record.dump(path)
            env = os.environ.copy()
            env["PYTHONPATH"] = str(ROOT / "src")
            result = subprocess.run([sys.executable, "-m", "persistent_agent", "validate",
                                     str(path), "--verify-key", self.public],
                                    env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), self.record.state_hash())

    def test_rehash_does_not_authenticate_tampering(self):
        data = deepcopy(self.record.data)
        data["agent_identity"]["display_name"] = "unauthorized"
        changed = IdentityRecord(data).with_state_hash()
        changed.data["agent_identity"]["integrity"]["signature"] = self.record.data["agent_identity"]["integrity"]["signature"]
        with self.assertRaises(IdentityValidationError):
            verify_signature(changed, expected_public_key=self.public)

    def test_malformed_and_unsigned_signatures_fail_closed(self):
        for signature in [None, "bad", "ed25519-v1:%%%%", "ed25519-v1:YQ=="]:
            record = deepcopy(self.record)
            record.data["agent_identity"]["integrity"]["signature"] = signature
            with self.assertRaises(IdentityValidationError):
                verify_signature(record, expected_public_key=self.public)

    def test_authenticated_import_and_replay(self):
        agent_id = self.record.data["agent_identity"]["agent_id"]
        actor = Principal("importer", frozenset({agent_id}), frozenset({"import_signed", "read"}))
        with tempfile.TemporaryDirectory() as folder:
            store = IdentityStore(Path(folder) / "state.db")
            first = store.import_signed(self.record, actor=actor, expected_public_key=self.public, expected_revision=None)
            data = deepcopy(self.record.data)
            data["agent_identity"]["display_name"] = "updated"
            data["agent_identity"]["integrity"]["previous_state_hash"] = first.record.state_hash()
            updated = self.sign(IdentityRecord(data))
            second = store.import_signed(updated, actor=actor, expected_public_key=self.public, expected_revision=1)
            verify_signature(second.record, expected_public_key=self.public)
            with self.assertRaises(RevisionConflict):
                store.import_signed(updated, actor=actor, expected_public_key=self.public, expected_revision=1)
            with self.assertRaises(RevisionConflict):
                store.import_signed(self.record, actor=actor, expected_public_key=self.public, expected_revision=2)
            self.assertEqual(store.read(agent_id, actor=actor).checkpoint, second.checkpoint)

    def test_import_does_not_grant_its_own_permissions(self):
        agent_id = self.record.data["agent_identity"]["agent_id"]
        with tempfile.TemporaryDirectory() as folder:
            store = IdentityStore(Path(folder) / "state.db")
            actor = Principal("reader", frozenset({agent_id}), frozenset({"read"}))
            with self.assertRaises(AuthorizationError):
                store.import_signed(self.record, actor=actor, expected_public_key=self.public, expected_revision=None)
            with self.assertRaises(KeyError):
                store.read(agent_id, actor=actor)

    def test_import_cannot_silently_rotate_enrolled_key(self):
        agent_id = self.record.data["agent_identity"]["agent_id"]
        actor = Principal("importer", frozenset({agent_id}), frozenset({"import_signed"}))
        with tempfile.TemporaryDirectory() as folder:
            store = IdentityStore(Path(folder) / "state.db")
            first = store.import_signed(self.record, actor=actor, expected_public_key=self.public, expected_revision=None)
            self.key = Ed25519PrivateKey.generate()
            replacement = "ed25519:" + self.key.public_key().public_bytes_raw().hex()
            data = deepcopy(first.record.data)
            data["agent_identity"]["cryptographic_identity"]["public_key"] = replacement
            data["agent_identity"]["integrity"]["previous_state_hash"] = first.record.state_hash()
            with self.assertRaises(AuthorizationError):
                store.import_signed(self.sign(IdentityRecord(data)), actor=actor,
                                    expected_public_key=replacement, expected_revision=1)
