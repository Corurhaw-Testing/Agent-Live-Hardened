"""Host-authorized edits and transactional, revision-checked local persistence.

The host authenticates callers and constructs Principals from trusted policy.
Neither identity JSON nor a model response may grant these permissions.
"""
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
from uuid import UUID

from .model import IdentityRecord, IdentityValidationError


class AuthorizationError(PermissionError):
    """The host-supplied principal lacks an operation or identity scope."""


class RevisionConflict(ValueError):
    """State changed, or a separately retained checkpoint cannot be verified."""


@dataclass(frozen=True)
class Principal:
    subject: str
    agent_ids: frozenset[str]
    permissions: frozenset[str]

    def __post_init__(self):
        if not isinstance(self.subject, str) or not self.subject or len(self.subject) > 256:
            raise ValueError("principal requires a bounded subject identifier")
        object.__setattr__(self, "agent_ids", frozenset(str(UUID(x)) for x in self.agent_ids))
        object.__setattr__(self, "permissions", frozenset(self.permissions))

    def require(self, operation: str, agent_id: str) -> str:
        identity = str(UUID(agent_id))
        if identity not in self.agent_ids or operation not in self.permissions:
            raise AuthorizationError("operation or identity scope denied")
        return identity


@dataclass(frozen=True)
class Snapshot:
    revision: int
    record: IdentityRecord

    @property
    def checkpoint(self) -> tuple[int, str]:
        return self.revision, self.record.state_hash()


class IdentityStore:
    """SQLite store for a private local disk; all cooperating writers use this API.

    Revision checks and audit rows commit in the same transaction. Protect the
    database directory using OS access control. This is not a sandbox against
    callers with arbitrary Python execution or direct database access.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        # New database files are private even under a permissive process umask.
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            if self.path.is_symlink() or not self.path.is_file():
                raise ValueError("database must be a regular file in a trusted directory")
        else:
            os.close(fd)
        with self._connection(write=True) as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS snapshots (
                agent_id TEXT NOT NULL, revision INTEGER NOT NULL,
                state_hash TEXT NOT NULL, previous_hash TEXT,
                actor TEXT NOT NULL, operation TEXT NOT NULL, saved_at TEXT NOT NULL,
                payload TEXT NOT NULL, PRIMARY KEY (agent_id, revision)
            )""")

    @contextmanager
    def _connection(self, *, write=False):
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _head(connection, agent_id):
        return connection.execute(
            "SELECT * FROM snapshots WHERE agent_id=? ORDER BY revision DESC LIMIT 1",
            (agent_id,),
        ).fetchone()

    @staticmethod
    def _decode(row) -> Snapshot:
        if row is None:
            raise KeyError("identity not found")
        record = IdentityRecord.from_bytes(row["payload"].encode("utf-8"))
        if str(UUID(record.data["agent_identity"]["agent_id"])) != row["agent_id"] or record.state_hash() != row["state_hash"]:
            raise IdentityValidationError("stored snapshot metadata mismatch")
        if row["revision"] > 1 and record.data["agent_identity"]["integrity"].get("previous_state_hash") != row["previous_hash"]:
            raise IdentityValidationError("stored snapshot predecessor mismatch")
        return Snapshot(row["revision"], record)

    @staticmethod
    def _insert(connection, record, revision, previous_hash, actor, operation):
        # Round-trip detaches caller-owned mutable data and applies wire budgets.
        payload = json.dumps(record.data, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        record = IdentityRecord.from_bytes(payload.encode("utf-8"))
        agent_id = str(UUID(record.data["agent_identity"]["agent_id"]))
        connection.execute("INSERT INTO snapshots VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (
            agent_id, revision, record.state_hash(), previous_hash, actor.subject,
            operation, datetime.now(timezone.utc).isoformat(), payload,
        ))
        return Snapshot(revision, record)

    def create(self, record: IdentityRecord, *, actor: Principal) -> Snapshot:
        """Explicit trusted bootstrap; importing an external record uses import_signed."""
        record.validate_core_invariants()
        # Freeze before authorization so caller mutations cannot switch identities.
        record = IdentityRecord.from_bytes(record.canonical_bytes()).with_state_hash()
        agent_id = actor.require("create", record.data["agent_identity"]["agent_id"])
        with self._connection(write=True) as connection:
            if self._head(connection, agent_id) is not None:
                raise RevisionConflict("identity already exists")
            return self._insert(connection, record, 1, None, actor, "create")

    def import_signed(self, record: IdentityRecord, *, actor: Principal,
                      expected_public_key: str, expected_revision: int | None) -> Snapshot:
        """Import a host-authorized signed snapshot with pinned key and predecessor.

        None means first enrollment only. Existing identities require their current
        revision and a signed previous_state_hash. Key rotation needs a separate
        host enrollment workflow; this method will not silently rotate keys.
        """
        from .signing import verify_signature
        record.validate_core_invariants()
        record = IdentityRecord.from_bytes(json.dumps(record.data, ensure_ascii=False,
            allow_nan=False, separators=(",", ":")).encode("utf-8"))
        agent_id = actor.require("import_signed", record.data["agent_identity"]["agent_id"])
        if expected_revision is not None and (type(expected_revision) is not int or expected_revision < 1):
            raise ValueError("expected revision must be positive or None for enrollment")
        verify_signature(record, expected_public_key=expected_public_key)
        with self._connection(write=True) as connection:
            row = self._head(connection, agent_id)
            if expected_revision is None:
                if row is not None:
                    raise RevisionConflict("identity already enrolled")
                revision, previous_hash = 1, None
            else:
                current = self._decode(row)
                if current.revision != expected_revision:
                    raise RevisionConflict("stale revision")
                if current.record.data["agent_identity"]["cryptographic_identity"].get("public_key") != expected_public_key:
                    raise AuthorizationError("key rotation requires an explicit host enrollment workflow")
                previous_hash = current.record.state_hash()
                if record.data["agent_identity"]["integrity"].get("previous_state_hash") != previous_hash:
                    raise RevisionConflict("signed predecessor does not match current state")
                revision = current.revision + 1
            return self._insert(connection, record, revision, previous_hash, actor, "import_signed")

    def read(self, agent_id: str, *, actor: Principal, checkpoint: tuple[int, str] | None = None) -> Snapshot:
        agent_id = actor.require("read", agent_id)
        with self._connection() as connection:
            snapshot = self._decode(self._head(connection, agent_id))
            if checkpoint is not None:
                revision, digest = checkpoint
                row = connection.execute("SELECT state_hash FROM snapshots WHERE agent_id=? AND revision=?",
                                         (agent_id, revision)).fetchone()
                if snapshot.revision < revision or row is None or row["state_hash"] != digest:
                    raise RevisionConflict("retained checkpoint does not match stored history")
            return snapshot

    def _edit(self, agent_id, operation, value, *, actor, expected_revision):
        agent_id = actor.require(operation, agent_id)
        if type(expected_revision) is not int or expected_revision < 1:
            raise ValueError("a positive expected revision is required")
        # Bound and detach untrusted operation arguments before opening a write transaction.
        from .limits import check_structure
        check_structure(value)
        value = deepcopy(value)
        with self._connection(write=True) as connection:
            current = self._decode(self._head(connection, agent_id))
            if current.revision != expected_revision:
                raise RevisionConflict("stale revision; reload and reconcile changes")
            data = deepcopy(current.record.data)
            identity = data["agent_identity"]
            if operation == "preferences":
                if type(value) is not dict:
                    raise IdentityValidationError("preferences must be an object")
                identity["self_model"]["preferences"] = value
            elif operation == "display_name":
                identity["display_name"] = value
            elif operation == "append_event":
                if type(value) is not dict or value.get("signed_by_agent") is not False:
                    raise IdentityValidationError("appended events must not claim an unverified signature")
                identity["autobiographical_memory"]["event_log"].append(value)
            else:
                raise AuthorizationError("unsupported edit operation")
            identity["integrity"]["previous_state_hash"] = current.record.state_hash()
            updated = IdentityRecord(data).with_state_hash()
            return self._insert(connection, updated, current.revision + 1,
                                current.record.state_hash(), actor, operation)

    def update_preferences(self, agent_id, preferences, *, actor, expected_revision):
        """Replace preference data only; these values never confer permissions."""
        return self._edit(agent_id, "preferences", preferences, actor=actor, expected_revision=expected_revision)

    def update_display_name(self, agent_id, display_name, *, actor, expected_revision):
        return self._edit(agent_id, "display_name", display_name, actor=actor, expected_revision=expected_revision)

    def append_event(self, agent_id, event, *, actor, expected_revision):
        return self._edit(agent_id, "append_event", event, actor=actor, expected_revision=expected_revision)

    def history(self, agent_id, *, actor, after_revision=0, limit=100):
        """Bounded audit metadata; memory content is not duplicated into audit output."""
        agent_id = actor.require("read", agent_id)
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("history limit must be 1..1000")
        if type(after_revision) is not int or after_revision < 0:
            raise ValueError("invalid history cursor")
        with self._connection() as connection:
            rows = connection.execute("""SELECT revision, state_hash, previous_hash, actor, operation, saved_at
                FROM snapshots WHERE agent_id=? AND revision>? ORDER BY revision LIMIT ?""",
                (agent_id, after_revision, limit)).fetchall()
            return [dict(row) for row in rows]
