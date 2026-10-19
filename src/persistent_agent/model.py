"""Validate, hash, load and atomically save persistent identity records.

Private keys and signature verification belong to an external keystore.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from functools import lru_cache
import hashlib
from importlib.resources import files
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Mapping
from uuid import UUID

from jsonschema import Draft202012Validator, FormatChecker
from .errors import IdentityValidationError
from .limits import MAX_BYTES, check_json_nesting, check_structure


@lru_cache(maxsize=1)
def _validator() -> Draft202012Validator:
    schema = json.loads(
        files("persistent_agent").joinpath("persistent-agent.schema.json").read_text("utf-8")
    )
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _canonical_payload(data: Mapping[str, Any]) -> bytes:
    """v1 encoding; output hash, signature and signing time are excluded.

    This project-specific encoding is not RFC 8785 canonical JSON.
    """
    check_structure(data)
    obj = deepcopy(dict(data))
    integrity = obj["agent_identity"]["integrity"]
    for field in ("state_hash", "signature", "signed_at"):
        integrity[field] = None
    try:
        encoded = json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        if len(encoded) > MAX_BYTES:
            raise IdentityValidationError("JSON byte limit exceeded")
        return encoded
    except (TypeError, ValueError, UnicodeError) as exc:
        raise IdentityValidationError("record must contain finite UTF-8 JSON values") from exc


def _digest(data: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical_payload(data)).hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise IdentityValidationError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise IdentityValidationError(f"non-finite JSON constant: {value}")


@dataclass(frozen=True)
class IdentityRecord:
    # Frozen prevents assignment to data; nested state is still mutable.
    # Every public read/write operation revalidates it.
    data: dict[str, Any]

    @classmethod
    def load(cls, path: str | Path) -> "IdentityRecord":
        with Path(path).open("rb") as f:
            raw = f.read(MAX_BYTES + 1)
        return cls.from_bytes(raw)

    @classmethod
    def from_bytes(cls, raw: bytes) -> "IdentityRecord":
        if len(raw) > MAX_BYTES:
            raise IdentityValidationError("JSON byte limit exceeded")
        try:
            text = raw.decode("utf-8")
            check_json_nesting(text)
            data = json.loads(text, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
        except (ValueError, UnicodeError, RecursionError) as exc:
            if isinstance(exc, IdentityValidationError):
                raise
            raise IdentityValidationError("invalid UTF-8 JSON") from exc
        record = cls(data)
        record.validate_core_invariants()
        return record

    def validate_core_invariants(self) -> None:
        """Enforce the complete schema, lineage rules and any stored hash."""
        check_structure(self.data)
        error = next(_validator().iter_errors(self.data), None)
        if error is not None:
            location = ".".join(str(part) for part in error.absolute_path) or "$"
            detail = f"schema {error.validator} constraint failed"
            if error.validator == "required" and isinstance(error.instance, dict):
                missing = [key for key in error.validator_value if key not in error.instance]
                detail += ": missing " + ", ".join(missing)
            raise IdentityValidationError(f"{location}: {detail}")

        identity = self.data["agent_identity"]
        lineage = identity["lineage"]
        agent_id = UUID(identity["agent_id"])
        parent = lineage.get("parent_agent_id")
        if parent and UUID(parent) == agent_id:
            raise IdentityValidationError("an identity cannot be its own parent")
        if lineage["generation"] == 0 and parent is not None:
            raise IdentityValidationError("generation 0 cannot have a parent")
        for field, entries in (
            ("relationships", identity["relationships"]),
            ("event_log", identity["autobiographical_memory"]["event_log"]),
        ):
            id_field = "relationship_id" if field == "relationships" else "event_id"
            ids = [UUID(entry[id_field]) for entry in entries]
            if len(ids) != len(set(ids)):
                raise IdentityValidationError(f"{field} contains duplicate identifiers")

        actual = _digest(self.data)
        stored = identity["integrity"].get("state_hash")
        if stored is not None and stored != actual:
            raise IdentityValidationError("stored state_hash does not match identity state")

    def canonical_bytes(self) -> bytes:
        self.validate_core_invariants()
        return _canonical_payload(self.data)

    def state_hash(self) -> str:
        return "sha256:" + hashlib.sha256(self.canonical_bytes()).hexdigest()

    def with_state_hash(self) -> "IdentityRecord":
        """Rehash an intentional edit and discard stale signature metadata.

        This explicitly permits a new snapshot; it does not authorize a
        migration, verify a signature, or enforce an append-only history.
        """
        check_structure(self.data)
        obj = deepcopy(self.data)
        if not isinstance(obj, dict) or not isinstance(obj.get("agent_identity"), dict):
            self.validate_core_invariants()
        integrity = obj["agent_identity"].get("integrity")
        if not isinstance(integrity, dict):
            self.validate_core_invariants()
        integrity["state_hash"] = None
        integrity["signature"] = None
        integrity["signed_at"] = None
        record = IdentityRecord(obj)
        record.validate_core_invariants()
        integrity["state_hash"] = record.state_hash()
        return record

    def dump(self, path: str | Path) -> None:
        """Validate before atomically replacing a local snapshot."""
        self.validate_core_invariants()
        encoded = json.dumps(self.data, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
        if len(encoded.encode("utf-8")) > MAX_BYTES:
            raise IdentityValidationError("JSON byte limit exceeded")
        target = Path(path)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=target.parent,
                prefix=f".{target.name}.", delete=False,
            ) as f:
                temporary = Path(f.name)
                f.write(encoded)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temporary, target)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
