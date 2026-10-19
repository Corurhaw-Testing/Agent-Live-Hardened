"""Command-line validation and snapshot storage."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .model import IdentityRecord, IdentityValidationError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m persistent_agent",
        description="Validate or save persistent agent identity snapshots.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate", help="validate a record and print its hash")
    validate.add_argument("path", type=Path)
    validate.add_argument("--verify-key", help="host-pinned ed25519:hex public key; require valid signature")
    snapshot = commands.add_parser("snapshot", help="save a validated record with its hash")
    snapshot.add_argument("path", type=Path)
    snapshot.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        record = IdentityRecord.load(args.path)
        if args.command == "validate" and args.verify_key is not None:
            from .signing import verify_signature
            verify_signature(record, expected_public_key=args.verify_key)
        if args.command == "snapshot":
            record = record.with_state_hash()
            record.dump(args.output)
        print(record.state_hash())
    except (IdentityValidationError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
