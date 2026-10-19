from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from test_identity import ROOT
from persistent_agent import IdentityRecord, IdentityValidationError


class ImportLimitsTests(unittest.TestCase):
    def test_oversized_file_rejected_before_json_parsing(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "large.json"
            path.write_bytes(b" " * (4 * 1024 * 1024 + 1))
            with self.assertRaisesRegex(IdentityValidationError, "byte limit"):
                IdentityRecord.load(path)

    def test_deep_json_rejected_without_recursion_error(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "deep.json"
            path.write_text("[" * 2000 + "0" + "]" * 2000)
            with self.assertRaisesRegex(IdentityValidationError, "nesting"):
                IdentityRecord.load(path)

    def test_extension_fields_are_bounded(self):
        original = IdentityRecord.load(ROOT / "examples/agent-identity.example.json")
        for extension in ["x" * 65537, list(range(10001))]:
            data = deepcopy(original.data)
            data["agent_identity"]["self_model"]["extra"] = extension
            with self.assertRaises(IdentityValidationError):
                IdentityRecord(data).with_state_hash()

    def test_cyclic_in_memory_data_rejected(self):
        data = {}; data["loop"] = data
        with self.assertRaisesRegex(IdentityValidationError, "cyclic"):
            IdentityRecord(data).validate_core_invariants()

    def test_total_bytes_bound_across_individually_valid_strings(self):
        original = IdentityRecord.load(ROOT / "examples/agent-identity.example.json")
        original.data["agent_identity"]["self_model"]["extra"] = ["x" * 65536] * 65
        with self.assertRaisesRegex(IdentityValidationError, "byte limit"):
            original.with_state_hash()

    def test_invalid_utf8_and_non_json_extension_values(self):
        for value in ["\ud800", {1, 2}, b"bytes"]:
            original = IdentityRecord.load(ROOT / "examples/agent-identity.example.json")
            original.data["agent_identity"]["self_model"]["extra"] = value
            with self.assertRaises(IdentityValidationError):
                original.with_state_hash()

    def test_structural_characters_inside_strings_are_not_nesting(self):
        record = IdentityRecord.load(ROOT / "examples/agent-identity.example.json")
        record.data["agent_identity"]["display_name"] = '[{"' * 100
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "identity.json"
            record.with_state_hash().dump(path)
            self.assertEqual(IdentityRecord.load(path).data["agent_identity"]["display_name"], '[{"' * 100)
