import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).parent


class CommandLineTests(unittest.TestCase):
    def run_cli(self, *args):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
        return subprocess.run(
            [sys.executable, "-m", "persistent_agent", *map(str, args)],
            cwd=ROOT, env=env, capture_output=True, text=True,
        )

    def test_snapshot_survives_separate_process(self):
        source = ROOT / "examples/agent-identity.example.json"
        before = json.loads(source.read_text())
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "identity.json"
            saved = self.run_cli("snapshot", source, "--output", output)
            self.assertEqual(saved.returncode, 0, saved.stderr)
            checked = self.run_cli("validate", output)
            self.assertEqual(checked.returncode, 0, checked.stderr)
            self.assertEqual(saved.stdout, checked.stdout)
            restored = json.loads(output.read_text())
            self.assertEqual(restored["agent_identity"]["agent_id"],
                             before["agent_identity"]["agent_id"])
            self.assertEqual(restored["agent_identity"]["autobiographical_memory"],
                             before["agent_identity"]["autobiographical_memory"])

    def test_invalid_record_does_not_overwrite(self):
        data = json.loads((ROOT / "examples/agent-identity.example.json").read_text())
        del data["agent_identity"]["relationships"]
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "invalid.json"
            source.write_text(json.dumps(data))
            output = Path(folder) / "existing.json"
            output.write_text("existing snapshot")
            result = self.run_cli("snapshot", source, "--output", output)
            self.assertEqual(result.returncode, 1)
            self.assertIn("relationships", result.stderr)
            self.assertEqual(output.read_text(), "existing snapshot")

    def test_missing_input(self):
        result = self.run_cli("validate", ROOT / "absent.json")
        self.assertEqual(result.returncode, 1)
        self.assertIn("error:", result.stderr)

    def test_explicit_empty_verification_key_fails_closed(self):
        result = self.run_cli("validate", ROOT / "examples/agent-identity.example.json", "--verify-key", "")
        self.assertEqual(result.returncode, 1)
        self.assertIn("host-pinned", result.stderr)

    def test_unsigned_record_cannot_pass_required_signature(self):
        result = self.run_cli("validate", ROOT / "examples/agent-identity.example.json", "--verify-key", "ed25519:" + "00" * 32)
        self.assertEqual(result.returncode, 1)


if __name__ == "__main__":
    unittest.main()
