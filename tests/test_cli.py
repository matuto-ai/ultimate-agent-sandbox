"""The same CLI used by operators returns normalized JSON or one bounded error."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CLITests(unittest.TestCase):
    def run_cli(self, *args, input=None):
        return subprocess.run([sys.executable, "-m", "uas", "validate-config", *args], cwd=ROOT, input=input, text=True, capture_output=True)

    def test_fixture_is_usable_without_credentials_or_services(self):
        result = self.run_cli("tests/fixtures/two-rooms.json")
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual([r["id"] for r in data["rooms"]], ["alpha", "beta"])
        self.assertTrue(all(s["resolved"]["credential_status"] == "unavailable" for r in data["rooms"] for s in r["seats"]))
        self.assertEqual(result.stderr, "")

    def test_invalid_second_room_produces_no_partial_stdout(self):
        data = json.loads((ROOT / "tests/fixtures/two-rooms.json").read_text())
        del data["rooms"][1]["boundary"]["process_binding"]
        result = self.run_cli("-", input=json.dumps(data))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(json.loads(result.stderr)["field"], "$.rooms[1].boundary.process_binding")

    def test_unreadable_file_does_not_disclose_path(self):
        result = self.run_cli("/not-a-real-directory/private-key")
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("private-key", result.stderr)
        self.assertEqual(json.loads(result.stderr)["error"], "CONFIG_UNREADABLE")

    def test_inventory_is_reference_only_and_not_activation(self):
        result = self.run_cli("tests/fixtures/two-rooms.json", "--available-credential", "alice-git", "--available-credential", "alice-forge")
        self.assertEqual(result.returncode, 0, result.stderr)
        seat = json.loads(result.stdout)["rooms"][0]["seats"][0]
        self.assertEqual(seat["resolved"]["credential_status"], "available")
        self.assertEqual(seat["resolved"]["activation"], "not-evaluated")


if __name__ == "__main__":
    unittest.main()
