"""Exercise admission through the public loader, including all-or-nothing failure."""
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from uas.config import ConfigError, load

FIXTURE = Path(__file__).parent / "fixtures" / "two-rooms.json"


def admit(value, **kwargs):
    return load(io.StringIO(json.dumps(value)), **kwargs)


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.config = json.loads(FIXTURE.read_text())

    def invalid(self, document, field):
        with self.assertRaises(ConfigError) as raised:
            admit(document)
        self.assertEqual(field, raised.exception.field)
        self.assertLess(len(str(raised.exception)), 300)

    def test_two_rooms_share_actor_without_sharing_room_state(self):
        result = admit(self.config, available_credentials=["alice-git", "alice-forge"])
        a, b = result["rooms"]
        self.assertEqual(a["seats"][0]["actor"], b["seats"][0]["actor"])
        self.assertNotEqual(a["state_root"], b["state_root"])
        self.assertNotEqual(a["network"]["id"], b["network"]["id"])
        self.assertEqual(a["seats"][0]["resolved"]["room_id"], "alpha")
        self.assertEqual(b["seats"][0]["resolved"]["room_id"], "beta")
        self.assertEqual(a["seats"][0]["resolved"]["credential_status"], "available")
        self.assertEqual(a["seats"][1]["resolved"]["credential_status"], "unavailable")
        self.assertEqual(a["seats"][1]["resolved"]["missing_actor_credentials"], ["git", "forge"])
        self.assertEqual(a["resolved"]["activation"], "not-evaluated")
        self.assertFalse(a["ambient"]["browser"])
        self.assertFalse(a["ambient"]["nested_containers"])
        self.assertEqual(result["capability_enforcement"]["review"], "hub")
        self.assertEqual(result["capability_enforcement"]["git-push"], "broker")

    def test_normalization_does_not_modify_caller_or_share_room_objects(self):
        original = deepcopy(self.config)
        result = admit(self.config)
        result["rooms"][0]["profiles"][0]["instructions"] = "changed"
        self.assertNotEqual(result["rooms"][1]["profiles"][0]["instructions"], "changed")
        self.assertEqual(self.config, original)

    def test_registry_order_is_canonical(self):
        first = admit(self.config)
        self.config["rooms"].reverse()
        for key in ["actors", "credentials", "images", "providers"]:
            self.config["deployment"][key].reverse()
        for room in self.config["rooms"]:
            for key in ["profiles", "policies", "seats"]:
                room[key].reverse()
        self.assertEqual(first, admit(self.config))

    def test_absent_actor_credentials_disable_only_affected_seats(self):
        del self.config["deployment"]["actors"][0]["git_credential_ref"]
        result = admit(self.config, available_credentials=["alice-forge", "bob-git", "bob-forge"])
        for room in result["rooms"]:
            self.assertEqual(room["seats"][0]["resolved"]["missing_actor_credentials"], ["git"])
            self.assertEqual(room["seats"][1]["resolved"]["credential_status"], "available")

    def test_offline_provider_configuration_does_not_probe_inference(self):
        with patch("socket.create_connection", side_effect=AssertionError("network called")):
            result = admit(self.config)
        resolved = result["rooms"][0]["seats"][0]["resolved"]
        self.assertEqual(resolved["provider_configuration"], "valid")
        self.assertEqual(resolved["inference_health"], "unknown")

    def test_unknown_fields_at_each_owned_boundary(self):
        paths = [[], ["deployment"], ["deployment", "manager"], ["deployment", "actors", 0],
                 ["deployment", "credentials", 0], ["deployment", "providers", 0],
                 ["deployment", "audit"], ["deployment", "images", 0], ["rooms", 0],
                 ["rooms", 0, "project"], ["rooms", 0, "project", "roots"],
                 ["rooms", 0, "boundary"], ["rooms", 0, "network"],
                 ["rooms", 0, "resources"], ["rooms", 0, "profiles", 0],
                 ["rooms", 0, "policies", 0], ["rooms", 0, "policies", 0, "gates", 0],
                 ["rooms", 0, "policies", 0, "protected_operations"], ["rooms", 0, "seats", 0]]
        for path in paths:
            with self.subTest(path=path):
                value = deepcopy(self.config)
                target, field = value, "$"
                for key in path:
                    target = target[key]
                    field += f"[{key}]" if isinstance(key, int) else "." + key
                target["unexpected"] = "secret-value-never-echoed"
                self.invalid(value, field + ".unexpected")

    def test_required_fields_and_boundary_controls(self):
        for section in ["boundary", "network", "resources"]:
            for key in self.config["rooms"][0][section]:
                with self.subTest(section=section, key=key):
                    value = deepcopy(self.config)
                    del value["rooms"][0][section][key]
                    self.invalid(value, f"$.rooms[0].{section}.{key}")
        for section in ["boundary", "network"]:
            for key in self.config["rooms"][0][section]:
                if key == "id":
                    continue
                for bad in [False, 1, "true", None]:
                    with self.subTest(key=key, bad=bad):
                        value = deepcopy(self.config)
                        value["rooms"][0][section][key] = bad
                        self.invalid(value, f"$.rooms[0].{section}.{key}")

    def test_malformed_references_and_ambiguous_bindings(self):
        cases = [
            (["version"], 2), (["version"], True), (["rooms", 0, "version"], None),
            (["rooms", 0, "seats", 0, "actor"], "missing"),
            (["rooms", 0, "seats", 0, "profile"], "missing"),
            (["rooms", 0, "seats", 0, "provider"], "missing"),
            (["rooms", 0, "seats", 0, "provider"], "claude-native"),
            (["rooms", 0, "image"], "missing"), (["rooms", 0, "default_policy"], "missing"),
            (["deployment", "actors", 0, "git_credential_ref"], "missing"),
            (["deployment", "actors", 0, "git_credential_ref"], "alice-forge"),
            (["deployment", "manager", "client_credential_ref"], "alice-git"),
            (["rooms", 0, "seats", 1, "participant"], "builder"),
            (["rooms", 1, "project", "id"], "alpha"),
            (["rooms", 1, "project", "repository"], "EXAMPLE/Alpha"),
            (["rooms", 1, "network", "id"], "net-alpha"),
            (["rooms", 0, "seats", 0, "runtime"], "unknown"),
            (["deployment", "images", 0, "reference"], "example/uas:latest"),
            (["deployment", "credentials", 0, "kind"], "runtime-secret"),
            (["rooms", 0, "policies", 0, "protected_operations", "complete", 0], "missing"),
            (["rooms", 0, "profiles", 0, "capabilities", 0], "browser"),
        ]
        for path, bad in cases:
            with self.subTest(path=path, bad=bad):
                value = deepcopy(self.config)
                target, field = value, "$"
                for key in path[:-1]:
                    target = target[key]
                    field += f"[{key}]" if isinstance(key, int) else "." + key
                key = path[-1]
                target[key] = bad
                field += f"[{key}]" if isinstance(key, int) else "." + key
                self.invalid(value, field)

    def test_duplicate_registry_identifiers(self):
        for key in ["actors", "credentials", "images", "providers"]:
            value = deepcopy(self.config)
            value["deployment"][key].append(deepcopy(value["deployment"][key][0]))
            self.invalid(value, f"$.deployment.{key}[{len(value['deployment'][key])-1}].id")
        for key in ["profiles", "policies", "seats"]:
            value = deepcopy(self.config)
            value["rooms"][0][key].append(deepcopy(value["rooms"][0][key][0]))
            self.invalid(value, f"$.rooms[0].{key}[{len(value['rooms'][0][key])-1}].id")

    def test_unsafe_limits_types_and_unbounded_numbers(self):
        for key in self.config["rooms"][0]["resources"]:
            for bad in [0, -1, True, "100", None, float("inf")]:
                with self.subTest(key=key, bad=bad):
                    value = deepcopy(self.config)
                    value["rooms"][0]["resources"][key] = bad
                    self.invalid(value, "$" if bad == float("inf") else f"$.rooms[0].resources.{key}")
        value = deepcopy(self.config)
        value["rooms"][0]["resources"]["log_bytes"] = value["rooms"][0]["resources"]["disk_bytes"] + 1
        self.invalid(value, "$.rooms[0].resources.log_bytes")
        for bad in [0, 6, True]:
            value = deepcopy(self.config)
            value["rooms"][0]["policies"][0]["review_return_cap"] = bad
            self.invalid(value, "$.rooms[0].policies[0].review_return_cap")

    def test_paths_and_cross_room_overlap(self):
        for bad in ["relative", "/", "/srv/../etc", "/srv/x/", "/etc/project", "/srv/uas/state", "/srv/projects/alpha/workspace", "/srv/projects/beta/repo/subdir"]:
            with self.subTest(bad=bad):
                value = deepcopy(self.config)
                value["rooms"][0]["project"]["roots"]["repo"] = bad
                with self.assertRaises(ConfigError):
                    admit(value)
        for bad in ["/srv/other", "/srv/uas/state", "/srv/uas/state/alpha/child"]:
            value = deepcopy(self.config)
            value["rooms"][1]["state_root"] = bad
            self.invalid(value, "$.rooms[1].state_root")
        # Shared read-only references are allowed; writable aliases are not.
        self.config["rooms"][1]["project"]["roots"]["reference"] = self.config["rooms"][0]["project"]["roots"]["reference"]
        admit(self.config)

    def test_filesystem_inspection_is_read_only_and_rejects_symlink_ancestors(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "actual").mkdir()
            (root / "link").symlink_to(root / "actual", target_is_directory=True)
            for suffix in ["link/not-created", "file", "file/child"]:
                (root / "file").write_text("untouched")
                self.config["rooms"][0]["project"]["roots"]["repo"] = str(root / suffix)
                self.invalid(self.config, "$.rooms[0].project.roots.repo")
            self.config["rooms"][0]["project"]["roots"]["repo"] = str(root / "not-created")
            admit(self.config)
            self.assertFalse((root / "not-created").exists())
            self.assertEqual((root / "file").read_text(), "untouched")

    def test_disabled_ambient_and_deferred_local_routing(self):
        for key in ["browser", "nested_containers"]:
            for bad in [True, 0, None]:
                value = deepcopy(self.config)
                value["rooms"][0]["ambient"] = {key: bad}
                self.invalid(value, f"$.rooms[0].ambient.{key}")
        for bad in ["http://api.example.com", "https://localhost", "https://127.0.0.1", "https://127.1", "https://169.254.169.254", "https://10.0.0.1", "https://user:secret@example.com", "https://api.example.com?token=secret"]:
            value = deepcopy(self.config)
            value["deployment"]["providers"][0]["endpoint"] = bad
            self.invalid(value, "$.deployment.providers[0].endpoint")

    def test_bad_json_duplicate_fields_and_size_fail_without_partial_result(self):
        for raw, field in [("{} {}", "$"), ("null", "$"), ('{"version":1,"version":2}', "$.version"), ('{"rooms":[{"id":"a","id":"b"}]}', "$.rooms[0].id"), (" " * (1024 * 1024 + 1), "$")]:
            with self.subTest(field=field):
                with self.assertRaises(ConfigError) as caught:
                    load(io.StringIO(raw))
                self.assertEqual(caught.exception.field, field)
        self.config["rooms"][1]["boundary"]["non_root"] = False
        self.invalid(self.config, "$.rooms[1].boundary.non_root")

    def test_huge_numeric_and_malformed_types_report_fields_not_tracebacks(self):
        self.config["rooms"][0]["project"]["roots"]["repo"] = "/srv/\ud800"
        self.invalid(self.config, "$.rooms[0].project.roots.repo")
        self.config = json.loads(FIXTURE.read_text())
        self.config["rooms"][0]["resources"]["cpu"] = 10**400
        self.invalid(self.config, "$.rooms[0].resources.cpu")
        for raw in ['{"' + 'a'*1000 + '":1}', '['*50 + '0' + ']'*50]:
            with self.assertRaises(ConfigError) as error:
                load(io.StringIO(raw))
            self.assertEqual(error.exception.field, "$")
            self.assertLess(len(str(error.exception)), 200)
        with self.assertRaises(ConfigError):
            load(io.StringIO("\ud800"))

    def test_image_reference_syntax_without_pulling(self):
        suffix = "@sha256:" + "a" * 64
        for name in ["uas", "example/uas", "registry.example.com:5000/team/uas", "example/uas:release-1"]:
            with self.subTest(valid=name):
                self.config["deployment"]["images"][0]["reference"] = name + suffix
                admit(self.config)
        for name in ["https://registry.example.com/uas", "example//uas", "example/", "/uas", "registry.example.com:5000:6000/uas", "registry.example.com:0/uas", "example/Upper", "example/uas::tag", "example/uas:", "example/../uas"]:
            with self.subTest(invalid=name):
                self.config["deployment"]["images"][0]["reference"] = name + suffix
                self.invalid(self.config, "$.deployment.images[0].reference")

    def test_control_characters_except_instruction_linebreaks(self):
        for character in ["\x00", "\x1f", "\x7f", "\x80", "\x9f"]:
            with self.subTest(control=ord(character)):
                self.config["rooms"][0]["profiles"][0]["instructions"] = "text" + character
                self.invalid(self.config, "$.rooms[0].profiles[0].instructions")
        self.config["rooms"][0]["profiles"][0]["instructions"] = "First line\n\tSecond line"
        admit(self.config)

    def test_inventory_cannot_select_unknown_secret(self):
        with self.assertRaises(ConfigError) as error:
            admit(self.config, available_credentials=["not-declared"])
        self.assertEqual(error.exception.field, "$available_credentials[0]")


if __name__ == "__main__":
    unittest.main()
