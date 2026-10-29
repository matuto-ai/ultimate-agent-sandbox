"""Library contract seam and fail-closed settings admission, with no effects."""
from copy import deepcopy
from dataclasses import replace
import io
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from uas import config as deployment_config
from uas import library
from uas import library_bundle
from uas.ledger import Origin
from uas.manager_actions import HumanSession

AT = "2026-10-28T22:00:00+00:00"
FIXTURE = Path(__file__).parent / "fixtures" / "two-rooms.json"
ORIGIN = Origin("actor-alpha", "seat-a", "inc-1", "epoch-1", ("implement", "library:enqueue"))
REVOKED = Origin("actor-alpha", "seat-a", "inc-1", "epoch-2", ("implement",))
OTHER = Origin("actor-beta", "seat-b", "inc-2", "epoch-2", ("library:enqueue",))
HUMAN = Origin("human", "human-seat", "inc-human", "human-epoch", ("human-control-run",))


def document():
    return {
        "version": 1,
        "repository": {"target": "ssh://git@git.example.com/library.git",
                       "branch": "library/canonical", "credential_ref": "target-cred",
                       "qualification_ref": "target-qualification"},
        "model": {"profile_ref": "synth-local", "placement": "local",
                  "qualification_ref": "synth-qualification"},
        "filters": dict(library.INITIAL_FILTERS),
        "limits": dict(library.INITIAL_LIMITS),
    }


def admit(settings=None, egress=()):
    return library.admit_settings(io.StringIO(json.dumps(document() if settings is None else settings)),
                                  egress_approvals=egress)


def binding(project_id="alpha", repository="acme/alpha", source="1001"):
    return library.project_binding({"id": project_id, "repository": repository,
                                    "roots": {"reference": "/srv/" + project_id + "/reference"}},
                                   source_identity=source)


def session(allowed=("library-drain",), connected=True):
    return HumanSession("deployment", "room", "instance", "manager", HUMAN,
                        lambda _session, action: action in allowed, lambda: connected)


def capture(settings, scope=None, *, operation_id="op-1", request_id="request-1", value=None):
    return library.capture(scope or library.participant_scope(ORIGIN, binding=binding()),
                           settings, operation_id=operation_id, request_id=request_id,
                           value=value or {"type": "decision", "title": "Pick SQLite",
                                           "body": "We picked SQLite.\n",
                                           "sources": [{"resource": "decisions/pick-sqlite.md"}]},
                           at=AT)


def hosted(egress=()):
    settings = document()
    settings["model"]["placement"] = "hosted"
    return admit(settings, egress=egress)


EGRESS = {"project_id": "alpha", "model_profile_ref": "synth-local",
          "approval_ref": "egress-approval-1"}


class SettingsAdmissionTests(unittest.TestCase):
    def test_explicit_initial_values_and_stable_identity(self):
        settled = {"title_chars": 200, "body_bytes": 16384, "sources": 16,
                   "payload_bytes": 32768, "batch_drafts": 8,
                   "batch_bytes": 65536, "attempt_seconds": 120,
                   "warning_seconds": 86400, "result_count": 8}
        self.assertEqual(settled, {key: library.INITIAL_LIMITS[key] for key in settled})
        admitted = admit()
        self.assertEqual(library.INITIAL_LIMITS, admitted["limits"])
        self.assertRegex(admitted["settings_id"], r"^[0-9a-f]{64}$")
        self.assertEqual(admitted["settings_id"], admit()["settings_id"])
        self.assertEqual([], admitted["egress"])
        self.assertIsNot(admitted["limits"], library.INITIAL_LIMITS)

    def test_missing_or_unknown_setting_fails_closed_without_defaults(self):
        settings = document()
        del settings["limits"]["title_chars"]
        with self.assertRaises(library.LibraryError) as raised:
            admit(settings)
        self.assertEqual(("MISSING_FIELD", "limits.title_chars"),
                         (raised.exception.code, raised.exception.field))
        settings = document()
        settings["limits"]["unbounded"] = 10
        with self.assertRaises(library.LibraryError) as raised:
            admit(settings)
        self.assertEqual("UNKNOWN_FIELD", raised.exception.code)

    def test_unsafe_nonfinite_and_conflicting_bounds_are_refused(self):
        cases = [("limits", "title_chars", 513, "INVALID_INTEGER"),
                 ("limits", "body_bytes", 0, "INVALID_INTEGER"),
                 ("limits", "batch_bytes", 1024, "CONFLICTING_SETTING"),
                 ("version", None, 2, "UNSUPPORTED_SETTINGS_VERSION")]
        for section, key, value, code in cases:
            settings = document()
            if key is None:
                settings[section] = value
            else:
                settings[section][key] = value
            with self.subTest(code=code), self.assertRaises(library.LibraryError) as raised:
                admit(settings)
            self.assertEqual(code, raised.exception.code)
        with self.assertRaises(library.LibraryError) as raised:
            library.admit_settings(io.StringIO(
                '{"version":1,"version":1,"repository":{},"model":{},"limits":{}}'))
        self.assertEqual("DUPLICATE_FIELD", raised.exception.code)
        with self.assertRaises(library.LibraryError):
            library.admit_settings(io.StringIO('[1]'))

    def test_canonical_target_branch_and_references_are_distinct_inputs(self):
        for target in ("/srv/library.git", "file:///srv/library.git",
                       "https://user:secret@git.example.com/library.git",
                       "https://git.example.com/library.git"):
            settings = document()
            settings["repository"]["target"] = target
            with self.subTest(target=target):
                if target.startswith("https://git."):
                    admit(settings)
                else:
                    with self.assertRaises(library.LibraryError) as raised:
                        admit(settings)
                    self.assertEqual("UNSAFE_TARGET", raised.exception.code)
        for target in ("ssh://git:fixture-password@git.example.com/library.git",
                       "ssh://git.example.com/library.git",
                       "ssh://g it@git.example.com/library.git"):
            settings = document()
            settings["repository"]["target"] = target
            with self.subTest(target=target), self.assertRaises(library.LibraryError) as raised:
                admit(settings)
            self.assertEqual("UNSAFE_TARGET", raised.exception.code)
        for branch in ("-library", "a..b", "library/", "library//canonical",
                       "folder.lock/canonical", ".hidden/canonical"):
            settings = document()
            settings["repository"]["branch"] = branch
            with self.subTest(branch=branch), self.assertRaises(library.LibraryError) as raised:
                admit(settings)
            self.assertEqual("UNSAFE_BRANCH", raised.exception.code)
        settings = document()
        settings["repository"]["credential_ref"] = "token with spaces"
        with self.assertRaises(library.LibraryError):
            admit(settings)

    def test_secret_filter_modes_are_finite_settings(self):
        self.assertEqual({"high_confidence": "block", "heuristic": "observe"},
                         library.INITIAL_FILTERS)
        settings = document()
        del settings["filters"]
        with self.assertRaises(library.LibraryError) as raised:
            admit(settings)
        self.assertEqual(("MISSING_FIELD", "$.filters"), (raised.exception.code,
                                                           raised.exception.field))
        for mode in ("sometimes", "off", True):
            settings = document()
            settings["filters"]["heuristic"] = mode
            with self.subTest(mode=mode), self.assertRaises(library.LibraryError) as raised:
                admit(settings)
            self.assertEqual("UNSAFE_SETTING", raised.exception.code)
        blocking = document()
        blocking["filters"]["heuristic"] = "block"
        self.assertNotEqual(admit()["settings_id"], admit(blocking)["settings_id"])

    def test_mutated_settings_fail_closed_at_operation_start(self):
        admitted = admit()
        for change, code in (
                (dict(admitted, limits={**admitted["limits"], "title_chars": "9"}),
                 "INVALID_INTEGER"),
                (dict(admitted, limits={**admitted["limits"], "title_chars": 201}),
                 "CONFIGURATION_MISMATCH"),
                (dict(admitted, model={**admitted["model"], "placement": "Hosted"}),
                 "UNSAFE_SETTING"),
                (dict(admitted, filters={"high_confidence": "block", "heuristic": "off"}),
                 "UNSAFE_SETTING"),
                (dict(admitted, egress=[{"project_id": "alpha"}]), "MISSING_FIELD")):
            with self.subTest(code=code), self.assertRaises(library.LibraryError) as raised:
                capture(change)
            self.assertEqual(code, raised.exception.code)
        capture(admit(egress=[EGRESS]))
        approved = hosted(egress=[EGRESS])
        stale = dict(approved, egress=[dict(EGRESS, model_profile_ref="synth-other")])
        with self.assertRaises(library.LibraryError) as raised:
            library.action(library.human_scope(session(), binding=binding(), kind="drain"),
                           stale, kind="drain", operation_id="op-drain",
                           request_id="request-drain", at=AT,
                           payload={"observed_version": "a" * 64})
        self.assertEqual("CONFLICTING_EGRESS", raised.exception.code)

    def test_unadmitted_settings_fail_typed_at_operation_start(self):
        for value, code in ((None, "INVALID_SETTINGS"), ({}, "UNSUPPORTED_SETTINGS_VERSION"),
                            ({"version": 1}, "INVALID_CONTRACT")):
            with self.subTest(code=code), self.assertRaises(library.LibraryError) as raised:
                capture(value)
            self.assertEqual(code, raised.exception.code)
        with self.assertRaises(library.LibraryError) as raised:
            library.action(library.human_scope(session(), binding=binding(), kind="drain"),
                           {}, kind="drain", operation_id="op", request_id="request", at=AT,
                           payload={"observed_version": "a" * 64})
        self.assertEqual("UNSUPPORTED_SETTINGS_VERSION", raised.exception.code)

    def test_egress_is_a_separate_project_approval_not_settings(self):
        self.assertEqual(admit()["settings_id"], admit(egress=[EGRESS])["settings_id"])
        approved = admit(egress=[EGRESS])
        self.assertEqual(EGRESS, library.egress_approval(approved, "alpha"))
        with self.assertRaises(library.LibraryError) as raised:
            library.egress_approval(approved, "beta")
        self.assertEqual("EGRESS_NOT_AUTHORIZED", raised.exception.code)
        mismatched = dict(EGRESS, model_profile_ref="synth-other")
        with self.assertRaises(library.LibraryError) as raised:
            admit(egress=[mismatched])
        self.assertEqual("CONFLICTING_EGRESS", raised.exception.code)
        with self.assertRaises(library.LibraryError) as raised:
            admit(egress=[EGRESS, dict(EGRESS, approval_ref="egress-approval-2")])
        self.assertEqual("CONFLICTING_EGRESS", raised.exception.code)

    def test_profiles_can_declare_the_specified_library_capability(self):
        raw = json.loads(FIXTURE.read_text())
        raw["rooms"][0]["profiles"][0]["capabilities"].append("library:enqueue")
        admitted = deployment_config.load(io.StringIO(json.dumps(raw)))
        self.assertEqual("hub", admitted["capability_enforcement"]["library:enqueue"])
        raw = json.loads(FIXTURE.read_text())
        raw["rooms"][0]["profiles"][0]["capabilities"].append("library-enqueue")
        with self.assertRaises(deployment_config.ConfigError):
            deployment_config.load(io.StringIO(json.dumps(raw)))


class ScopeTests(unittest.TestCase):
    def test_participant_scope_requires_authenticated_capability(self):
        scope = library.participant_scope(ORIGIN, binding=binding())
        self.assertEqual(("participant", "alpha", "github.com/1001"),
                         (scope.subject, scope.project_id, scope.project_identity))
        self.assertEqual("github.com/acme/alpha", scope.project_path)
        self.assertTrue(scope.reference_root.endswith("/library"))
        with self.assertRaises(library.LibraryError) as raised:
            library.participant_scope(REVOKED, binding=binding())
        self.assertEqual("FORBIDDEN", raised.exception.code)
        with self.assertRaises(library.LibraryError):
            library.participant_scope({"actor_id": "actor-alpha"}, binding=binding())

    def test_human_scope_uses_fresh_existing_manager_authority(self):
        scope = library.human_scope(session(), binding=binding(), kind="drain")
        self.assertEqual(("human", "library-drain"), (scope.subject, scope.capabilities[0]))
        self.assertEqual("manager", scope.human_id)
        for kwargs in ({"allowed": ("library-inspect",)}, {"connected": False}):
            with self.subTest(kwargs=kwargs), self.assertRaises(library.LibraryError) as raised:
                library.human_scope(session(**kwargs), binding=binding(), kind="drain")
            self.assertEqual("FORBIDDEN", raised.exception.code)
        with self.assertRaises(library.LibraryError) as raised:
            library.human_scope(session(), binding=binding(), kind="settings-update")
        self.assertEqual("UNKNOWN_OPERATION", raised.exception.code)

    def test_scope_cannot_be_built_or_replaced_outside_the_trusted_constructors(self):
        forged = dict(subject="human", actor_id="actor-alpha", authority_version="epoch-1",
                      capabilities=("library-drain",), project_id="alpha",
                      project_identity="github.com/acme/alpha",
                      reference_root="/srv/alpha/reference/library", human_id="manager")
        with self.assertRaises(TypeError):
            library.LibraryScope(**forged)
        scope = library.participant_scope(ORIGIN, binding=binding())
        with self.assertRaises(AttributeError):
            scope.subject = "human"
        with self.assertRaises(TypeError):
            replace(scope, subject="human", capabilities=("library-drain",),
                    human_id="manager")

    def test_installation_scope_holds_no_project_content_authority(self):
        operator = Origin("operator", "operator-seat", "inc-op", "epoch-op", ("library-settings",))
        scope = library.installation_scope(operator)
        self.assertEqual(("operator", None, None),
                         (scope.subject, scope.project_id, scope.project_identity))
        with self.assertRaises(library.LibraryError):
            library.installation_scope(ORIGIN)


class CaptureOperationTests(unittest.TestCase):
    def test_capture_derives_queue_identity_and_redacts_transient_content(self):
        settings = admit()
        operation = capture(settings)
        self.assertEqual("enqueue", operation.kind)
        self.assertRegex(operation.queue_id, r"^[0-9a-f]{64}$")
        path = library.queue_path(operation.scope.project_path, operation.queue_id)
        self.assertEqual("projects/github.com/acme/alpha/pending/"
                         + operation.queue_id + ".md", path)
        metadata = operation.audit_metadata()
        self.assertNotIn("Pick SQLite", json.dumps(metadata))
        self.assertNotIn("body", metadata)
        self.assertEqual(operation.digest(), metadata["payload_sha256"])
        self.assertEqual(settings["settings_id"], operation.settings_id)

    def test_capture_rejects_caller_owned_authority_and_unknown_fields(self):
        settings = admit()
        for value, code in (
                ({"type": "decision", "title": "t", "body": "b", "project_id": "beta"},
                 "CALLER_AUTHORITY"),
                ({"type": "decision", "title": "t", "body": "b",
                  "sources": [{"resource": "a.md", "actor_id": "actor-beta"}]},
                 "CALLER_AUTHORITY"),
                ({"type": "decision", "title": "t", "body": "b", "queue_id": "mine"},
                 "CALLER_AUTHORITY"),
                ({"type": "decision", "title": "t", "body": "b", "verified": True},
                 "CALLER_AUTHORITY"),
                ({"type": "decision", "title": "t", "body": "b", "frontmatter": {}},
                 "UNKNOWN_FIELD")):
            with self.subTest(code=code), self.assertRaises(library.LibraryError) as raised:
                capture(settings, value=value)
            self.assertEqual(code, raised.exception.code)

    def test_capture_bounds_and_type_rules(self):
        settings = admit()
        cases = [(dict(type="research", title="t", body="b"), "SOURCE_REQUIRED"),
                 (dict(type="note", title="t", body="b"), "UNSAFE_CAPTURE_TYPE"),
                 (dict(type="decision", title="x" * 201, body="b"), "INVALID_TEXT"),
                 (dict(type="decision", title="t", body="x" * 16385), "CAPTURE_TOO_LARGE"),
                 (dict(type="decision", title="t", body="b",
                       sources=[{"resource": "r.md"}] * 17), "INVALID_CONTRACT")]
        for value, code in cases:
            with self.subTest(code=code), self.assertRaises(library.LibraryError) as raised:
                capture(settings, value=value)
            self.assertEqual(code, raised.exception.code)

    def test_retry_keeps_request_identity_and_rechecks_current_authority(self):
        settings = admit()
        first = capture(settings)
        retried = library.retry(library.participant_scope(OTHER, binding=binding()), settings,
                                first, operation_id="op-2", at=AT)
        self.assertEqual(first.queue_id, retried.queue_id)
        self.assertEqual(first.provenance, retried.provenance)
        self.assertEqual("actor-beta", retried.scope.actor_id)
        self.assertEqual(settings["settings_id"], retried.settings_id)
        with self.assertRaises(library.LibraryError) as raised:
            library.retry(library.participant_scope(REVOKED, binding=binding()), settings,
                          first, operation_id="op-3", at=AT)
        self.assertEqual("FORBIDDEN", raised.exception.code)
        with self.assertRaises(library.LibraryError) as raised:
            library.retry(library.participant_scope(ORIGIN, binding=binding()), settings,
                          first, operation_id="op-1", at=AT)
        self.assertEqual("ID_CONFLICT", raised.exception.code)

    def test_queue_identity_is_immutable_while_bundle_coordinates_can_move(self):
        settings = admit()
        before = library.participant_scope(ORIGIN, binding=binding())
        after = library.participant_scope(ORIGIN, binding=binding(repository="acme/renamed-alpha"))
        first = capture(settings, scope=before)
        renamed = capture(settings, scope=after, operation_id="op-2")
        self.assertEqual(first.queue_id, renamed.queue_id)
        self.assertNotEqual(library.queue_path(first.scope.project_path, first.queue_id),
                            library.queue_path(renamed.scope.project_path, renamed.queue_id))
        self.assertEqual("RETRY", library.identity(first, renamed))
        retried = library.retry(after, settings, first, operation_id="op-2", at=AT)
        self.assertEqual(first.queue_id, retried.queue_id)

    def test_queue_and_retry_identity_stay_inside_one_project(self):
        settings = admit()
        alpha = capture(settings)
        beta = capture(settings, scope=library.participant_scope(ORIGIN, binding=binding("beta",
                                                                                        "acme/beta",
                                                                                        "2002")))
        self.assertNotEqual(alpha.queue_id, beta.queue_id)
        with self.assertRaises(library.LibraryError) as raised:
            library.identity(alpha, beta)
        self.assertEqual("INVALID_OPERATION", raised.exception.code)
        with self.assertRaises(library.LibraryError) as raised:
            library.retry(library.participant_scope(ORIGIN, binding=binding("beta", "acme/beta",
                                                                            "2002")),
                          settings, alpha, operation_id="op-2", at=AT)
        self.assertEqual("FORBIDDEN", raised.exception.code)

    def test_identity_separates_duplicate_retry_and_conflict(self):
        settings = admit()
        first = capture(settings)
        self.assertEqual("DUPLICATE", library.identity(first, capture(settings)))
        self.assertEqual("RETRY", library.identity(first, library.retry(
            library.participant_scope(ORIGIN, binding=binding()), settings, first,
            operation_id="op-2", at=AT)))
        same_operation_id = capture(
            settings, operation_id="op-1", request_id="request-1",
            value={"type": "decision", "title": "Other", "body": "Different\n"})
        with self.assertRaises(library.LibraryError) as raised:
            library.identity(first, same_operation_id)
        self.assertEqual("ID_CONFLICT", raised.exception.code)
        same_request = capture(
            settings, operation_id="op-2", request_id="request-1",
            value={"type": "decision", "title": "Other", "body": "Different\n"})
        with self.assertRaises(library.LibraryError) as raised:
            library.identity(first, same_request)
        self.assertEqual("ID_CONFLICT", raised.exception.code)


class HumanActionTests(unittest.TestCase):
    def test_human_action_requires_exact_kind_fence_and_identity(self):
        settings = admit()
        scope = library.human_scope(session(), binding=binding(), kind="drain")
        operation = library.action(scope, settings, kind="drain", operation_id="op-drain",
                                   request_id="request-drain", at=AT,
                                   payload={"observed_version": "a" * 64})
        self.assertEqual("drain", operation.kind)
        with self.assertRaises(library.LibraryError) as raised:
            library.action(scope, settings, kind="drain", operation_id="op-drain-2",
                           request_id="request-drain", at=AT, payload={})
        self.assertEqual("MISSING_FIELD", raised.exception.code)
        with self.assertRaises(library.LibraryError) as raised:
            library.action(scope, settings, kind="drain", operation_id="op-drain-2",
                           request_id="request-drain", at=AT,
                           payload={"observed_version": "not-a-digest"})
        self.assertEqual("INVALID_DIGEST", raised.exception.code)
        reject_scope = library.human_scope(session(("library-reject",)),
                                           binding=binding(), kind="reject")
        payload = {"observed_version": "b" * 64, "drain_id": "drain-1"}
        with self.assertRaises(library.LibraryError) as raised:
            library.action(reject_scope, settings, kind="reject", operation_id="op-reject",
                           request_id="request-reject", at=AT, payload=payload)
        self.assertEqual("MISSING_FIELD", raised.exception.code)
        with self.assertRaises(library.LibraryError) as raised:
            library.action(reject_scope, settings, kind="reject", operation_id="op-reject",
                           request_id="request-reject", at=AT,
                           payload=dict(payload, queue_id="a" * 64, reason="DUPLICATE",
                                        commit_sha="c" * 40))
        self.assertEqual("UNKNOWN_FIELD", raised.exception.code)
        rejection = library.action(
            reject_scope, settings, kind="reject", operation_id="op-reject",
            request_id="request-reject", at=AT,
            payload={"observed_version": "b" * 64, "drain_id": "drain-1",
                     "queue_id": "a" * 64, "reason": "DUPLICATE"})
        self.assertEqual("drain-1", rejection.drain_id)
        self.assertEqual("drain-1", library.receipt(
            rejection, "COMMITTED", at=AT,
            publication={"commit_sha": "c" * 40,
                         "path": "projects/github.com/acme/alpha/pending/x.md"},
            reason="OPERATOR_DISPOSED")["drain_id"])
        with self.assertRaises(library.LibraryError) as raised:
            library.action(library.participant_scope(ORIGIN, binding=binding()), settings,
                           kind="drain", operation_id="op-drain-3",
                           request_id="request-drain", at=AT,
                           payload={"observed_version": "a" * 64})
        self.assertEqual("FORBIDDEN", raised.exception.code)

    def test_hosted_model_operation_needs_project_egress_but_git_capture_does_not(self):
        hosted_settings = hosted()
        scope = library.human_scope(session(), binding=binding(), kind="drain")
        with self.assertRaises(library.LibraryError) as raised:
            library.action(scope, hosted_settings, kind="drain", operation_id="op-drain",
                           request_id="request-drain", at=AT,
                           payload={"observed_version": "a" * 64})
        self.assertEqual("EGRESS_NOT_AUTHORIZED", raised.exception.code)
        capture(hosted_settings)
        approved = hosted(egress=[EGRESS])
        self.assertEqual("drain", library.action(scope, approved, kind="drain",
                                                operation_id="op-drain",
                                                request_id="request-drain", at=AT,
                                                payload={"observed_version": "a" * 64}).kind)
        local = admit()
        self.assertEqual("drain", library.action(scope, local, kind="drain",
                                                 operation_id="op-drain-local",
                                                 request_id="request-drain", at=AT,
                                                 payload={"observed_version": "a" * 64}).kind)


class TypedHumanPayloadTests(unittest.TestCase):
    def test_adjudication_and_import_accept_only_their_typed_fields(self):
        settings = admit()
        scope = library.human_scope(session(("library-adjudicate",)), binding=binding(),
                                    kind="adjudicate")
        payload = {"drain_id": "drain-1", "queue_id": "a" * 64,
                   "conclusion": "Use SQLite.\n", "rationale": "Fixed prior art.\n",
                   "observed_version": "b" * 64}
        self.assertEqual("adjudicate", library.action(
            scope, settings, kind="adjudicate", operation_id="op-adjudicate",
            request_id="request-adjudicate", at=AT, payload=payload).kind)
        with self.assertRaises(library.LibraryError) as raised:
            library.action(scope, settings, kind="adjudicate", operation_id="op-adjudicate-2",
                           request_id="request-adjudicate", at=AT,
                           payload=dict(payload, commit_sha="c" * 40))
        self.assertEqual("UNKNOWN_FIELD", raised.exception.code)
        import_scope = library.human_scope(session(("library-import-confirm",)),
                                           binding=binding(), kind="import-confirm")
        manifest = {"preview_id": "preview-1", "source_commit": "d" * 40,
                    "paths": ["docs/a.md"], "observed_version": "b" * 64}
        self.assertEqual("import-confirm", library.action(
            import_scope, settings, kind="import-confirm", operation_id="op-import",
            request_id="request-import", at=AT, payload=manifest).kind)
        for change, code in ((dict(manifest, paths=["../escape.md"]), "UNSAFE_PATH"),
                             (dict(manifest, paths=["/etc/passwd"]), "UNSAFE_PATH"),
                             (dict(manifest, paths=["a\nb.md"]), "UNSAFE_PATH"),
                             (dict(manifest, paths=["a\x00b.md"]), "UNSAFE_PATH"),
                             (dict(manifest, source_commit="main"), "INVALID_COMMIT")):
            with self.subTest(code=code), self.assertRaises(library.LibraryError) as raised:
                library.action(import_scope, settings, kind="import-confirm",
                               operation_id="op-import", request_id="request-import",
                               at=AT, payload=change)
            self.assertEqual(code, raised.exception.code)

    def test_hosted_retry_needs_project_egress(self):
        hosted_settings = hosted()
        first = capture(hosted_settings)
        retry_scope = library.human_scope(session(("library-retry",)), binding=binding(),
                                          kind="retry")
        payload = {"drain_id": "drain-1", "observed_version": "b" * 64}
        with self.assertRaises(library.LibraryError) as raised:
            library.action(retry_scope, hosted_settings, kind="retry",
                           operation_id="op-retry", request_id="request-retry", at=AT,
                           payload=payload)
        self.assertEqual("EGRESS_NOT_AUTHORIZED", raised.exception.code)
        self.assertEqual("retry", library.action(
            retry_scope, hosted(egress=[EGRESS]), kind="retry", operation_id="op-retry",
            request_id="request-retry", at=AT, payload=payload).kind)
        self.assertEqual(first.kind, "enqueue")


class SettingsChangeTests(unittest.TestCase):
    def test_shared_settings_authority_is_not_project_content_authority(self):
        settings = admit()
        operator = library.installation_scope(
            Origin("operator", "operator-seat", "inc-op", "epoch-op", ("library-settings",)))
        changed = document()
        changed["limits"]["title_chars"] = 120
        operation = library.settings_change(
            operator, settings, operation_id="op-settings", request_id="request-settings",
            document=io.StringIO(json.dumps(changed)), at=AT)
        self.assertEqual("settings-update", operation.kind)
        self.assertEqual(settings["settings_id"], operation.settings_id)
        self.assertNotEqual(settings["settings_id"], operation.payload["next_settings_id"])
        human = library.human_scope(session(("library-drain",)), binding=binding(), kind="drain")
        with self.assertRaises(library.LibraryError):
            library.settings_change(human, settings, operation_id="op-settings-2",
                                    request_id="request-settings-2",
                                    document=io.StringIO(json.dumps(changed)), at=AT)
        with self.assertRaises(library.LibraryError) as raised:
            library.settings_change(operator, settings, operation_id="op-settings-3",
                                    request_id="request-settings-3",
                                    document=io.StringIO(json.dumps(document())), at=AT)
        self.assertEqual("UNCHANGED_SETTINGS", raised.exception.code)
        with_egress = document()
        with_egress["egress"] = [EGRESS]
        with self.assertRaises(library.LibraryError) as raised:
            library.settings_change(operator, settings, operation_id="op-settings-4",
                                    request_id="request-settings-4",
                                    document=io.StringIO(json.dumps(with_egress)), at=AT)
        self.assertEqual("UNKNOWN_FIELD", raised.exception.code)


class NonContentSuccessTests(unittest.TestCase):
    def test_configuration_and_acknowledgement_success_carry_no_git_commit(self):
        settings = admit()
        operator = library.installation_scope(
            Origin("operator", "operator-seat", "inc-op", "epoch-op", ("library-settings",)))
        changed = document()
        changed["limits"]["title_chars"] = 120
        operation = library.settings_change(
            operator, settings, operation_id="op-settings", request_id="request-settings",
            document=io.StringIO(json.dumps(changed)), at=AT)
        configured = library.receipt(
            operation, "CONFIGURED", at=AT,
            configuration={"settings_id": operation.payload["next_settings_id"],
                           "version": 2})
        self.assertIsNone(configured["publication"])
        self.assertEqual(2, configured["configuration"]["version"])
        drain = library.action(library.human_scope(session(), binding=binding(), kind="drain"),
                              settings, kind="drain", operation_id="op-drain",
                              request_id="request-drain", at=AT,
                              payload={"observed_version": "a" * 64})
        acknowledged = library.receipt(drain, "ACKNOWLEDGED", at=AT,
                                       acknowledgement="OPERATIONAL_ACCEPTED")
        self.assertIsNone(acknowledged["publication"])
        with self.assertRaises(library.LibraryError) as raised:
            library.receipt(drain, "ACKNOWLEDGED", at=AT)
        self.assertEqual("INVALID_IDENTIFIER", raised.exception.code)
        with self.assertRaises(library.LibraryError) as raised:
            library.receipt(operation, "CONFIGURED", at=AT)
        self.assertEqual("CONFIGURATION_REQUIRED", raised.exception.code)
        with self.assertRaises(library.LibraryError) as raised:
            library.receipt(operation, "CONFIGURED", at=AT,
                            configuration={"settings_id": "a" * 64, "version": 2},
                            publication={"commit_sha": "c" * 40, "path": "projects/x"})
        self.assertEqual("INVALID_OUTCOME", raised.exception.code)


class OutcomeTests(unittest.TestCase):
    def test_receipt_distinguishes_durable_visible_refused_and_uncertain(self):
        settings = admit()
        operation = capture(settings)
        sha = "c" * 40
        durable = library.receipt(
            operation, "DURABLY_QUEUED", at=AT,
            publication={"commit_sha": sha,
                         "path": library.queue_path("github.com/acme/alpha", operation.queue_id)},
            projection={"commit_sha": sha, "visible": True})
        self.assertEqual(("DURABLY_QUEUED", False), (durable["outcome"], durable["retryable"]))
        self.assertTrue(durable["projection"]["visible"])
        pending = library.receipt(operation, "DURABLY_QUEUED", at=AT,
                                  publication=durable["publication"],
                                  projection={"commit_sha": None, "visible": False})
        self.assertFalse(pending["projection"]["visible"])
        advanced = library.receipt(operation, "DURABLY_QUEUED", at=AT,
                                   publication=durable["publication"],
                                   projection={"commit_sha": "b" * 40, "visible": True})
        self.assertEqual("b" * 40, advanced["projection"]["commit_sha"])
        with self.assertRaises(library.LibraryError) as raised:
            library.receipt(operation, "DURABLY_QUEUED", at=AT,
                            publication=durable["publication"],
                            projection={"commit_sha": None, "visible": True})
        self.assertEqual("INVALID_PROJECTION", raised.exception.code)
        uncertain = library.receipt(operation, "NOT_DURABLE", at=AT, reason="TRANSPORT_UNKNOWN")
        self.assertTrue(uncertain["retryable"])
        self.assertIsNone(uncertain["publication"])
        refused = library.receipt(operation, "REJECTED", at=AT, reason="INVALID_TEXT")
        self.assertFalse(refused["retryable"])
        with self.assertRaises(library.LibraryError) as raised:
            library.receipt(operation, "DURABLY_QUEUED", at=AT,
                            publication=durable["publication"])
        self.assertEqual("PROJECTION_REQUIRED", raised.exception.code)
        for outcome, kwargs in (("DURABLY_QUEUED", {}),
                                ("REJECTED", {"reason": "X", "publication": durable["publication"]}),
                                ("REJECTED", {"reason": "X", "retryable": True})):
            with self.subTest(outcome=outcome), self.assertRaises(library.LibraryError):
                library.receipt(operation, outcome, at=AT, **kwargs)
        with self.assertRaises(library.LibraryError) as raised:
            library.receipt(operation, "DURABLY_QUEUED", at=AT,
                            publication={"commit_sha": sha, "path":
                                         "projects/github.com/acme/alpha/pending/other.md"},
                            projection={"commit_sha": sha, "visible": True})
        self.assertEqual("INVALID_PUBLICATION", raised.exception.code)

    def test_received_receipt_rejects_content_and_unknown_fields(self):
        operation = capture(admit())
        value = library.receipt(operation, "REFUSED", at=AT, reason="BUSY")
        self.assertEqual(value, library.admit_receipt(deepcopy(value)))
        for change, code in ((dict(value, body="secret"), "UNKNOWN_FIELD"),
                             (dict(value, outcome="SUCCESS"), "UNKNOWN_OUTCOME"),
                             (dict(value, retryable=True), "INVALID_OUTCOME"),
                             (dict(value, version=2), "UNSUPPORTED_CONTRACT_VERSION")):
            with self.subTest(code=code), self.assertRaises(library.LibraryError) as raised:
                library.admit_receipt(change)
            self.assertEqual(code, raised.exception.code)

    def test_snapshot_and_projection_coherence(self):
        empty = {"version": 1, "project_id": "alpha",
                 "project_identity": "github.com/acme/alpha",
                 "commit_sha": None, "published_at": None}
        self.assertFalse(library.projection(empty, bundle_present=False)["visible"])
        with self.assertRaises(library.LibraryError):
            library.projection(empty, bundle_present=True)
        sha = "e" * 40
        published = dict(empty, commit_sha=sha, published_at=AT)
        self.assertTrue(library.projection(published, bundle_present=True,
                                           bundle_commit_sha=sha)["visible"])
        with self.assertRaises(library.LibraryError):
            library.projection(published, bundle_present=False)
        with self.assertRaises(library.LibraryError):
            library.projection(published, bundle_present=True, bundle_commit_sha="f" * 40)
        with self.assertRaises(library.LibraryError):
            library.snapshot(dict(published, published_at=None))


class ProposalTests(unittest.TestCase):
    def batch(self):
        settings = admit()
        first = capture(settings, operation_id="op-1", request_id="request-1")
        second = capture(settings, operation_id="op-2", request_id="request-2",
                         value={"type": "context", "title": "Stack", "body": "SQLite.\n"})
        return settings, [first.queue_id, second.queue_id]

    def proposal(self, queue_ids, operations=None):
        return {"version": 1, "drain_id": "drain-1", "attempt": 1,
                "operations": operations if operations is not None else [
                    {"op": "create", "path": "decisions/use-sqlite.md", "type": "decision",
                     "title": "Use SQLite", "body": "SQLite.\n"},
                    {"op": "park", "queue_id": queue_ids[-1], "reason": "CONTRADICTION"}]}

    def test_typed_proposal_keeps_content_and_identity_bounded(self):
        settings, queue_ids = self.batch()
        admitted = library.admit_proposal(self.proposal(queue_ids), drain_id="drain-1",
                                          queue_ids=queue_ids, limits=settings["limits"])
        self.assertEqual(["create", "park"],
                         [item["op"] for item in admitted["operations"]])
        with self.assertRaises(library.LibraryError) as raised:
            library.admit_proposal(self.proposal(queue_ids, [
                {"op": "delete", "path": "decisions/use-sqlite.md"}]),
                drain_id="drain-1", queue_ids=queue_ids, limits=settings["limits"])
        self.assertEqual("UNSAFE_PROPOSAL_OPERATION", raised.exception.code)
        for path in ("decisions/../escape.md", "/decisions/use-sqlite.md",
                     "decisions/index.md", "other/use-sqlite.md", "decisions/Use SQLite.md"):
            with self.subTest(path=path), self.assertRaises(library.LibraryError):
                library.admit_proposal(self.proposal(queue_ids, [
                    {"op": "create", "path": path, "type": "decision",
                     "title": "t", "body": "b\n"}]), drain_id="drain-1",
                    queue_ids=queue_ids, limits=settings["limits"])
        for change, code in (
                ({"op": "create", "path": "decisions/x.md", "type": "decision",
                  "title": "t", "body": "b\n", "verified": True}, "UNKNOWN_FIELD"),
                ({"op": "park", "queue_id": "a" * 64, "reason": "X"},
                 "PROPOSAL_BATCH_MISMATCH"),
                ({"op": "park", "queue_id": queue_ids[0], "reason": "X"}, None)):
            with self.subTest(code=code):
                if code is None:
                    library.admit_proposal(self.proposal(queue_ids, [change]),
                                           drain_id="drain-1", queue_ids=queue_ids,
                                           limits=settings["limits"])
                    continue
                with self.assertRaises(library.LibraryError) as raised:
                    library.admit_proposal(self.proposal(queue_ids, [change]),
                                           drain_id="drain-1", queue_ids=queue_ids,
                                           limits=settings["limits"])
                self.assertEqual(code, raised.exception.code)
        operations = [{"op": "park", "queue_id": queue_ids[0], "reason": "X"}] * 2
        with self.assertRaises(library.LibraryError):
            library.admit_proposal(self.proposal(queue_ids, operations), drain_id="drain-1",
                                   queue_ids=queue_ids, limits=settings["limits"])
        with self.assertRaises(library.LibraryError):
            library.admit_proposal(self.proposal(queue_ids), drain_id="drain-2",
                                   queue_ids=queue_ids, limits=settings["limits"])
        deprecated = library.admit_proposal(self.proposal(queue_ids, [
            {"op": "deprecate", "path": "decisions/use-sqlite.md", "reason": "SUPERSEDED"}]),
            drain_id="drain-1", queue_ids=queue_ids, limits=settings["limits"])
        self.assertEqual("deprecate", deprecated["operations"][0]["op"])
        with self.assertRaises(library.LibraryError) as raised:
            library.admit_proposal(self.proposal(queue_ids, [
                {"op": "deprecate", "path": "decisions/use-sqlite.md",
                 "reason": "SUPERSEDED", "body": "gone"}]), drain_id="drain-1",
                queue_ids=queue_ids, limits=settings["limits"])
        self.assertEqual("UNKNOWN_FIELD", raised.exception.code)


class ObservationAndMetadataTests(unittest.TestCase):
    def test_literal_observations_and_metadata_only_audit(self):
        for state in library.OBSERVATION_STATES:
            admitted = library.observation({"version": 1, "owner": "library-service",
                                            "subject": "alpha", "state": state,
                                            "observed_at": AT, "reason": "TRANSPORT"})
            self.assertEqual(state, admitted["state"])
        with self.assertRaises(library.LibraryError):
            library.observation({"version": 1, "owner": "library-service", "subject": "alpha",
                                 "state": "clean", "observed_at": AT})
        self.assertEqual({"project_id": "alpha", "commit_sha": None},
                         library.audit_metadata({"project_id": "alpha", "commit_sha": None}))
        for value, code in (({"body": "text"}, "CONTENT_NOT_ALLOWED"),
                            ({"nested": {"title": "t"}}, "CONTENT_NOT_ALLOWED"),
                            ({"padding": "x" * library.MAX_AUDIT_BYTES}, "AUDIT_TOO_LARGE")):
            with self.subTest(code=code), self.assertRaises(library.LibraryError) as raised:
                library.audit_metadata(value)
            self.assertEqual(code, raised.exception.code)


class NoEffectsTests(unittest.TestCase):
    def test_admission_and_contracts_touch_no_file_network_or_process(self):
        with patch("builtins.open", side_effect=AssertionError("file access")), \
                patch.object(socket, "socket", side_effect=AssertionError("socket")), \
                patch.object(socket, "create_connection", side_effect=AssertionError("network")), \
                patch.object(subprocess, "run", side_effect=AssertionError("process")):
            settings = admit(egress=[EGRESS])
            operation = capture(settings)
            library.retry(library.participant_scope(OTHER, binding=binding()), settings,
                          operation, operation_id="op-2", at=AT)
            scope = library.human_scope(session(("library-reject",)),
                                        binding=binding(), kind="reject")
            library.action(scope, settings, kind="reject", operation_id="op-reject",
                           request_id="request-reject", at=AT,
                           payload={"observed_version": "b" * 64, "drain_id": "drain-1",
                                    "queue_id": operation.queue_id, "reason": "DUPLICATE"})
            library.receipt(operation, "NOT_DURABLE", at=AT, reason="TRANSPORT_UNKNOWN")
            library.admit_proposal(ProposalTests().proposal([operation.queue_id]),
                                   drain_id="drain-1", queue_ids=[operation.queue_id],
                                   limits=settings["limits"])


OKF_AT = "2026-10-29T12:00:00+00:00"
NEW_LOG = ("# Update log\n\n## 2026-10-20\n"
           "* **Creation**: Added [Pick SQLite](context/pick-sqlite.md).\n\n"
           "## 2026-10-01\n* **Initialization**: Created the Project bundle.\n")


def root_index(path, identity):
    return ("---\nokf_version: \"0.2\"\n---\n\n# Project Library\n\n"
            "Source coordinates: %s\nSource identity: %s\n\n"
            "* [Context](context/index.md)\n* [Decisions](decisions/index.md)\n"
            "* [Research](research/index.md)\n* [Pending](pending/index.md)\n"
            % (path, identity))


def concept(type_, title, status=None, body="# Body\n\nText.\n", fields=()):
    lines = ["---", "type: " + type_, 'title: "%s"' % title]
    if status is not None:
        lines.append("status: " + status)
    lines.extend(fields)
    return "\n".join(lines + ["---", "", body])


class BundleValidationTests(unittest.TestCase):
    def settings(self, **limits):
        value = document()
        value["limits"].update(limits)
        return admit(value)

    def scope(self, project_id="alpha", repository="acme/alpha", source="1001"):
        return library.participant_scope(ORIGIN, binding=binding(project_id, repository, source))

    def initial(self, scope):
        prefix = "projects/" + scope.project_path
        files = {
            "index.md": root_index(scope.project_path, scope.project_identity),
            "log.md": ("# Update log\n\n## 2026-10-01\n"
                       "* **Initialization**: Created the Project bundle.\n"),
            "context/index.md": "# Context\n",
            "decisions/index.md": "# Decisions\n",
            "research/index.md": "# Research\n",
            "pending/index.md": "# Pending\n",
        }
        return prefix, {prefix + "/" + name: value.encode("utf-8")
                        for name, value in files.items()}

    def update(self, scope, *, document_text=None,
               index_text="# Context\n\n* [Pick SQLite](/context/pick-sqlite.md) - short.\n",
               log=None, extra=(), remove=()):
        prefix, files = self.initial(scope)
        default = concept("context", "Pick SQLite", "stable")
        chosen = default if document_text is None else document_text
        files[prefix + "/context/pick-sqlite.md"] = (
            chosen if isinstance(chosen, bytes) else chosen.encode("utf-8"))
        files[prefix + "/context/index.md"] = index_text.encode("utf-8")
        files[prefix + "/log.md"] = (log or NEW_LOG).encode("utf-8")
        for name, data in extra:
            files[prefix + "/" + name] = data if isinstance(data, bytes) else data.encode("utf-8")
        for name in remove:
            del files[prefix + "/" + name]
        return prefix, files

    def validate(self, scope, settings, proposed, current=None, selected=()):
        return library_bundle.validate(
            scope, settings,
            current=None if current is None else library_bundle.Tree(files=current),
            proposed=library_bundle.Tree(files=proposed), selected=selected)

    def refused(self, scope, settings, proposed, current=None, selected=(), code=None):
        with self.assertRaises(library.LibraryError) as raised:
            self.validate(scope, settings, proposed, current=current, selected=selected)
        if code is not None:
            self.assertEqual(code, raised.exception.code, raised.exception.field)
        return raised.exception

    def test_initialization_accepts_exactly_the_six_file_skeleton(self):
        scope = self.scope()
        prefix, files = self.initial(scope)
        settings = self.settings()
        result = self.validate(scope, settings, files)
        self.assertEqual(prefix, result.prefix)
        self.assertEqual(files, result.files)
        self.assertEqual(tuple(sorted(library_bundle.REQUIRED)), result.added)
        self.assertEqual((), result.updated)
        self.assertEqual((), result.removed)
        with self.assertRaises(TypeError):
            library_bundle.validate(scope, settings, proposed=library_bundle.Tree(files=files),
                                    prefix="projects/github.com/acme/sibling")

    def test_initialization_refuses_partial_extra_and_incoherent_skeletons(self):
        scope, settings = self.scope(), self.settings()
        prefix, files = self.initial(scope)
        cases = []
        cases.append((dict(files, **{}), None, None))
        without_log = dict(files)
        del without_log[prefix + "/log.md"]
        cases = [(without_log, None, "MISSING_REQUIRED_FILE")]
        extra = dict(files)
        extra[prefix + "/context/early.md"] = concept("context", "Early").encode("utf-8")
        cases.append((extra, None, "INITIALIZATION_NOT_EMPTY"))
        linked = dict(files)
        linked[prefix + "/context/index.md"] = b"# Context\n\n* [x](context/x.md)\n"
        cases.append((linked, None, "INITIALIZATION_NOT_EMPTY"))
        wrong_version = dict(files)
        wrong_version[prefix + "/index.md"] = root_index(
            scope.project_path, scope.project_identity).replace('"0.2"', '"0.1"').encode("utf-8")
        cases.append((wrong_version, None, "INVALID_OKF_VERSION"))
        root_with_extra = dict(files)
        root_with_extra[prefix + "/index.md"] = b"---\nokf_version: \"0.2\"\ntitle: x\n---\n\n# x\n"
        cases.append((root_with_extra, None, "INVALID_OKF_VERSION"))
        no_identity = dict(files)
        no_identity[prefix + "/index.md"] = (
            b"---\nokf_version: \"0.2\"\n---\n\n# x\n\n"
            b"* [Context](context/index.md)\n* [Decisions](decisions/index.md)\n"
            b"* [Research](research/index.md)\n* [Pending](pending/index.md)\n")
        cases.append((no_identity, None, "MISSING_SOURCE_IDENTITY"))
        for proposed, current, code in cases:
            with self.subTest(code=code):
                self.refused(scope, settings, proposed, current=current, code=code)

    def test_authority_derives_the_only_bundle_prefix_and_refuses_siblings(self):
        settings = self.settings()
        alpha, beta = self.scope(), self.scope("beta", "acme/beta", "1002")
        _prefix, alpha_files = self.initial(alpha)
        _prefix, beta_files = self.initial(beta)
        self.validate(beta, settings, beta_files)
        self.refused(beta, settings, alpha_files, code="FOREIGN_PROJECT")
        mixed = dict(beta_files)
        mixed.update(alpha_files)
        self.refused(beta, settings, mixed, code="FOREIGN_PROJECT")
        operator = library.installation_scope(
            Origin("operator", "seat-o", "inc-o", "epoch-o", ("library-settings",)))
        self.refused(operator, settings, beta_files, code="FORBIDDEN")
        self.refused(None, settings, beta_files, code="LIBRARY_AUTHENTICATION_REQUIRED")

    def test_canonical_text_and_yaml_safety_reject_before_any_structure(self):
        scope, settings = self.scope(), self.settings()
        prefix, current = self.initial(scope)
        cases = {
            "MALFORMED_UTF8": b"---\ntype: context\ntitle: \xff\n---\n",
            "CR_LINE_ENDING": concept("context", "Pick SQLite").replace(
                "\n", "\r\n").encode("utf-8"),
            "DISALLOWED_CONTROL": concept("context", "Pick\x00 SQLite").encode("utf-8"),
            "NON_CANONICAL_TEXT": concept("context", "Cafe\u0301").encode("utf-8"),
            "DUPLICATE_YAML_KEY": b"---\ntype: context\ntitle: a\ntitle: b\n---\n\n# x\n",
            "UNSAFE_YAML": b"---\ntype: context\ntitle: !!str x\n---\n\n# x\n",
            "UNSAFE_SCALAR": b"---\ntype: context\ntitle: yes\n---\n\n# x\n",
            "MISSING_FRONTMATTER": b"# no frontmatter\n",
        }
        for code, value in cases.items():
            with self.subTest(code=code):
                _prefix, files = self.update(scope)
                files[prefix + "/context/pick-sqlite.md"] = value
                self.refused(scope, settings, files, current=current, code=code)

    def test_paths_symlinks_collisions_and_repository_metadata_are_refused(self):
        scope, settings = self.scope(), self.settings()
        prefix, files = self.initial(scope)
        variants = {
            "UNSAFE_PATH": prefix + "/context/bad\\name.md",
            "REPOSITORY_METADATA": prefix + "/.git/config",
            "FOREIGN_PROJECT": "projects/github.com/acme/sibling/index.md",
        }
        for code, path in variants.items():
            with self.subTest(code=code):
                self.refused(scope, settings, dict(files, **{path: b"x"}), code=code)
        traversal = dict(files)
        traversal[prefix + "/../escape.md"] = b"x"
        self.refused(scope, settings, traversal, code="UNSAFE_PATH")
        absolute = dict(files)
        absolute["/etc/passwd.md"] = b"x"
        self.refused(scope, settings, absolute, code="UNSAFE_PATH")
        collision = dict(files)
        collision[prefix + "/context/Pick.md"] = concept("context", "One").encode("utf-8")
        collision[prefix + "/context/pick.md"] = concept("context", "Two").encode("utf-8")
        self.refused(scope, settings, collision, code="PATH_COLLISION")
        with self.assertRaises(library.LibraryError) as raised:
            library_bundle.validate(scope, settings, proposed=library_bundle.Tree(
                files=files, symlinks=(prefix + "/context/pick.md",)))
        self.assertEqual("SYMLINK_NOT_ALLOWED", raised.exception.code)

    def test_update_preserves_unknown_existing_material_and_broken_targets(self):
        scope, settings = self.scope(), self.settings()
        prefix, files = self.initial(scope)
        legacy = ("---\ntype: BigQuery Table\ntitle: Legacy\nstatus: stable\n"
                  "usage_count: 5000\n---\n\n# Legacy\n\nAuthored material.\n")
        files[prefix + "/context/legacy.md"] = legacy.encode("utf-8")
        files[prefix + "/context/index.md"] = (
            "# Context\n\n* [Legacy](/context/legacy.md) - tolerated.\n").encode("utf-8")
        proposed = dict(files)
        proposed[prefix + "/context/pick-sqlite.md"] = concept(
            "context", "Pick SQLite", "stable",
            body="# Pick\n\nSee [missing](/context/missing.md).\n").encode("utf-8")
        proposed[prefix + "/context/index.md"] = (
            "# Context\n\n* [Legacy](/context/legacy.md) - tolerated.\n"
            "* [Pick SQLite](/context/pick-sqlite.md) - short.\n").encode("utf-8")
        proposed[prefix + "/log.md"] = NEW_LOG.encode("utf-8")
        result = self.validate(scope, settings, proposed, current=files)
        self.assertIn("context/pick-sqlite.md", result.added)
        self.assertIn("context/index.md", result.updated)
        self.assertEqual(legacy.encode("utf-8"), result.files[prefix + "/context/legacy.md"])

        preserved = dict(proposed)
        preserved[prefix + "/context/legacy.md"] = legacy.replace(
            "Authored material.", "Authored material, edited.").encode("utf-8")
        self.assertIn("context/legacy.md",
                      self.validate(scope, settings, preserved, current=files).updated)

        foreign_key = dict(proposed)
        foreign_key[prefix + "/context/legacy.md"] = legacy.replace(
            "status: stable", "status: stable\nauthor: someone").encode("utf-8")
        self.refused(scope, settings, foreign_key, current=files, code="UNSUPPORTED_FIELD")

        new_unknown = dict(proposed)
        new_unknown[prefix + "/context/fresh.md"] = concept(
            "context", "Fresh", "stable", fields=("author: someone",)).encode("utf-8")
        new_unknown[prefix + "/context/index.md"] = (
            "# Context\n\n* [Legacy](/context/legacy.md) - tolerated.\n"
            "* [Pick SQLite](/context/pick-sqlite.md) - short.\n"
            "* [Fresh](/context/fresh.md) - new.\n").encode("utf-8")
        self.refused(scope, settings, new_unknown, current=files, code="UNSUPPORTED_FIELD")

    def test_mutations_refuse_accepted_deletion_rename_and_unselected_pending(self):
        scope, settings = self.scope(), self.settings()
        operation = capture(settings)
        queue_id = operation.queue_id
        pending = "pending/" + queue_id + ".md"
        prefix, files = self.initial(scope)
        files[prefix + "/" + pending] = concept("decision", "Queued", "draft").encode("utf-8")
        files[prefix + "/pending/index.md"] = (
            "# Pending\n\n* [Queued](/%s) - DRAFT.\n" % pending).encode("utf-8")
        current = dict(files)
        _prefix, proposed = self.update(
            scope,
            index_text="# Context\n\n* [Pick SQLite](/context/pick-sqlite.md) - short.\n",
            log=NEW_LOG)
        proposed[prefix + "/" + pending] = files[prefix + "/" + pending]
        proposed[prefix + "/pending/index.md"] = files[prefix + "/pending/index.md"]

        integrated = dict(proposed)
        del integrated[prefix + "/" + pending]
        integrated[prefix + "/pending/index.md"] = b"# Pending\n"
        result = self.validate(scope, settings, integrated, current=current,
                              selected=(queue_id,))
        self.assertEqual((pending,), result.removed)

        unselected = dict(proposed)
        del unselected[prefix + "/" + pending]
        self.refused(scope, settings, unselected, current=current, selected=(),
                     code="UNSELECTED_PENDING_REMOVAL")
        _prefix, accepted_before = self.update(scope)
        deleted = dict(accepted_before)
        del deleted[prefix + "/context/pick-sqlite.md"]
        deleted[prefix + "/context/index.md"] = b"# Context\n"
        self.refused(scope, settings, deleted, current=accepted_before,
                     code="EXISTING_DATA_DELETION")
        renamed = dict(deleted)
        renamed[prefix + "/context/pick-sqlite-renamed.md"] = concept(
            "context", "Pick SQLite", "stable").encode("utf-8")
        self.refused(scope, settings, renamed, current=accepted_before,
                     code="EXISTING_DATA_DELETION")
        self.refused(scope, settings, proposed, current=current, selected=("short",),
                     code="INVALID_DIGEST")

    def test_index_log_and_required_relationships_stay_coherent(self):
        scope, settings = self.scope(), self.settings()
        prefix, current = self.initial(scope)
        _prefix, files = self.update(scope)
        cases = {
            "MISSING_INDEX_ENTRY": dict(files, **{prefix + "/context/index.md": b"# Context\n"}),
            "UNEXPECTED_FRONTMATTER": dict(
                files, **{prefix + "/context/index.md":
                          b"---\ntype: context\n---\n\n# Context\n",
                          }),
            "INVALID_INDEX": dict(files, **{prefix + "/context/index.md": b"plain text\n"}),
            "MISSING_LOG_ENTRY": dict(files, **{prefix + "/log.md": b"# Update log\n"}),
            "INVALID_LOG_DATE": dict(
                files, **{prefix + "/log.md": b"# Update log\n\n## 2026-02-30\n* entry\n"}),
            "LOG_HISTORY_REWRITTEN": dict(
                files, **{prefix + "/log.md":
                          b"# Update log\n\n## 2026-10-01\n* **Initialization**: edited.\n"}),
            "MISSING_INDEX_LINK": dict(
                files, **{prefix + "/index.md": root_index(
                    scope.project_path, scope.project_identity).replace(
                        "* [Pending](pending/index.md)\n", "").encode("utf-8")}),
        }
        for code, value in cases.items():
            with self.subTest(code=code):
                self.refused(scope, settings, value, current=current, code=code)
        malformed = dict(current)
        del malformed[prefix + "/research/index.md"]
        self.refused(scope, settings, files, current=malformed,
                     code="MALFORMED_EXISTING_BUNDLE")
        self.refused(scope, settings, dict(files, **{prefix + "/log.md": b"# Update log\n"}),
                     current=current, code="MISSING_LOG_ENTRY")

    def test_writer_output_stays_inside_supported_v1_types_and_fields(self):
        scope, settings = self.scope(), self.settings()
        prefix, current = self.initial(scope)
        variants = {
            "INCOHERENT_STATUS": (concept("context", "Pick", "draft"), "context/pick-sqlite.md"),
            "TYPE_MISMATCH": (concept("decision", "Pick", "stable"), "context/pick-sqlite.md"),
            "MISSING_TYPE": (b"---\ntitle: Pick\nstatus: stable\n---\n\n# Pick\n",
                             "context/pick-sqlite.md"),
            "MISSING_FIELD": (b"---\ntype: context\nstatus: stable\n---\n\n# Pick\n",
                              "context/pick-sqlite.md"),
            "INVALID_SOURCES": (concept("context", "Pick", "stable",
                                        fields=("sources:", "  - title: no resource")),
                                "context/pick-sqlite.md"),
            "PENDING_PATH_NOT_QUEUE_DERIVED": (concept("decision", "Queued", "draft"),
                                               "pending/not-a-queue-id.md"),
            "INCOHERENT_STATUS2": (concept("decision", "Queued", "stable"),
                                   "pending/" + "a" * 64 + ".md"),
        }
        for code, (text, name) in variants.items():
            with self.subTest(code=code):
                data = text if isinstance(text, bytes) else text.encode("utf-8")
                _prefix, files = self.update(scope, extra=((name, data),))
                expected = code.rstrip("2")
                self.refused(scope, settings, files, current=current, code=expected)

    def test_configured_bounds_bound_the_complete_result(self):
        scope = self.scope()
        prefix, files = self.initial(scope)
        default = self.settings()
        size = max(len(data) for data in files.values())
        per_document = self.settings(document_bytes=size)
        _prefix, files = self.update(
            scope, document_text=concept("context", "Pick SQLite", "stable",
                                          body="# Body\n\n" + "x" * (size * 2) + "\n"))
        self.refused(scope, per_document, files, current=self.initial(scope)[1],
                     code="DOCUMENT_TOO_LARGE")
        _prefix, files = self.initial(scope)
        limited = self.settings(scan_documents=6)
        _prefix, added = self.update(scope, extra=(("context/more.md",
                                                    concept("context", "More", "stable")),))
        self.refused(scope, limited, added, current=files, code="TOO_MANY_DOCUMENTS")
        _prefix, files = self.update(scope)
        budget = self.settings(projection_bytes=sum(len(data)
                                                    for data in self.initial(scope)[1].values()))
        self.refused(scope, budget, files, current=self.initial(scope)[1],
                     code="BUNDLE_TOO_LARGE")
        self.validate(scope, default, files, current=self.initial(scope)[1])

    def test_rejection_is_safe_evidence_and_mutates_nothing(self):
        scope, settings = self.scope(), self.settings()
        prefix, current = self.initial(scope)
        _prefix, files = self.update(
            scope, document_text=b"---\ntype: context\ntitle: a\ntitle: SECRET-MARKER\n---\n")
        proposed = {path: data for path, data in files.items()}
        snapshot = dict(proposed)
        current_snapshot = dict(current)
        with tempfile.TemporaryDirectory() as root:
            projection = Path(root) / "library.snapshot.json"
            projection.write_text('{"commit_sha": null}', encoding="utf-8")
            with patch("builtins.open", side_effect=AssertionError("file access")), \
                    patch.object(socket, "socket", side_effect=AssertionError("socket")), \
                    patch.object(subprocess, "run", side_effect=AssertionError("process")):
                error = self.refused(scope, settings, proposed, current=current,
                                     code="DUPLICATE_YAML_KEY")
            self.assertEqual('{"commit_sha": null}', projection.read_text(encoding="utf-8"))
        self.assertNotIn("SECRET-MARKER", str(error))
        self.assertNotIn("SECRET-MARKER", error.field)
        self.assertEqual("context/pick-sqlite.md.title", error.field)
        self.assertEqual(snapshot, proposed)
        self.assertEqual(current_snapshot, current)

    def test_integration_uses_the_capture_queue_identity_and_bundle_path_contract(self):
        scope, settings = self.scope(), self.settings()
        operation = capture(settings, scope)
        queue_id = operation.queue_id
        pending = library.queue_path(scope.project_path, queue_id)
        self.assertTrue(pending.startswith("projects/" + scope.project_path + "/pending/"))
        location = pending[len("projects/" + scope.project_path + "/"):]
        _prefix, current = self.initial(scope)
        current["projects/" + scope.project_path + "/" + location] = concept(
            "decision", "Pick SQLite", "draft").encode("utf-8")
        current["projects/" + scope.project_path + "/pending/index.md"] = (
            "# Pending\n\n* [Pick SQLite](/%s) - DRAFT.\n" % location).encode("utf-8")
        base = "projects/" + scope.project_path
        _prefix, proposed = self.initial(scope)
        proposed[base + "/decisions/pick-sqlite.md"] = concept(
            "decision", "Pick SQLite", "stable").encode("utf-8")
        proposed[base + "/decisions/index.md"] = (
            b"# Decisions\n\n* [Pick SQLite](/decisions/pick-sqlite.md) - short.\n")
        proposed[base + "/pending/index.md"] = b"# Pending\n"
        proposed[base + "/log.md"] = (
            "# Update log\n\n## 2026-10-20\n"
            "* **Creation**: Added [Pick SQLite](/decisions/pick-sqlite.md).\n\n"
            "## 2026-10-01\n* **Initialization**: Created the Project bundle.\n").encode("utf-8")
        result = self.validate(scope, settings, proposed, current=current,
                              selected=(queue_id,))
        self.assertEqual((location,), result.removed)
        self.assertEqual(operation.queue_id, queue_id)


    def test_tolerated_existing_documents_still_meet_coherence_rules(self):
        scope, settings = self.scope(), self.settings()
        prefix, files = self.initial(scope)

        def with_legacy(text, link="/context/legacy.md"):
            tree = dict(files)
            tree[prefix + "/context/legacy.md"] = text.encode("utf-8")
            tree[prefix + "/context/index.md"] = (
                "# Context\n\n* [Legacy](%s) - tolerated.\n" % link).encode("utf-8")
            return tree

        draft = with_legacy("---\ntype: context\ntitle: Legacy\nstatus: draft\n---\n\n# L\n")
        self.refused(scope, settings, draft, current=draft, code="INCOHERENT_STATUS")
        moved_type = with_legacy("---\ntype: decision\ntitle: Legacy\n---\n\n# L\n")
        self.refused(scope, settings, moved_type, current=moved_type, code="TYPE_MISMATCH")
        unknown = with_legacy("---\ntype: BigQuery Table\ntitle: Legacy\n---\n\n# L\n")
        self.validate(scope, settings, unknown, current=unknown)
        no_title = with_legacy("---\ntype: BigQuery Table\n---\n\n# L\n")
        self.validate(scope, settings, no_title, current=no_title)
        bad_sources = with_legacy("---\ntype: context\ntitle: Legacy\nsources: nope\n---\n\n# L\n")
        self.refused(scope, settings, bad_sources, current=bad_sources,
                     code="INVALID_SOURCES")

    def test_tolerated_existing_reader_data_cannot_be_rewritten(self):
        scope, settings = self.scope(), self.settings()
        prefix, files = self.initial(scope)
        legacy = ("---\ntype: BigQuery Table\ntitle: Legacy\nstatus: stable\n"
                  "usage_count: 5000\n---\n\n# Legacy\n\nAuthored material.\n")
        files[prefix + "/context/legacy.md"] = legacy.encode("utf-8")
        files[prefix + "/context/index.md"] = (
            "# Context\n\n* [Legacy](/context/legacy.md) - tolerated.\n").encode("utf-8")
        changed = dict(files)
        changed[prefix + "/context/legacy.md"] = legacy.replace(
            "usage_count: 5000", "usage_count: 1").encode("utf-8")
        self.refused(scope, settings, changed, current=files,
                     code="EXISTING_FIELD_CHANGED")
        dropped = dict(files)
        dropped[prefix + "/context/legacy.md"] = legacy.replace(
            "usage_count: 5000\n", "").encode("utf-8")
        self.refused(scope, settings, dropped, current=files,
                     code="EXISTING_FIELD_CHANGED")
        retyped = dict(files)
        retyped[prefix + "/context/legacy.md"] = legacy.replace(
            "type: BigQuery Table", "type: context").encode("utf-8")
        self.refused(scope, settings, retyped, current=files, code="TYPE_MISMATCH")

    def test_removal_requires_a_selected_pending_draft(self):
        scope, settings = self.scope(), self.settings()
        queue_id = capture(settings).queue_id
        location = "pending/" + queue_id + ".md"
        prefix, files = self.initial(scope)
        files[prefix + "/" + location] = concept("decision", "Queued", "stable").encode("utf-8")
        files[prefix + "/pending/index.md"] = (
            "# Pending\n\n* [Queued](/%s) - short.\n" % location).encode("utf-8")
        proposed = dict(files)
        del proposed[prefix + "/" + location]
        proposed[prefix + "/pending/index.md"] = b"# Pending\n"
        self.refused(scope, settings, proposed, current=files, selected=(queue_id,),
                     code="INCOHERENT_STATUS")
        fresh = dict(files)
        fresh[prefix + "/" + location] = concept("decision", "Queued", "draft").encode("utf-8")
        fresh[prefix + "/pending/index.md"] = (
            "# Pending\n\n* [Queued](/%s) - DRAFT.\n" % location).encode("utf-8")
        self.assertEqual((location,), self.validate(
            scope, settings, proposed, current=fresh, selected=(queue_id,)).removed)
        rewritten = dict(fresh)
        rewritten[prefix + "/" + location] = concept(
            "decision", "Queued", "draft", body="# Changed\n").encode("utf-8")
        self.refused(scope, settings, rewritten, current=fresh,
                     code="UNSELECTED_PENDING_MUTATION")

    def test_initialization_requires_the_registration_log_and_empty_indexes(self):
        scope, settings = self.scope(), self.settings()
        prefix, files = self.initial(scope)
        prefix_names = ("MISSING_LOG_ENTRY", "INITIALIZATION_LOG_FORM", "INVALID_LOG_DATE")
        cases = {
            "INITIALIZATION_LOG_FORM": b"# Update log\n\n## 2026-10-01\n* created\n",
            "INVALID_LOG_DATE": (b"# Update log\n\n## 0000-01-01\n"
                                 b"* **Initialization**: created\n"),
            "MISSING_LOG_ENTRY": b"# Update log\n\n* **Initialization**: created\n",
        }
        self.assertTrue(prefix_names)
        for code, log in cases.items():
            with self.subTest(code=code):
                value = dict(files, **{prefix + "/log.md": log})
                self.refused(scope, settings, value, code=code)
        two_dates = dict(files, **{prefix + "/log.md": (
            b"# Update log\n\n## 2026-10-02\n* entry\n\n## 2026-10-01\n"
            b"* **Initialization**: created\n")})
        self.refused(scope, settings, two_dates, code="INITIALIZATION_LOG_FORM")
        empty_frontmatter = dict(files, **{prefix + "/context/index.md": b"---\n---\n\n# Context\n"})
        self.refused(scope, settings, empty_frontmatter, code="UNEXPECTED_FRONTMATTER")
        listed = dict(files, **{prefix + "/context/index.md": b"# Context\n\n- reserved\n"})
        self.refused(scope, settings, listed, code="INITIALIZATION_NOT_EMPTY")
        self.validate(scope, settings, files)

    def test_parsed_scalars_and_flow_keys_obey_canonical_text_rules(self):
        scope, settings = self.scope(), self.settings()
        prefix, current = self.initial(scope)
        cases = {
            "DISALLOWED_CONTROL": concept("context", "Pick\u0000SQLite"),
            "CR_LINE_ENDING": concept("context", "Pick\u000dSQLite"),
            "NON_CANONICAL_TEXT": concept("context", "Cafe\u0301"),
            "UNSAFE_SCALAR": b"---\ntype: context\ntitle: .nan\n---\n\n# x\n",
            "UNSAFE_YAML": (b"---\ntype: context\ntitle: x\n"
                            b"sources:\n  - resource: a\n    \"resource\": b\n---\n\n# x\n"),
        }
        for code, text in cases.items():
            with self.subTest(code=code):
                _prefix, files = self.update(scope, document_text=text)
                self.refused(scope, settings, files, current=current, code=code)
        separator = dict(current)
        separator[prefix + "/context/index.md"] = (
            "# Context\n\n* [Pick](\u2028/context/pick-sqlite.md)\n").encode("utf-8")
        separator[prefix + "/context/pick-sqlite.md"] = concept(
            "context", "Pick", "stable").encode("utf-8")
        self.refused(scope, settings, separator, current=current,
                     code="DISALLOWED_CONTROL")
        uppercase_git = dict(current)
        uppercase_git[prefix + "/.GIT/config"] = b"x"
        self.refused(scope, settings, uppercase_git, code="REPOSITORY_METADATA")

    def test_configured_content_ceilings_and_provenance_vocabulary(self):
        scope = self.scope()
        _prefix, current = self.initial(scope)
        _prefix, files = self.update(scope, document_text=concept(
            "context", "Pick SQLite", "stable"))
        self.refused(scope, self.settings(title_chars=5), files, current=current,
                     code="TITLE_TOO_LONG")
        researched = dict(current)
        researched[_prefix + "/research/survey.md"] = concept(
            "research", "Survey", "stable").encode("utf-8")
        researched[_prefix + "/research/index.md"] = (
            "# Research\n\n* [Survey](/research/survey.md) - short.\n").encode("utf-8")
        self.refused(scope, self.settings(), researched, current=current,
                     code="SOURCE_REQUIRED")
        sourced = ("---\ntype: research\ntitle: Survey\nstatus: stable\nsources:\n"
                   "  - resource: https://example.com/a\n"
                   "  - resource: https://example.com/b\n---\n\n# Survey\n")
        swapped = dict(researched)
        swapped[_prefix + "/research/survey.md"] = sourced.encode("utf-8")
        self.refused(scope, self.settings(sources=1), swapped, current=current,
                     code="TOO_MANY_SOURCES")
        self.validate(scope, self.settings(), swapped, current=current)

    def test_refusal_evidence_is_bounded_without_echoing_caller_paths(self):
        scope, settings = self.scope(), self.settings()
        prefix, files = self.initial(scope)
        foreign = dict(files)
        foreign["projects/github.com/acme/" + "x" * 60 + "/index.md"] = b"x"
        error = self.refused(scope, settings, foreign, code="FOREIGN_PROJECT")
        self.assertEqual("proposed", error.field)
        _prefix, update = self.update(scope)
        long_path = dict(update)
        long_path[prefix + "/context/" + "a" * 100000 + ".md"] = concept(
            "context", "Long").encode("utf-8")
        error = self.refused(scope, settings, long_path, current=files, code="UNSAFE_PATH")
        self.assertLessEqual(len(error.field), 200)
        long_text = dict(update)
        long_text[prefix + "/context/pick-sqlite.md"] = concept(
            "context", "Pick", "stable").replace("Text.", "x" * 100000).encode("utf-8")
        with self.assertRaises(library.LibraryError) as raised:
            self.validate(scope, self.settings(document_bytes=1024), long_text, current=files)
        self.assertLessEqual(len(raised.exception.field), 200)

    def test_implicit_yaml_types_are_refused_only_where_the_writer_owns_them(self):
        scope, settings = self.scope(), self.settings()
        prefix, current = self.initial(scope)
        legacy = ("---\ntype: BigQuery Table\ntitle: Legacy\narchived: false\n"
                  "note: null\nusage_count: 5000\n---\n\n# Legacy\n")
        current[prefix + "/context/legacy.md"] = legacy.encode("utf-8")
        current[prefix + "/context/index.md"] = (
            "# Context\n\n* [Legacy](/context/legacy.md) - tolerated.\n").encode("utf-8")
        proposed = dict(current)
        proposed[prefix + "/context/pick-sqlite.md"] = concept(
            "context", "Pick SQLite", "stable").encode("utf-8")
        proposed[prefix + "/context/index.md"] = (
            "# Context\n\n* [Legacy](/context/legacy.md) - tolerated.\n"
            "* [Pick SQLite](/context/pick-sqlite.md) - short.\n").encode("utf-8")
        proposed[prefix + "/log.md"] = NEW_LOG.encode("utf-8")
        result = self.validate(scope, settings, proposed, current=current)
        self.assertIn("context/pick-sqlite.md", result.added)
        self.assertEqual(legacy.encode("utf-8"), result.files[prefix + "/context/legacy.md"])
        retyped = dict(proposed)
        retyped[prefix + "/context/legacy.md"] = legacy.replace(
            "usage_count: 5000", 'usage_count: "5000"').encode("utf-8")
        self.refused(scope, settings, retyped, current=current,
                     code="EXISTING_FIELD_CHANGED")

        cases = {
            "UNSAFE_SCALAR": b"---\ntype: context\ntitle: 2024-01-01\nstatus: stable\n---\n\n# x\n",
            "UNSAFE_YAML": b"---\ntype: context\ntitle: Note: important\n---\n\n# x\n",
        }
        for code, text in cases.items():
            with self.subTest(code=code):
                files = dict(proposed)
                files[prefix + "/context/pick-sqlite.md"] = text
                self.refused(scope, settings, files, current=current, code=code)
        unquoted_version = dict(current)
        unquoted_version[prefix + "/index.md"] = root_index(
            scope.project_path, scope.project_identity).replace('"0.2"', "0.2").encode("utf-8")
        self.refused(scope, settings, unquoted_version, current=current,
                     code="INVALID_OKF_VERSION")
        bogus_status = dict(current)
        bogus_status[prefix + "/context/legacy.md"] = legacy.replace(
            "title: Legacy", "title: Legacy\nstatus: bogus").encode("utf-8")
        self.refused(scope, settings, bogus_status, current=current,
                     code="UNSUPPORTED_STATUS")
        unsourced_pending = dict(current)
        queue_id = capture(settings).queue_id
        unsourced_pending[prefix + "/pending/" + queue_id + ".md"] = concept(
            "research", "Unsourced", "draft").encode("utf-8")
        unsourced_pending[prefix + "/pending/index.md"] = (
            "# Pending\n\n* [Unsourced](/pending/%s.md) - DRAFT.\n" % queue_id).encode("utf-8")
        self.refused(scope, settings, unsourced_pending, current=current,
                     code="SOURCE_REQUIRED")
        researched = dict(current)
        researched[prefix + "/research/sourced.md"] = concept(
            "research", "Sourced", "stable",
            fields=("sources:", "  - resource: https://example.com/a",
                    "    secret_note: xyz")).encode("utf-8")
        researched[prefix + "/research/index.md"] = (
            "# Research\n\n* [Sourced](/research/sourced.md) - short.\n").encode("utf-8")
        self.refused(scope, settings, researched, current=current,
                     code="UNSUPPORTED_FIELD")

    def test_existing_state_and_nested_metadata_are_preserved_with_bounded_parsing(self):
        scope, settings = self.scope(), self.settings()
        prefix, initial = self.initial(scope)
        conflicting = dict(initial)
        conflicting[prefix + "/index.md"] = root_index(
            scope.project_path, "github.com:OTHER-ID").encode("utf-8")
        self.refused(scope, settings, initial, current=conflicting,
                     code="MISSING_SOURCE_IDENTITY")
        malformed = dict(initial)
        malformed[prefix + "/context/index.md"] = b"no heading\n"
        self.refused(scope, settings, initial, current=malformed, code="INVALID_INDEX")

        _, current = self.update(scope, document_text=concept(
            "context", "Pick SQLite", "stable", fields=("custom: {flag: false}",)))
        retyped = dict(current)
        path = prefix + "/context/pick-sqlite.md"
        retyped[path] = current[path].replace(b"flag: false", b'flag: "false"')
        self.refused(scope, settings, retyped, current=current,
                     code="EXISTING_FIELD_CHANGED")
        _, sourced = self.update(scope, document_text=concept(
            "context", "Pick SQLite", "stable",
            fields=("sources:", "  - resource: https://example.com/a",
                    "    author: LegacyAuthor")))
        dropped = dict(sourced)
        dropped[path] = sourced[path].replace(b"    author: LegacyAuthor\n", b"")
        self.refused(scope, settings, dropped, current=sourced,
                     code="EXISTING_FIELD_CHANGED")

        nested = "".join(" " * depth + "k:\n" for depth in range(500)) + " " * 500 + "leaf: value\n"
        deep = self.update(scope, document_text=(
            "---\ntype: context\ntitle: Pick SQLite\ncustom:\n"
            + "".join("  " + line + "\n" for line in nested.splitlines())
            + "---\n\n# Body\n"))[1]
        self.refused(scope, self.settings(document_bytes=1 << 20, projection_bytes=1 << 20),
                     deep, current=initial, code="INVALID_YAML")

        list_title = self.update(scope, document_text=concept(
            "context", "Pick SQLite", "stable",
            fields=("sources:", "  - resource: https://example.com/a",
                    "    title: [nested, list]")))[1]
        self.refused(scope, settings, list_title, current=initial,
                     code="INVALID_SOURCES")
        long_source_title = self.update(scope, document_text=concept(
            "context", "Pick SQLite", "stable",
            fields=("sources:", "  - resource: https://example.com/a",
                    '    title: "%s"' % ("t" * 40))))[1]
        self.refused(scope, self.settings(title_chars=5), long_source_title,
                     current=initial, code="TITLE_TOO_LONG")
        trailing_dot = self.update(
            scope, document_text="---\ntype: context\ntitle: 1.\nstatus: stable\n---\n\n# x\n",
            index_text="# Context\n\n* [1.](/context/pick-sqlite.md)\n")[1]
        self.refused(scope, settings, trailing_dot, current=initial,
                     code="UNSAFE_SCALAR")

    def test_registration_identity_and_source_edits_use_complete_values(self):
        scope, settings = self.scope(), self.settings()
        prefix, initial = self.initial(scope)
        for identity in (scope.project_identity + "0", "x" + scope.project_identity):
            with self.subTest(identity=identity):
                conflicting = dict(initial)
                conflicting[prefix + "/index.md"] = root_index(
                    scope.project_path, identity).encode("utf-8")
                self.refused(scope, settings, initial, current=conflicting,
                             code="MISSING_SOURCE_IDENTITY")
        moved = dict(initial)
        moved[prefix + "/index.md"] = root_index(
            scope.project_path + "2", scope.project_identity).encode("utf-8")
        self.refused(scope, settings, initial, current=moved,
                     code="MISSING_SOURCE_IDENTITY")

        path = prefix + "/context/pick-sqlite.md"
        _, current = self.update(scope, document_text=concept(
            "context", "Pick SQLite", "stable", fields=(
                "sources:", "  - resource: https://example.com/a",
                "    title: Typo", "    author: LegacyAuthor")))
        corrected = dict(current)
        corrected[path] = current[path].replace(b"title: Typo", b"title: Corrected")
        self.assertIn("context/pick-sqlite.md",
                      self.validate(scope, settings, corrected, current=current).updated)
        deflowered = dict(current)
        deflowered[path] = current[path].replace(
            b"sources:\n  - resource: https://example.com/a\n    title: Typo\n"
            b"    author: LegacyAuthor\n", b"")
        self.refused(scope, settings, deflowered, current=current,
                     code="EXISTING_FIELD_CHANGED")
        unsourced = dict(current)
        unsourced[path] = current[path].replace(
            b"sources:\n  - resource: https://example.com/a\n    title: Typo\n"
            b"    author: LegacyAuthor\n", b"sources:\n  - resource: https://example.com/b\n")
        self.refused(scope, settings, unsourced, current=current,
                     code="EXISTING_FIELD_CHANGED")
        _, ordinary = self.update(scope, document_text=concept(
            "context", "Pick SQLite", "stable", fields=(
                "sources:", "  - resource: https://example.com/a", "    title: Typo")))
        optional = dict(ordinary)
        optional[path] = ordinary[path].replace(
            b"sources:\n  - resource: https://example.com/a\n    title: Typo\n", b"")
        self.assertIn("context/pick-sqlite.md",
                      self.validate(scope, settings, optional, current=ordinary).updated)

if __name__ == "__main__":
    unittest.main()
