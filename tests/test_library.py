"""Library contract seam and fail-closed settings admission, with no effects."""
from copy import deepcopy
import io
import json
from pathlib import Path
import socket
import subprocess
import unittest
from unittest.mock import patch

from uas import config as deployment_config
from uas import library
from uas.ledger import Origin
from uas.manager_actions import HumanSession

AT = "2026-10-28T22:00:00+00:00"
FIXTURE = Path(__file__).parent / "fixtures" / "two-rooms.json"
ORIGIN = Origin("actor-alpha", "seat-a", "inc-1", "epoch-1", ("implement", "library-enqueue"))
REVOKED = Origin("actor-alpha", "seat-a", "inc-1", "epoch-2", ("implement",))
OTHER = Origin("actor-beta", "seat-b", "inc-2", "epoch-2", ("library-enqueue",))
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


def binding(project_id="alpha", repository="acme/alpha"):
    return library.project_binding({"id": project_id, "repository": repository,
                                    "roots": {"reference": "/srv/" + project_id + "/reference"}})


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
        for branch in ("-library", "a..b", "library/", "library//canonical"):
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

    def test_unadmitted_settings_fail_typed_at_operation_start(self):
        for value, code in ((None, "INVALID_SETTINGS"), ({}, "UNSUPPORTED_SETTINGS_VERSION"),
                            ({"version": 1}, "MISSING_FIELD")):
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

    def test_profiles_can_declare_library_capabilities(self):
        raw = json.loads(FIXTURE.read_text())
        raw["rooms"][0]["profiles"][0]["capabilities"].append("library-enqueue")
        admitted = deployment_config.load(io.StringIO(json.dumps(raw)))
        self.assertEqual("hub", admitted["capability_enforcement"]["library-enqueue"])


class ScopeTests(unittest.TestCase):
    def test_participant_scope_requires_authenticated_capability(self):
        scope = library.participant_scope(ORIGIN, binding=binding())
        self.assertEqual(("participant", "alpha", "github.com/acme/alpha"),
                         (scope.subject, scope.project_id, scope.project_identity))
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

    def test_scope_cannot_be_built_outside_the_trusted_constructors(self):
        with self.assertRaises(library.LibraryError) as raised:
            library.LibraryScope(subject="human", actor_id="actor-alpha",
                                 authority_version="epoch-1", capabilities=("library-drain",),
                                 project_id="alpha", project_identity="github.com/acme/alpha",
                                 reference_root="/srv/alpha/reference/library",
                                 human_id="manager")
        self.assertEqual(("INVALID_SCOPE", "seal"),
                         (raised.exception.code, raised.exception.field))

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
        path = library.queue_path(operation.scope.project_identity, operation.queue_id)
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

    def test_queue_and_retry_identity_stay_inside_one_project(self):
        settings = admit()
        alpha = capture(settings)
        beta = capture(settings, scope=library.participant_scope(ORIGIN, binding=binding("beta",
                                                                                        "acme/beta")))
        self.assertNotEqual(alpha.queue_id, beta.queue_id)
        with self.assertRaises(library.LibraryError) as raised:
            library.identity(alpha, beta)
        self.assertEqual("INVALID_OPERATION", raised.exception.code)
        with self.assertRaises(library.LibraryError) as raised:
            library.retry(library.participant_scope(ORIGIN, binding=binding("beta", "acme/beta")),
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
                            publication=durable["publication"],
                            projection={"commit_sha": "d" * 40, "visible": True})
        self.assertEqual("INVALID_PROJECTION", raised.exception.code)
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


if __name__ == "__main__":
    unittest.main()
