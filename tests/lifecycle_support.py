"""File-backed resource simulator for supervisor fault tests, not Docker proof."""
import json
from pathlib import Path

from uas.lifecycle import BackendUnknown, OwnershipConflict


class FileFixtureBackend:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir()
        self.calls = []
        self.fail_before = set()
        self.fail_after = set()
        self.revoke_verified = True

    def name(self, state, kind):
        return state["instance_id"] + "-" + kind

    def path(self, state, kind):
        return self.root / self.name(state, kind)

    def inspect(self, state, kind):
        path = self.path(state, kind)
        if not path.exists():
            return None
        resource = json.loads(path.read_text())
        if resource["owner"] != state["instance_id"]:
            raise OwnershipConflict()
        return resource

    def _before(self, operation):
        self.calls.append(operation)
        if operation in self.fail_before:
            raise BackendUnknown()

    def _after(self, operation):
        if operation in self.fail_after:
            raise BackendUnknown()

    def create(self, state, kind):
        operation = "create-" + kind
        self._before(operation)
        resource = {"id": self.name(state, kind), "owner": state["instance_id"],
                    "running": False, "image_id": state["spec"]["image_id"], "unowned_setting": "preserved"}
        self.path(state, kind).write_text(json.dumps(resource))
        self._after(operation)

    def start(self, state):
        self._before("start")
        resource = self.inspect(state, "container")
        resource["running"] = True
        self.path(state, "container").write_text(json.dumps(resource))
        self._after("start")

    def stop(self, state):
        self._before("stop")
        resource = self.inspect(state, "container")
        resource["running"] = False
        self.path(state, "container").write_text(json.dumps(resource))
        self._after("stop")

    def remove(self, state, kind):
        operation = "remove-" + kind
        self._before(operation)
        self.path(state, kind).unlink(missing_ok=True)
        self._after(operation)

    def revoke(self, instance, scope):
        self.calls.append("revoke-" + scope)
        return self.revoke_verified
