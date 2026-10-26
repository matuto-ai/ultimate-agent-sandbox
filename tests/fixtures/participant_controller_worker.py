"""Disposable supervisor killed by the authority recovery test after launch."""
import json
from pathlib import Path
import signal
import sys

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO), str(REPO / "tests")]
from lifecycle_support import FileFixtureBackend
from uas.ledger import RoomLedger
from uas.lifecycle import FixtureSpec, Supervisor
from uas.participant import FixtureCredentials, FixtureSeat
from uas.peer import FixtureParticipant, FixturePeerHub

root = Path(sys.argv[1])
project = root / "project"
project.mkdir(parents=True)
backend = FileFixtureBackend(root / "resources")
supervisor = Supervisor(root / "control", "alpha", backend, authorize=lambda *_: True, revoke=backend.revoke)
spec = FixtureSpec("alpha", "fixture", (str(project),), *["sha256:" + c * 64 for c in "abc"])
supervisor.start(spec)
ledger = RoomLedger(root / "room.db", "alpha")
hub = FixturePeerHub(ledger)
hub.configure("configure", (FixtureParticipant("alice", "actor-a"), FixtureParticipant("bob", "actor-b")), "run-1")
controller = supervisor.participants(hub, FixtureCredentials())
handle = controller.launch(FixtureSeat("alice", "actor-a", "peer-profile", ("peer-traffic",)), None)
ready = json.loads(handle.process.stdout.readline())
print(json.dumps({"pid": ready["pid"], "incarnation": handle.badge.incarnation_id,
                  "epoch": handle.badge.epoch}), flush=True)
signal.pause()
