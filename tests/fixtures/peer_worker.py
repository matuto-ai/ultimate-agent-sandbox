"""Real crash worker around fixture receiver/Hub commits; never starts an agent."""
import signal
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from uas.fixture_peer import FixtureReceiver
from uas.ledger import RoomLedger
from uas.peer import FixturePeerHub, Readiness

root, phase = Path(sys.argv[1]), sys.argv[2]
ledger = RoomLedger(root / "room.db", "alpha")
receiver = FixtureReceiver(root / "bob.db", "alpha", "bob", "bob-1")
hub = FixturePeerHub(ledger)
connection = hub.connect("worker-attach", "bob", "bob-1", receiver)
hub.observe(connection, Readiness.SAFE)


def pause():
    print("CRASH_POINT", flush=True)
    while True:
        signal.pause()


receiver_commit = receiver._commit

def commit_receiver():
    if phase == "receiver-before-commit":
        pause()
    receiver_commit()
    if phase == "receiver-after-commit":
        pause()


hub_commit = ledger._commit

def commit_hub():
    event = ledger._connection().execute("SELECT event FROM events ORDER BY seq DESC LIMIT 1").fetchone()[0]
    import json
    kind = json.loads(event)["kind"]
    if kind == "peer.delivery.confirmed" and phase == "hub-before-confirm":
        pause()
    hub_commit()
    if ((kind == "peer.delivery.offered" and phase == "hub-after-offer")
            or (kind == "peer.delivery.confirmed" and phase == "hub-after-confirm")):
        pause()


receiver._commit = commit_receiver
ledger._commit = commit_hub
hub.deliver(connection)
raise RuntimeError("crash point was not reached")
