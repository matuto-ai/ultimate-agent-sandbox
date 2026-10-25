"""Subprocess recovery/concurrency fixture; never imported by production code."""
import json
from pathlib import Path
import os
import signal
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]
from ledger_support import ORIGIN, authorized, command, increment
from uas.ledger import LedgerError, RoomLedger

path, mode = sys.argv[1:3]
with RoomLedger(path, "alpha") as ledger:
    if mode in {"before", "after"}:
        commit = ledger._commit
        def interrupted_commit():
            if mode == "after":
                commit()
            os.kill(os.getpid(), signal.SIGKILL)
        ledger._commit = interrupted_commit
    if mode == "partial":
        def interrupt_statement(statement):
            if statement.startswith("INSERT INTO operations"):
                os.kill(os.getpid(), signal.SIGKILL)
        ledger._db.set_trace_callback(interrupt_statement)
    if mode == "snapshot":
        print(json.dumps({"snapshot": ledger.snapshot(), "events": ledger.replay(0)}), flush=True)
    else:
        operation = command(sys.argv[3] if len(sys.argv) > 3 else "op-1",
                            int(sys.argv[4]) if len(sys.argv) > 4 else 1)
        try:
            print(json.dumps(ledger.apply(operation, ORIGIN, authorize=authorized, decide=increment)), flush=True)
        except LedgerError as error:
            print(json.dumps({"error": error.code}), flush=True)
