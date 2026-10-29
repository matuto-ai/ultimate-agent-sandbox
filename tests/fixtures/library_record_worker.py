"""Library record restart fixture; never imported by production code."""
import json
import os
from pathlib import Path
import signal
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]
from library_support import operation
from uas.library import LibraryError
from uas.library_records import LibraryRecords

path, mode = sys.argv[1:3]
with LibraryRecords(path, "deployment-1") as records:
    if mode == "during":
        def interrupted_commit():
            os.kill(os.getpid(), signal.SIGKILL)
        records._commit = interrupted_commit
    try:
        result = records.begin(operation())
        print(json.dumps({"state": result["state"]}), flush=True)
    except LibraryError as error:
        print(json.dumps({"error": error.code}), flush=True)
    if mode != "read":
        os.kill(os.getpid(), signal.SIGKILL)
