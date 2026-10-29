"""Library Git lease fixture; never imported by production code."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]
from uas.library import LibraryError
from uas.library_git import LibraryGit
from uas.library_records import LibraryRecords

root, records_path, target, branch = sys.argv[1:5]
publisher = LibraryGit(root, records_path=records_path, deployment_id="deployment-1",
                       target=target, branch=branch)
try:
    recovery = publisher.startup()
    print(json.dumps({"head": recovery.head_sha}), flush=True)
except LibraryError as error:
    print(json.dumps({"error": error.code}), flush=True)
finally:
    publisher.close()
