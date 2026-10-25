"""Kill after actual Docker container removal to exercise persisted intent."""
from pathlib import Path
import os
import signal
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from uas.docker_fixture import DockerFixtureBackend
from uas.lifecycle import Supervisor


class InterruptedBackend(DockerFixtureBackend):
    def remove(self, state, kind):
        super().remove(state, kind)
        if kind == "container":
            os.kill(os.getpid(), signal.SIGKILL)


# The CI fixture issues no endpoint/Participant capabilities. Verification of an
# empty authority set is deliberate, not a production authentication substitute.
supervisor = Supervisor(sys.argv[1], "alpha", InterruptedBackend(),
                        authorize=lambda *_: True, revoke=lambda *_: True)
supervisor.destroy()
raise SystemExit("expected interruption was not reached")
