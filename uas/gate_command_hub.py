"""Command lifecycle bindings without weakening the artifacts-only profile."""
from .artifact_protocol import TARGET_KEYS
from .gate_evaluation import ArtifactGateHub, SCRATCH_BYTES
from .gate_repository import WORK_BYTES, validate_command_target


class CommandGateHub(ArtifactGateHub):
    scratch_bytes = SCRATCH_BYTES + WORK_BYTES

    @staticmethod
    def _validate_target(target, source):
        validate_command_target(target)
        ArtifactGateHub._validate_target({key: target[key] for key in TARGET_KEYS}, source)

    @staticmethod
    def _validate_cleanup(proof):
        ArtifactGateHub._validate_cleanup(proof, target_validator=validate_command_target)
