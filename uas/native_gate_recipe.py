"""Exact optional artifacts mounts, never arbitrary /uas prefix exceptions."""
import hashlib


def strip_mounts(mounts, profile, git_profile, *, seat, image_id, image_reference):
    if profile is None:
        return mounts
    from .native_pi_recipe import NativeRecipeError, below
    from .native_gate_resources import NativeGateMountProfile, NativeGateMount
    from .native_git_resources import GitMountProfile
    from .artifact_protocol import canonical
    if (type(profile) is not NativeGateMountProfile or type(git_profile) is not GitMountProfile
            or type(mounts) is not tuple or profile.room_id != seat.room_id
            or profile.instance_id != seat.room_instance or profile.container_id != seat.container_id
            or profile.image_id != image_id or profile.image_reference != image_reference
            or profile.mapping_digest != git_profile.mapping_digest):
        raise NativeRecipeError('exact native artifacts projection binding required')
    document = profile.document()
    if (document.get('room_id') != profile.room_id or document.get('instance') != profile.instance_id
            or document.get('container_id') != profile.container_id or document.get('image_id') != image_id
            or document.get('image_reference') != image_reference
            or document.get('mapping_digest') != profile.mapping_digest
            or hashlib.sha256(canonical(document)).hexdigest() != profile.digest):
        raise NativeRecipeError('native artifacts projection changed')
    selected = tuple(m for m in mounts if type(m) is NativeGateMount)
    remainder = tuple(m for m in mounts if type(m) is not NativeGateMount)
    if (selected != profile.mounts or len(selected) != 2 or len(remainder) != 13
            or tuple(m.destination for m in selected) != ('/uas/gate-targets','/uas/gate')
            or any(m.read_only is not True for m in selected)
            or document.get('mounts') != [m.__dict__ for m in selected]
            or len({m.destination for m in mounts}) != len(mounts)):
        raise NativeRecipeError('exact complete artifacts projection required')
    if any(below(a.destination,b.destination) or below(b.destination,a.destination)
           for a in selected for b in remainder):
        raise NativeRecipeError('artifacts projection aliases native mounts')
    return remainder
