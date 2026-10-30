"""Exact opt-in Git projection, never an exception for arbitrary /opt binds."""


def base_mounts(mounts, profile, *, seat, checkout, image_id, image_reference, gate_profile=None):
    from .native_pi_recipe import NativeMount, NativeRecipeError
    if gate_profile is not None:
        from .native_gate_recipe import strip_mounts
        mounts = strip_mounts(mounts, gate_profile, profile, seat=seat, image_id=image_id, image_reference=image_reference)
    if profile is None:
        return mounts
    from .native_git_resources import GitMountProfile, NativeGitMount
    if (type(profile) is not GitMountProfile or type(mounts) is not tuple
            or profile.room_id != seat.room_id or profile.instance_id != seat.room_instance
            or profile.container_id != seat.container_id or profile.image_id != image_id
            or profile.image_reference != image_reference):
        raise NativeRecipeError('exact native Git projection binding required')
    profile.require_checkout('primary', checkout)
    selected = tuple(m for m in mounts if type(m) is NativeGitMount)
    ordinary = tuple(m for m in mounts if type(m) is NativeMount)
    if (selected != profile.mounts or len(ordinary) != 6
            or len(selected) != 7 or len(mounts) != 13
            or len({m.destination for m in mounts}) != len(mounts)):
        raise NativeRecipeError('exact complete native Git projection required')
    # Only the independently validated seven-role projection may overlap itself.
    # Its parents/leaves cannot cover ordinary Project/runtime/peer destinations.
    from .native_pi_recipe import below
    if any(below(a.destination,b.destination) or below(b.destination,a.destination)
           for a in ordinary for b in selected):
        raise NativeRecipeError('Git projection aliases ordinary native mounts')
    return ordinary
