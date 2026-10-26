# Explicit native payload profile

`build_payload(..., profile="native-pi-v1")` is opt-in only. It does not change
`static-go-v1`, its 900-second manual build limit, RPM limits, or automatic CI.
Native manual preparation is capped at 1,200 seconds, 3 GiB working bytes,
30,000 runtime files, 160 MiB per file, 512 MiB unpacked runtime, and a 544 MiB
runtime archive. RPM acquisition retains the existing signed Fedora 44 limits.
No VM, listener, namespace, runtime session, or paid model is started by staging.

Input is the caller's explicit source allowlist. Add exact package.json/lock,
`runtime/workstation/pi_connector.c`, Pi extension/channel/provider/guard, and
required `uas/*.py` sources. Compilation uses only the manifest-bound copies.
The runner needs Node 24.22.1/npm and a C compiler with static libc available.

`native-runtime.tar` contains ordinary files at `opt/uas/...`. Node is the
upstream Linux x64 24.22.1 archive, SHA256
`6c172a9ab6718f7b801fb5a7bd486af2ee5e32758086a04b84fcce2aa77095e6`, obtained
from the official HTTPS `https://nodejs.org/dist/v24.22.1/SHASUMS256.txt`.
Node's license is retained. Pi 1.4.0 uses the existing reviewed SHA512 lock,
registry-only acquisition, empty npm configs and `npm ci --ignore-scripts`.
Only npm `.bin` aliases are omitted; other symlinks and special files fail closed.
The C connector is statically compiled, not run; acquired Node is not run.

`manifest.json.native_runtime` binds the archive and `native-files.json`, whose
8 MiB maximum file list binds each runtime file's path, size, mode and digest.
The guest must verify both before extracting ordinary relative paths and must
reject duplicate/traversing/symlink/hardlink/special archive members. The native
profile's signed RPM roots are Python 3, tini, glibc and libstdc++; the guest
owns offline `dnf --installroot` with `tsflags=noscripts`, exact local repository
only, disabled weak dependencies, and signature verification. It copies the
packaged tini to fixed `/opt/uas/bin/tini` and measures/hashes the final rootfs.
No package lifecycle scripts, account configuration, or credentials are staged.

The Node artifact and npm packages are exact pinned inputs. Fedora RPM candidate
resolution remains version-observed and signed, **not reproducibly pinned across
build dates**; the manifest freezes its bytes for this build. Do not claim a fully
reproducible distro closure or actual native qualification from these pure tests.
A separate deliberate no-NIC Fedora CI run is required after review.
