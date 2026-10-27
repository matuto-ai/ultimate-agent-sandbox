#!/bin/bash
# Run only on an explicitly selected disposable Docker test host (CI).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export PYTHONDONTWRITEBYTECODE=1
command -v docker
command -v go
docker version
go version
# Capture the real typed-inspect absence contract without creating a resource.
python3 - <<'PYPROBE'
import subprocess, uuid
from uas.docker_fixture import DockerFixtureBackend
name = "uas-absence-probe-" + uuid.uuid4().hex
arguments = ["inspect", "--type", "volume", name]
result = subprocess.run(["docker", *arguments], capture_output=True, text=True, timeout=20)
print("Docker volume absence probe:", result.returncode, repr(result.stderr), flush=True)
assert result.returncode == 1, "unexpected absence probe result"
assert DockerFixtureBackend()._run(arguments, missing_ok=True) is None
PYPROBE
build="$(mktemp -d)"
image=""
cleanup() {
  if [[ -n "$image" ]]; then docker image rm "$image"; fi
  rm -rf -- "$build" # Only this script's newly created build directory.
}
trap cleanup EXIT
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GO111MODULE=off CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o "$build/fixture" tests/fixtures/workstation/main.go
mkdir "$build/state"
touch "$build/state/.keep"
cp tests/fixtures/workstation/Dockerfile "$build/Dockerfile"
docker build --pull=false --network=none --iidfile "$build/image-id" "$build"
image="$(cat "$build/image-id")"
[[ "$image" =~ ^sha256:[0-9a-f]{64}$ ]]
export UAS_DOCKER_FIXTURE_IMAGE="$image"
python3 -m unittest discover -s tests -p test_lifecycle_docker.py -v
# Bounded actual endpoint-mount/resource hook proof; no native Broker claim.
python3 -m unittest discover -s tests -p test_room_fixture_docker.py -v
