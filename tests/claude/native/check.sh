#!/bin/sh
# Hosted cheap source checks only. No compiled binary is executed.
set -eu
cd "$(dirname "$0")/../../.."
for source in runtime/claude/host-bootstrap.c runtime/claude/native-bootstrap.c runtime/claude/mcp-connector.c; do
  cc -std=c11 -Wall -Wextra -Werror -fsyntax-only "$source"
done
node --check runtime/claude/native-host.mjs
node --check runtime/claude/mcp-server.mjs
node tests/claude/native/policy.mjs
node --check runtime/provider-auth.mjs
node --check runtime/pi/native-entry.mjs
node tests/claude/native/provider-auth.mjs
node --check runtime/pi/provider-store.mjs

node tests/claude/native/pi-startup.mjs
node tests/claude/native/pi-resume.mjs
