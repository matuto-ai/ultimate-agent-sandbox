#!/usr/bin/env bash
# PROTOTYPE fixture: a fake long-lived agent CLI standing in for Pi/Claude
# where those binaries or their credentials are unavailable.
# Proves supervisor mechanics only; it is not a runtime compatibility shim.
echo "fakecli up mode=${1:-fresh} session=${FAKECLI_SESSION:-none}"
while IFS= read -r line; do
  line="${line%$'\r'}"
  case "$line" in
    mark\ *) echo "${line#mark }" >> "${FAKECLI_MARKER:?FAKECLI_MARKER unset}" ;;
  esac
  echo "ack: $line"
done
echo "fakecli down"
