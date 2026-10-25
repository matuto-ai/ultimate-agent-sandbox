#!/bin/bash
# The successor's current aggregate. Later slices extend it with their proof.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
export PYTHONDONTWRITEBYTECODE=1
python3 -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11+ is required"'
python3 -m unittest discover -s tests -v
