#!/usr/bin/python3 -I
"""Fixed image entry; never import Project Python or ambient PYTHONPATH."""
import sys

sys.path.insert(0, '/opt/uas')
from uas.git_worker import main

if __name__ == '__main__':
    main()
