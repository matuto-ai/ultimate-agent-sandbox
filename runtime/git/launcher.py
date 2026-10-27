#!/usr/bin/python3 -I
import os
import sys
sys.path.insert(0, '/opt/uas')
from uas.git_launcher import main
try:
    sys.exit(main(sys.argv[1:], invoked_as=os.path.basename(sys.argv[0])))
except Exception as error:
    code = getattr(error, 'code', 'GIT_UNAVAILABLE')
    sys.stderr.write('Controlled Git: ' + code + '\n')
    sys.exit(128)
