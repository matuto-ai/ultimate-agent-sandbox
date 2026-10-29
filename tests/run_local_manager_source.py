#!/usr/bin/env python3
"""Finite Manager source checks; no process/network/privilege effects."""
import run_native_combined_image_source as guarded

guarded.TEST_CLASSES = (('test_local_manager','LocalManagerTests'),
                        ('test_local_manager','ManagerSelectionTests'),
                        ('test_human_mtls_source','HumanMTLSSourceTests'))
if __name__=='__main__':raise SystemExit(guarded.main())
