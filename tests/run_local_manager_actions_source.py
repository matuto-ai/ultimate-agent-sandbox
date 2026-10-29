#!/usr/bin/env python3
import run_native_combined_image_source as guarded
guarded.TEST_CLASSES=(('test_local_manager_actions','LocalManagerActionsTests'),)
if __name__=='__main__':raise SystemExit(guarded.main())
