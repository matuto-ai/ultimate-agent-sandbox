#!/usr/bin/env python3
"""Fixed archive tests under pre-import process/socket/privilege guards."""
import run_native_combined_image_source as guarded

guarded.TEST_CLASSES = (('test_native_image_archive', 'NativeImageArchiveTests'),)

if __name__ == '__main__':
    raise SystemExit(guarded.main())
