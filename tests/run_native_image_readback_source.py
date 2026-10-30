#!/usr/bin/env python3
"""Reuse the existing pre-import effect guard with a fixed readback test suite."""
import run_native_combined_image_source as guarded

guarded.TEST_CLASSES = (('test_native_image_readback', 'NativeImageReadbackTests'),)

if __name__ == '__main__':
    raise SystemExit(guarded.main())
