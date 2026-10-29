#!/usr/bin/env python3
"""Finite pre-import guarded Hub packaging/readback checks; no Docker/VM."""
import run_native_combined_image_source as guarded

guarded.TEST_CLASSES = (('test_native_hub_image','NativeHubImageTests'),)

if __name__ == '__main__': raise SystemExit(guarded.main())
