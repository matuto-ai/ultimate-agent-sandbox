#!/usr/bin/env python3
"""Run the fixed artifact-retention suite with pre-import effect guards."""
import run_native_combined_image_source as guarded

guarded.TEST_CLASSES = (('test_native_image_artifact_retention', 'NativeImageArtifactRetentionTests'),)

if __name__ == '__main__':
    raise SystemExit(guarded.main())
