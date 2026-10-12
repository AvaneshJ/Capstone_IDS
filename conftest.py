import os
import tempfile

# Keep test runs away from the real per-install token, HMAC key, manifest and evidence anchors.
os.environ["SENTINEL_DATA_DIR"] = tempfile.mkdtemp(prefix="sentinel_test_data_")
os.environ.pop("SENTINEL_API_TOKEN", None)
os.environ.pop("SENTINEL_INTEGRITY_REQUIRED", None)
