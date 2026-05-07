"""Test-suite-wide setup."""

import os

# The API module fails-fast at import if the pipeline's required env vars
# are missing. Tests don't actually start the pipeline (runner.start is
# mocked), so any non-empty placeholder satisfies the check.
os.environ.setdefault("SERVER_STREAM_SOURCE", "tcp://localhost:5555")
os.environ.setdefault("PANDA_STREAM_SOURCE", "tcp://localhost:5556")
os.environ.setdefault("TILED_BASE_URL", "http://localhost:8000")
