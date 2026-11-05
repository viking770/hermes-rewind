"""Keep the tests away from the real Hermes home and the real Docker cleanup."""
import os
import tempfile

os.environ["REWIND_STATE_DIR"] = tempfile.mkdtemp(prefix="rewind-tests-")
os.environ["REWIND_AUTO_GC"] = "0"
