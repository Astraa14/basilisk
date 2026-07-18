"""Shared fixtures for backend tests."""

import os
import tempfile

os.environ.setdefault("DATABASE_URL", f"sqlite:///{tempfile.mktemp(suffix='.db')}")
