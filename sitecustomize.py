import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
for folder in ("data", "features", "models", "streaming", "api"):
    path = os.path.join(ROOT, folder)
    if path not in sys.path:
        sys.path.insert(0, path)
