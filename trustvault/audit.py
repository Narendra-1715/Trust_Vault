import sys
import os

root_dir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
backend_dir = os.path.join(root_dir, "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.audit.cli import main

if __name__ == "__main__":
    sys.exit(main())
