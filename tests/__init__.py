import sys
from pathlib import Path
engine_dir = Path(__file__).resolve().parent.parent / "engine"
if str(engine_dir) not in sys.path:
    sys.path.insert(0, str(engine_dir))
