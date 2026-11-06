"""Read-only demo API."""
from pathlib import Path
import sys

SOURCE = str(Path(__file__).resolve().parents[2] / 'src')
if SOURCE not in sys.path:
    sys.path.insert(0, SOURCE)
