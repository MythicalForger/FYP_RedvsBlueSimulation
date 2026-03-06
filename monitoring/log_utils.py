from pathlib import Path
import json
from typing import List

# Use Docker container paths when running inside container
if Path("/app").exists():
    # Running inside Docker container
    LOG_DIR = Path("/app/logs")
else:
    # Running locally
    ROOT = Path(__file__).resolve().parents[1]
    LOG_DIR = ROOT / "logs"

# Define active log files
ACTIVE_LOGS = {
    "ai_events": LOG_DIR / "ai_events.jsonl",
    "alerts": LOG_DIR / "alerts.jsonl",
    "red_sent": LOG_DIR / "red_sent.jsonl",
}


def read_jsonl(file_path) -> List[dict]:
    """
    Read a JSONL file and return a list of dictionaries.
    
    Args:
        file_path: Path to the JSONL file (str or Path object)
    
    Returns:
        List of dictionaries, one per line
    """
    items = []
    
    # Convert to Path object if string
    if isinstance(file_path, str):
        file_path = Path(file_path)
    
    # Check if file exists
    if not file_path.exists():
        return items
    
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    items.append(json.loads(line))
                except json.JSONDecodeError as e:
                    print(f"[WARNING] Failed to parse line {line_num} in {file_path}: {e}")
                    continue
    except Exception as e:
        print(f"[ERROR] Failed to read {file_path}: {e}")
    
    return items


def write_jsonl(file_path, data: List[dict]):
    """
    Write a list of dictionaries to a JSONL file.
    
    Args:
        file_path: Path to the JSONL file (str or Path object)
        data: List of dictionaries to write
    """
    # Convert to Path object if string
    if isinstance(file_path, str):
        file_path = Path(file_path)
    
    # Ensure parent directory exists
    file_path.parent.mkdir(parents=True, exist_ok=True)
    
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            for item in data:
                f.write(json.dumps(item) + "\n")
    except Exception as e:
        print(f"[ERROR] Failed to write to {file_path}: {e}")


def append_jsonl(file_path, item: dict):
    """
    Append a single dictionary to a JSONL file.
    
    Args:
        file_path: Path to the JSONL file (str or Path object)
        item: Dictionary to append
    """
    # Convert to Path object if string
    if isinstance(file_path, str):
        file_path = Path(file_path)
    
    # Ensure parent directory exists
    file_path.parent.mkdir(parents=True, exist_ok=True)
    
    try:
        with open(file_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(item) + "\n")
    except Exception as e:
        print(f"[ERROR] Failed to append to {file_path}: {e}")
