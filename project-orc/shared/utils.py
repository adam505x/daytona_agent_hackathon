import json
import os
from datetime import datetime


def save_output(data: dict, filename: str = None) -> str:
    """Save results to output/ directory, return path."""
    os.makedirs("output", exist_ok=True)
    if filename is None:
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        filename = f"results_{ts}.json"
    path = os.path.join("output", filename)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path


def load_json(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def chunk_list(lst: list, size: int) -> list[list]:
    """Split list into chunks of at most `size`."""
    return [lst[i : i + size] for i in range(0, len(lst), size)]
