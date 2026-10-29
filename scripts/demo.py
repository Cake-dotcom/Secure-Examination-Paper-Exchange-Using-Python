"""Repeatable no-prompt demonstration in a new isolated results directory.

Passwords exist only in this process environment and are discarded on exit.
Run normal setup with your own passwords for durable participant keys.
"""

import os
from pathlib import Path

from secure_exam.cli import main
from secure_exam.validation import random_bytes


def demo() -> int:
    root = Path(__file__).resolve().parents[1]
    run_root = root / "results" / ("demo-" + random_bytes(8).hex())
    variables = ("SECURE_EXAM_SENDER_PASSWORD", "SECURE_EXAM_RECIPIENT_PASSWORD")
    previous = {name: os.environ.get(name) for name in variables}
    try:
        for name in variables:
            os.environ[name] = random_bytes(32).hex()
        # Use the current workshop paper, preserving the source and existing keys.
        source = run_root / "sender/input/exam_paper.txt"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_bytes((root / "sender/input/exam_paper.txt").read_bytes())
        print(f"Isolated demo workspace: {run_root}", flush=True)
        return main(["--root", str(run_root), "simulate"])
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


if __name__ == "__main__":
    raise SystemExit(demo())
