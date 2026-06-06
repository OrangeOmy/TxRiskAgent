#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from signshield.openai_subagent import run_openai_subagent  # noqa: E402


def main() -> int:
    try:
        context = json.load(sys.stdin)
    except Exception as exc:
        print(json.dumps({"status": "error", "assessments": [], "limitations": [f"Invalid context JSON: {exc}"]}, ensure_ascii=False))
        return 0
    result = run_openai_subagent(context)
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
