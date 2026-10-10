"""CLI for sealed fixture-oracle runs. Not an integration/runtime verdict."""
import argparse
import json
import sys
from pathlib import Path

from tests.oracles.semantic import FAIL, INCOMPLETE, PASS, evaluate


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--case", choices=["B-037", "B-038", "B-039", "B-040"], required=True)
    parser.add_argument("--observation", type=Path, required=True)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    try:
        observation = json.loads(args.observation.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        observation = None
    verdict = evaluate(args.root, args.case, observation)
    payload = json.dumps(verdict, ensure_ascii=False, indent=2, sort_keys=True)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(payload + "\n", encoding="utf-8")
    print(payload)
    return {PASS: 0, FAIL: 1, INCOMPLETE: 3}[verdict["fixture_oracle_status"]]


if __name__ == "__main__":
    sys.exit(main())
