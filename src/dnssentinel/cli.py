"""Command line entrypoint."""
import argparse
import json
from pathlib import Path
from .detector import analyze, read_queries


def main() -> None:
    parser = argparse.ArgumentParser(description="Offline DNS anomaly triage")
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--observed", required=True)
    parser.add_argument("--output", help="Optional JSON report")
    parser.add_argument("--contamination", type=float, default=0.1)
    args = parser.parse_args()
    results = analyze(read_queries(args.baseline), read_queries(args.observed), args.contamination)
    report = {"total": len(results), "flagged": sum(item["anomaly"] for item in results), "results": results}
    content = json.dumps(report, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(content, encoding="utf-8")
    else:
        print(content, end="")


if __name__ == "__main__":
    main()
