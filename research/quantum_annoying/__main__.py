"""Run the lab from a source checkout: python -m research.quantum_annoying."""

import argparse
from pathlib import Path

from .experiment import canonical_report, report_digest, run_experiment
from .report import render_html


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=(
            "Quantum Annoying Lab: insecure synthetic experiments, no real credentials."
        )
    )
    parser.add_argument(
        "--guesses", type=int, default=32, choices=range(2, 129), metavar="2..128"
    )
    parser.add_argument("--seed", type=int, default=20260921)
    parser.add_argument("--output", type=Path, default=Path("research/results"))
    args = parser.parse_args(argv)
    if not 0 <= args.seed < 2**32:
        parser.error("seed must be a 32-bit unsigned integer")
    report = run_experiment(args.guesses, args.seed)
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "experiment.json").write_text(
        canonical_report(report), encoding="utf-8"
    )
    (args.output / "index.html").write_text(render_html(report), encoding="utf-8")
    print(report["status"])
    for case in report["cases"]:
        metrics = case["metrics"]
        print(
            f"{case['name']}: {case['guesses']} guesses, "
            f"{metrics.get('distinct_dlog_targets', 0)} distinct DLog targets"
        )
    cross = report["cross_session"]
    print(
        f"Second session adds {cross['distinct_targets_added_second_session']} "
        "DLog target(s)"
    )
    print(f"Reproducible report SHA-256: {report_digest(report)}")
    print(f"Open {args.output / 'index.html'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
