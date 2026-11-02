#!/usr/bin/env python3
"""Run and aggregate independent controlled D3CS/BSW07 campaigns.

The Rust benchmark performs the cryptographic measurements. This script only
orchestrates independent processes and computes campaign-level summaries.
It uses only the Python standard library.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import platform
import random
import statistics
import subprocess
import sys
import time
from pathlib import Path


RATIO_PAIRS = {
    ("BSW07", "Setup"): ("D3CS_PM23_LK10", "Setup"),
    ("BSW07", "KeyGen"): ("D3CS_PM23_LK10", "KeyGen"),
    ("BSW07", "Encrypt"): ("D3CS_PM23_LK10", "Encrypt"),
    ("BSW07", "Decrypt"): ("D3CS_PM23_LK10", "TM_Decrypt+Decrypt"),
    ("BSW07", "Delegate"): ("D3CS_PM23_LK10", "Delegate+TM_Delegate"),
}


def percentile(values: list[int], fraction: float) -> float:
    ordered = sorted(values)
    rank = max(1, math.ceil(len(ordered) * fraction))
    return float(ordered[rank - 1])


def median(values: list[int]) -> float:
    return float(statistics.median(values))


def sample_stddev(values: list[int]) -> float:
    return float(statistics.stdev(values)) if len(values) > 1 else 0.0


def bootstrap_ci(values: list[float], seed: int, iterations: int = 10000) -> tuple[float, float]:
    if len(values) < 2:
        return (float("nan"), float("nan"))
    rng = random.Random(seed)
    estimates = []
    for _ in range(iterations):
        sample = [values[rng.randrange(len(values))] for _ in values]
        estimates.append(statistics.median(sample))
    estimates.sort()
    return estimates[249], estimates[9749]


def stable_seed(base: int, value: object) -> int:
    digest = hashlib.sha256(f"{base}:{value}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big")


def block_order(seed: int, pair_id: int, block_count: int) -> list[bool]:
    order = [index < block_count // 2 for index in range(block_count)]
    state = seed ^ ((pair_id * 0x9E3779B97F4A7C15) & ((1 << 64) - 1))
    for index in range(len(order) - 1, 0, -1):
        state ^= (state << 7) & ((1 << 64) - 1)
        state ^= state >> 9
        state ^= (state << 8) & ((1 << 64) - 1)
        swap_index = state % (index + 1)
        order[index], order[swap_index] = order[swap_index], order[index]
    return order


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def command_output(command: list[str]) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
    except OSError:
        return "unavailable"
    value = result.stdout.strip()
    return value or "unavailable"


def git_status(root: Path) -> str:
    return command_output(["git", "-C", str(root), "status", "--porcelain"])


def system_conditions() -> dict[str, object]:
    governors = []
    for path in Path("/sys/devices/system/cpu").glob("cpu*/cpufreq/scaling_governor"):
        try:
            governors.append(path.read_text(encoding="utf-8").strip())
        except OSError:
            pass
    temperatures = []
    for path in Path("/sys/class/thermal").glob("thermal_zone*/temp"):
        try:
            temperatures.append({"path": str(path), "millidegrees": int(path.read_text().strip())})
        except (OSError, ValueError):
            pass
    try:
        load_average: object = list(os.getloadavg())
    except OSError:
        load_average = "unavailable"
    return {
        "cpu_frequency_lscpu": command_output(
            ["bash", "-lc", "lscpu | grep -E 'CPU MHz|CPU max MHz|CPU min MHz' || true"]
        ),
        "energy_governors": sorted(set(governors)) if governors else "unavailable",
        "load_average_at_aggregation": load_average,
        "temperatures": temperatures or "unavailable",
    }


def parse_args(root: Path) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaigns", type=int, default=5)
    parser.add_argument("--warmups", type=int, default=100)
    parser.add_argument("--measurements", type=int, default=500)
    parser.add_argument("--block-size", type=int, default=25)
    parser.add_argument("--seed", type=int, default=0x6D6574686F6431)
    parser.add_argument(
        "--output",
        type=Path,
        default=root / "results" / "bsw07_comparison_controlled",
    )
    parser.add_argument(
        "--binary",
        type=Path,
        default=root / "target" / "release" / "bsw07_comparison",
    )
    parser.add_argument("--aggregate-only", action="store_true")
    return parser.parse_args()


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    args = parse_args(root)
    if args.campaigns < 5:
        raise SystemExit("at least five independent campaigns are required")
    if args.warmups < 0 or args.measurements <= 0 or args.block_size <= 0:
        raise SystemExit("warmups, measurements and block-size are invalid")
    if args.measurements < args.block_size:
        raise SystemExit("measurements must be at least the block size")
    if args.output.exists() and not args.aggregate_only:
        raise SystemExit(f"refusing to overwrite existing output directory: {args.output}")
    if not args.aggregate_only and not args.binary.exists():
        raise SystemExit(
            f"release benchmark not found: {args.binary}; build it before running this script"
        )

    args.output.mkdir(parents=True, exist_ok=True)
    if args.aggregate_only:
        campaign_dirs = sorted(args.output.glob("campaign_*"))
        if len(campaign_dirs) < 5:
            raise SystemExit("aggregate-only requires at least five campaign directories")
        campaign_records = []
        for campaign_dir in campaign_dirs:
            metadata = json.loads((campaign_dir / "metadata.json").read_text(encoding="utf-8"))
            campaign_records.append(
                {
                    "campaign_id": int(metadata.get("campaign_id", campaign_dir.name.rsplit("_", 1)[-1])),
                    "seed": int(metadata["order_seed"]),
                    "return_code": 0,
                    "duration_seconds": 0,
                }
            )
        args.seed = min(int(record["seed"]) for record in campaign_records)
        aggregate_outputs(args, root, campaign_records)
        print(f"Controlled campaign outputs re-aggregated: {args.output}")
        return 0

    campaign_records = []
    for campaign_id in range(1, args.campaigns + 1):
        campaign_seed = args.seed + campaign_id - 1
        campaign_dir = args.output / f"campaign_{campaign_id:02d}"
        campaign_dir.mkdir()
        environment = os.environ.copy()
        environment.update(
            {
                "BSW07_COMPARISON_CONTROLLED": "1",
                "BSW07_COMPARISON_OUTPUT_DIR": str(campaign_dir),
                "BSW07_COMPARISON_CAMPAIGN_ID": str(campaign_id),
                "BSW07_COMPARISON_ORDER_SEED": str(campaign_seed),
                "BSW07_COMPARISON_ORDER_BLOCK_SIZE": str(args.block_size),
                "BSW07_COMPARISON_WARMUPS": str(args.warmups),
                "BSW07_COMPARISON_MEASUREMENTS": str(args.measurements),
                "BSW07_COMPARISON_MESSAGE_SIZES": "4,1048576",
                "RUST_BACKTRACE": "1",
            }
        )
        started = time.time()
        result = subprocess.run(
            [str(args.binary)],
            cwd=root,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        (campaign_dir / "process_stdout.log").write_text(result.stdout, encoding="utf-8")
        (campaign_dir / "process_stderr.log").write_text(result.stderr, encoding="utf-8")
        record = {
            "campaign_id": campaign_id,
            "seed": campaign_seed,
            "return_code": result.returncode,
            "duration_seconds": time.time() - started,
        }
        campaign_records.append(record)
        if result.returncode != 0:
            raise SystemExit(
                f"campaign {campaign_id} failed with code {result.returncode}; see {campaign_dir}"
            )

    aggregate_outputs(args, root, campaign_records)
    print(f"Controlled campaign completed: {args.output}")
    return 0


def aggregate_outputs(args: argparse.Namespace, root: Path, campaign_records: list[dict[str, object]]) -> None:
    raw_rows: list[dict[str, object]] = []
    summary_rows: list[dict[str, object]] = []
    size_rows: list[dict[str, object]] = []
    error_rows: list[dict[str, object]] = []
    child_metadata = []

    for record in campaign_records:
        campaign_id = int(record["campaign_id"])
        campaign_dir = args.output / f"campaign_{campaign_id:02d}"
        raw = read_csv(campaign_dir / "timings_raw.csv")
        for row in raw:
            row["campaign_id"] = campaign_id
            raw_rows.append(row)
        for row in read_csv(campaign_dir / "timings_summary.csv"):
            row["campaign_id"] = campaign_id
            summary_rows.append(row)
        for row in read_csv(campaign_dir / "sizes.csv"):
            row["campaign_id"] = campaign_id
            size_rows.append(row)
        for row in read_csv(campaign_dir / "errors.csv"):
            row["campaign_id"] = campaign_id
            error_rows.append(row)
        child_metadata.append(json.loads((campaign_dir / "metadata.json").read_text(encoding="utf-8")))

    raw_fields = ["campaign_id"] + [
        "schema",
        "operation",
        "iteration",
        "message_size_bytes",
        "user_attributes",
        "delegated_attributes",
        "policy_leaves",
        "unit",
        "duration",
        "success",
    ]
    write_csv(args.output / "timings_raw.csv", raw_fields, raw_rows)

    summary_fields = ["campaign_id"] + [
        field for field in summary_rows[0] if field != "campaign_id"
    ]
    write_csv(args.output / "timings_summary_by_campaign.csv", summary_fields, summary_rows)

    grouped: dict[tuple[str, str, str], list[tuple[int, int]]] = {}
    for row in raw_rows:
        if row["success"] != "true" or not row["duration"]:
            continue
        key = (str(row["schema"]), str(row["operation"]), str(row["message_size_bytes"]))
        grouped.setdefault(key, []).append((int(row["campaign_id"]), int(row["duration"])))

    aggregate_rows = []
    confidence_rows = []
    for key in sorted(grouped):
        schema, operation, message_size = key
        observations = [duration for _, duration in grouped[key]]
        campaign_values = []
        for campaign_id in range(1, args.campaigns + 1):
            values = [duration for cid, duration in grouped[key] if cid == campaign_id]
            if values:
                campaign_values.append(median(values))
        ci_low, ci_high = bootstrap_ci(
            campaign_values,
            stable_seed(args.seed, key),
        )
        aggregate_rows.append(
            {
                "schema": schema,
                "operation": operation,
                "message_size_bytes": message_size,
                "campaign_count": len(campaign_values),
                "valid_samples_total": len(observations),
                "mean_ns_all_samples": f"{statistics.mean(observations):.3f}",
                "median_ns_all_samples": f"{median(observations):.3f}",
                "stddev_ns_all_samples": f"{sample_stddev(observations):.3f}",
                "min_ns_all_samples": min(observations),
                "max_ns_all_samples": max(observations),
                "p95_ns_all_samples": f"{percentile(observations, 0.95):.3f}",
                "median_of_campaign_medians_ns": f"{median(campaign_values):.3f}",
                "ci95_median_low_ns": f"{ci_low:.3f}" if not math.isnan(ci_low) else "",
                "ci95_median_high_ns": f"{ci_high:.3f}" if not math.isnan(ci_high) else "",
                "ci_method": "bootstrap over campaign medians; 10000 resamples",
            }
        )
        confidence_rows.append(
            {
                "quantity": "median",
                "schema": schema,
                "operation": operation,
                "message_size_bytes": message_size,
                "campaign_count": len(campaign_values),
                "estimate_ns": f"{median(campaign_values):.3f}",
                "ci95_low_ns": f"{ci_low:.3f}" if not math.isnan(ci_low) else "",
                "ci95_high_ns": f"{ci_high:.3f}" if not math.isnan(ci_high) else "",
                "method": "bootstrap over campaign medians; 10000 resamples",
            }
        )

    write_csv(
        args.output / "timings_summary.csv",
        list(aggregate_rows[0].keys()) if aggregate_rows else ["schema"],
        aggregate_rows,
    )

    order_rows = []
    pair_specs = [
        (1, "Setup", "Setup", "NA"),
        (2, "KeyGen", "KeyGen", "NA"),
        (3, "Delegate+TM_Delegate", "Delegate", "NA"),
        (14, "Encrypt", "Encrypt", "4"),
        (1048586, "Encrypt", "Encrypt", "1048576"),
        (24, "TM_Decrypt+Decrypt", "Decrypt", "4"),
        (1048596, "TM_Decrypt+Decrypt", "Decrypt", "1048576"),
    ]
    block_count = math.ceil(args.measurements / args.block_size)
    for record in campaign_records:
        campaign_id = int(record["campaign_id"])
        for pair_id, d3cs_operation, bsw_operation, message_size in pair_specs:
            for block_index, d3cs_first in enumerate(
                block_order(int(record["seed"]), pair_id, block_count), start=1
            ):
                order_rows.append(
                    {
                        "campaign_id": campaign_id,
                        "order_seed": record["seed"],
                        "pair_id": pair_id,
                        "d3cs_operation": d3cs_operation,
                        "bsw07_operation": bsw_operation,
                        "message_size_bytes": message_size,
                        "block_index": block_index,
                        "block_size": args.block_size,
                        "first_schema": "D3CS_PM23_LK10" if d3cs_first else "BSW07",
                    }
                )
    write_csv(args.output / "order_trace.csv", list(order_rows[0].keys()), order_rows)

    ratio_rows = []
    for (bsw_schema, bsw_operation), (d3cs_schema, d3cs_operation) in RATIO_PAIRS.items():
        sizes = sorted(
            {
                key[2]
                for key in grouped
                if key[0] == bsw_schema and key[1] == bsw_operation
            }
        )
        for message_size in sizes:
            ratios = []
            per_campaign = []
            for campaign_id in range(1, args.campaigns + 1):
                numerator = [
                    duration
                    for cid, duration in grouped[(bsw_schema, bsw_operation, message_size)]
                    if cid == campaign_id
                ]
                denominator = [
                    duration
                    for cid, duration in grouped[(d3cs_schema, d3cs_operation, message_size)]
                    if cid == campaign_id
                ]
                if numerator and denominator:
                    ratio = median(numerator) / median(denominator)
                    ratios.append(ratio)
                    per_campaign.append((campaign_id, ratio))
            ci_low, ci_high = bootstrap_ci(
                ratios,
                stable_seed(args.seed ^ len(ratios), message_size),
            )
            ratio_rows.append(
                {
                    "bsw07_operation": bsw_operation,
                    "d3cs_operation": d3cs_operation,
                    "message_size_bytes": message_size,
                    "campaign_count": len(ratios),
                    "median_of_campaign_ratios": f"{median(ratios):.6f}" if ratios else "",
                    "ci95_low": f"{ci_low:.6f}" if not math.isnan(ci_low) else "",
                    "ci95_high": f"{ci_high:.6f}" if not math.isnan(ci_high) else "",
                    "ci_method": "bootstrap over paired campaign ratios; 10000 resamples",
                    "ratios_by_campaign": ";".join(f"{cid}:{value:.6f}" for cid, value in per_campaign),
                }
            )
    write_csv(
        args.output / "performance_ratios.csv",
        list(ratio_rows[0].keys()) if ratio_rows else ["bsw07_operation"],
        ratio_rows,
    )

    size_fields = ["campaign_id"] + [field for field in size_rows[0] if field != "campaign_id"]
    write_csv(args.output / "sizes.csv", size_fields, size_rows)
    error_fields = ["campaign_id"] + [field for field in error_rows[0] if field != "campaign_id"] if error_rows else ["campaign_id", "schema", "operation", "message_size_bytes", "iteration", "phase", "error"]
    write_csv(args.output / "errors.csv", error_fields, error_rows)
    write_csv(args.output / "confidence_intervals.csv", list(confidence_rows[0].keys()), confidence_rows)

    first_metadata = child_metadata[0]
    metadata = {
        "benchmark": "Controlled independent comparison of D3CS PM23/LK10 and standalone BSW07",
        "campaign_count": args.campaigns,
        "warmups": args.warmups,
        "measurements_per_operation_per_campaign": args.measurements,
        "order_block_size": args.block_size,
        "base_order_seed": args.seed,
        "campaign_seeds": [record["seed"] for record in campaign_records],
        "independent_process_per_campaign": True,
        "order_strategy": "balanced reproducible short blocks; D3CS/BSW07 order shuffled per operation pair",
        "ci_method": "bootstrap over campaign medians and paired campaign ratios; 10000 resamples",
        "ci_warning": "five campaigns provide limited precision; iterations within a campaign are not treated as independent campaigns",
        "git_commit": first_metadata.get("git_commit", "unavailable"),
        "git_worktree_state": first_metadata.get("git_worktree_state", "unavailable"),
        "git_status_porcelain": first_metadata.get("git_status_porcelain", "unavailable"),
        "rustc": first_metadata.get("rustc", "unavailable"),
        "dependencies": first_metadata.get("dependencies", "unavailable"),
        "operating_system": platform.platform(),
        "kernel": command_output(["uname", "-a"]),
        "processor": first_metadata.get("processor", "unavailable"),
        "system_conditions_at_aggregation": system_conditions(),
        "python": platform.python_version(),
        "binary": str(args.binary),
        "source_campaign_metadata": child_metadata,
        "campaign_processes": campaign_records,
        "timestamp_unix_seconds": int(time.time()),
        "raw_sha256": hashlib.sha256((args.output / "timings_raw.csv").read_bytes()).hexdigest(),
        "note": "API-level comparison; validation and serialization per production API are intentionally retained and documented.",
    }
    (args.output / "metadata.json").write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    if error_rows:
        raise SystemExit(f"campaigns completed with {len(error_rows)} errors; see {args.output / 'errors.csv'}")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit("interrupted")
