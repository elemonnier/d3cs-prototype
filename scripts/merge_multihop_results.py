#!/usr/bin/env python3
import argparse
import csv
import statistics
from pathlib import Path


RAW_FIELDS = ["workflow", "hops", "iteration", "run_id",
              "source_node", "destination_node", "latency_ms", "success"]
SUMMARY_FIELDS = ["workflow", "hops", "n_total", "n_success",
                  "delivery_rate_percent", "mean_ms", "stddev_ms",
                  "median_ms", "min_ms", "max_ms"]
TOPOLOGY_FIELDS = ["hops", "node_id", "x_m", "expected_neighbors",
                   "observed_neighbors", "validated"]


def read_csv(path):
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def validate_raw(rows, allowed_hops, label):
    if any(int(row["hops"]) not in allowed_hops for row in rows):
        raise RuntimeError(f"{label}: configuration inattendue")
    ids = [row["run_id"] for row in rows]
    if len(ids) != len(set(ids)):
        raise RuntimeError(f"{label}: run_id dupliqué")
    groups = {}
    for row in rows:
        key = (row["workflow"], int(row["hops"]))
        groups.setdefault(key, []).append(row)
        if row["success"] not in ("true", "false"):
            raise RuntimeError(f"{label}: valeur success invalide")
    return groups


def write_raw(path, rows):
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=RAW_FIELDS)
        writer.writeheader()
        writer.writerows({key: row[key] for key in RAW_FIELDS} for row in rows)


def write_summary(path, rows):
    groups = {}
    for row in rows:
        key = (row["workflow"], int(row["hops"]))
        groups.setdefault(key, []).append(row)
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(SUMMARY_FIELDS)
        for (workflow, hops), group in sorted(groups.items(), key=lambda item: (item[0][1], item[0][0])):
            good = [float(row["latency_ms"]) for row in group
                    if row["success"] == "true" and row["latency_ms"] not in ("", "NA")]
            if len(good) != sum(row["success"] == "true" for row in group):
                raise RuntimeError(f"latence manquante pour {workflow}, h={hops}")
            stats = (statistics.mean(good),
                     statistics.stdev(good) if len(good) > 1 else 0.0,
                     statistics.median(good), min(good), max(good)) if good else (0, 0, 0, 0, 0)
            writer.writerow([workflow, hops, len(group), len(good),
                             f"{100 * len(good) / len(group):.3f}",
                             *(f"{value:.6f}" for value in stats)])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--existing", type=Path, required=True)
    parser.add_argument("--additional", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    base_rows = read_csv(args.existing / "multihop_latency_raw.csv")
    extra_rows = read_csv(args.additional / "multihop_latency_raw.csv")
    validate_raw(base_rows, {1, 2, 3, 4, 5}, "base")
    validate_raw(extra_rows, {10}, "10 sauts")
    rows = base_rows + extra_rows
    groups = validate_raw(rows, {1, 2, 3, 4, 5, 10}, "global")
    expected = {(workflow, hops) for workflow in
                ("CT_SHARE", "ARL_UPDATE", "KEY_REQUEST_RESPONSE")
                for hops in (1, 2, 3, 4, 5, 10)}
    if set(groups) != expected or any(len(group) != 30 for group in groups.values()):
        raise RuntimeError("groupes globaux incomplets ou non conformes")

    topology = read_csv(args.existing / "multihop_topology.csv")
    topology += read_csv(args.additional / "multihop_topology.csv")
    if any(int(row["hops"]) not in {1, 2, 3, 4, 5, 10} for row in topology):
        raise RuntimeError("topologie globale contenant une configuration interdite")

    args.output.mkdir(parents=True, exist_ok=True)
    write_raw(args.output / "multihop_latency_raw.csv", rows)
    write_summary(args.output / "multihop_latency_summary.csv", rows)
    with (args.output / "multihop_topology.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=TOPOLOGY_FIELDS)
        writer.writeheader()
        writer.writerows(topology)


if __name__ == "__main__":
    main()
