#!/usr/bin/env python3
"""Temporary LEPTON disconnection followed by CT_SHARE delivery.

This is deliberately an orchestration script, not a cryptographic benchmark.
The cryptographic and application operations remain those implemented by the
D3CS Rust binary; Python only controls LEPTON/DoDWAN and writes experiment
results.
"""

import argparse
import csv
import datetime as dt
import math
import os
import statistics
import time
from pathlib import Path

import multihop_latency as mh


MESSAGE_BYTES = 1024
SOURCE_NODE = "U1"
DESTINATION_NODE = "Authority"
WORKFLOW = "CT_SHARE"
RECONNECTION_SCHEDULE_MARGIN_SECONDS = 2.0


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


def monotonic_ns():
    return time.monotonic_ns()


def api_neighbors(api):
    data = api.get("/api/network/status").get("data") or {}
    return {item.get("name") for item in data.get("connected_nodes", [])}


def link_operational(source_api, destination_api):
    return (
        DESTINATION_NODE in api_neighbors(source_api)
        and SOURCE_NODE in api_neighbors(destination_api)
    )


def link_interrupted(source_api, destination_api):
    return (
        DESTINATION_NODE not in api_neighbors(source_api)
        and SOURCE_NODE not in api_neighbors(destination_api)
    )


def event_count(logs, event, run_id, node):
    count = 0
    for path in logs:
        if not path.exists():
            continue
        for line in path.read_text(errors="replace").splitlines():
            fields = mh.fields(line)
            if (
                fields.get("event") == event
                and fields.get("workflow") == WORKFLOW
                and fields.get("run_id") == str(run_id)
                and fields.get("node") == node
            ):
                count += 1
    return count


def lepton_edge_event(cluster, command, status, after_epoch_ns=0):
    """Return the latest structured LEPTON edge event after an instant."""
    path = cluster["run"] / "lepton" / "lepton.out"
    if not path.exists():
        return None
    marker = f"edge event {command} N00-N01 status={status}"
    found = None
    for line in path.read_text(errors="replace").splitlines():
        if marker not in line:
            continue
        try:
            event_time = dt.datetime.strptime(line[:23], "%Y-%m-%d %H:%M:%S.%f")
            local_zone = dt.datetime.now().astimezone().tzinfo
            event_time = event_time.replace(tzinfo=local_zone)
            epoch_ns = int(event_time.timestamp() * 1_000_000_000)
        except ValueError:
            continue
        if epoch_ns > after_epoch_ns:
            found = (
                epoch_ns,
                event_time.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds"),
            )
    return found


def document_paths(cluster, node, document_id):
    component = node.lower()
    root = cluster["run"] / "state" / node / "tm" / "nodes" / component
    return root / "ct" / f"{document_id}.ct", root / "signatures" / f"{document_id}.sign"


def received_successfully(cluster, document_id):
    event = receive_event(cluster, document_id)
    ct_path, sig_path = document_paths(cluster, DESTINATION_NODE, document_id)
    return event is not None and ct_path.exists() and sig_path.exists()


def receive_event(cluster, document_id):
    return mh.find_event(
        cluster["logs"], "receive", WORKFLOW, document_id, DESTINATION_NODE
    )


def payloads_match(cluster, document_id):
    source_ct, source_sig = document_paths(cluster, SOURCE_NODE, document_id)
    destination_ct, destination_sig = document_paths(
        cluster, DESTINATION_NODE, document_id
    )
    if not all(path.exists() for path in (source_ct, source_sig, destination_ct, destination_sig)):
        return False
    return source_ct.read_bytes() == destination_ct.read_bytes() and source_sig.read_bytes() == destination_sig.read_bytes()


def base_row(iteration):
    return {
        "iteration": iteration,
        "message_id": "",
        "outage_requested_s": "",
        "outage_effective_ms": "",
        "t_disconnect_utc": "",
        "t_emit_utc": "",
        "t_reconnect_command_utc": "",
        "reconnection_control": "LEPTON_DGS_EDGE_RECREATE",
        "t_reconnect_confirmed_utc": "",
        "t_connectivity_observed_utc": "",
        "t_receive_utc": "",
        "disconnect_monotonic_ns": "",
        "emit_monotonic_ns": "",
        "reconnect_command_monotonic_ns": "",
        "reconnect_confirmed_monotonic_ns": "",
        "receive_monotonic_ns": "",
        "delivery_ms": "",
        "status": "error",
        "error": "",
    }


def run_repetition(cluster, source_api, destination_api, iteration, outage_seconds, timeout_seconds):
    row = base_row(iteration)
    row["outage_requested_s"] = f"{outage_seconds:.6f}"
    document_id = None
    try:
        disconnect_wait_ns = monotonic_ns()
        mh.wait_for(
            lambda: link_interrupted(source_api, destination_api),
            90,
            "LEPTON scheduled disconnection",
        )
        disconnect_ns = monotonic_ns()
        disconnect_epoch_ns = time.time_ns()
        row["disconnect_monotonic_ns"] = disconnect_ns
        row["t_disconnect_utc"] = utc_now()

        # The API call is the real D3CS workflow. Its successful response means
        # encrypt_document completed and ask_for_sharing submitted CT_SHARE.
        emit_start_ns = monotonic_ns()
        row["emit_monotonic_ns"] = emit_start_ns
        row["t_emit_utc"] = utc_now()
        message = "D" * MESSAGE_BYTES
        response = source_api.request(
            "POST",
            "/api/encrypt",
            {"message": message, "classification": "FR-DR", "mission": "M1"},
        )
        document_id = int(response["data"]["id"])
        row["message_id"] = f"reconnection-{iteration:03d}-{document_id}"
        if event_count(cluster["logs"], "send", document_id, SOURCE_NODE) != 1:
            raise RuntimeError("CT_SHARE n'a pas ete emis exactement une fois")

        # LEPTON's structured EDGE_ADDED event is the reconnection reference.
        # DoDWAN neighbor visibility is checked separately below because it
        # can lag behind the topology event by one or more beacons.
        reconnect_event = mh.wait_for(
            lambda: lepton_edge_event(
                cluster, "ea", "CONNECTED", after_epoch_ns=disconnect_epoch_ns
            ),
            max(30, outage_seconds + timeout_seconds + 10),
            "LEPTON scheduled reconnection",
        )
        reconnect_confirmed_ns = monotonic_ns()
        row["reconnect_confirmed_monotonic_ns"] = reconnect_confirmed_ns
        row["t_reconnect_confirmed_utc"] = reconnect_event[1]
        row["outage_effective_ms"] = f"{(reconnect_confirmed_ns - disconnect_ns) / 1_000_000:.6f}"

        receive = receive_event(cluster, document_id)
        if receive is not None and int(receive["timestamp_ns"]) < reconnect_event[0]:
            row["status"] = "invalid"
            row["error"] = "CT_SHARE recu avant l'evenement LEPTON EDGE_ADDED"
            return row

        mh.wait_for(
            lambda: link_operational(source_api, destination_api),
            max(30, timeout_seconds),
            "connectivite DoDWAN apres reconnexion",
        )

        receive_deadline = time.monotonic() + timeout_seconds
        receive_ns = None
        while time.monotonic() < receive_deadline:
            if received_successfully(cluster, document_id):
                receive_ns = monotonic_ns()
                row["t_receive_utc"] = utc_now()
                row["receive_monotonic_ns"] = receive_ns
                break
            time.sleep(0.05)

        if receive_ns is None:
            row["status"] = "timeout"
            row["error"] = f"aucune reception valide dans {timeout_seconds:.3f} s"
            return row

        row["t_connectivity_observed_utc"] = utc_now()
        row["error"] = ""
        row["delivery_ms"] = f"{(receive_ns - reconnect_confirmed_ns) / 1_000_000:.6f}"
        if not payloads_match(cluster, document_id):
            row["status"] = "invalid"
            row["error"] = "payload CT_SHARE different entre source et destination"
            return row
        if event_count(cluster["logs"], "send", document_id, SOURCE_NODE) != 1:
            row["status"] = "invalid"
            row["error"] = "une seconde emission applicative a ete observee"
            return row
        row["status"] = "success"
        return row
    except Exception as exc:
        row["error"] = str(exc).replace("\n", " ")
        return row


def nearest_rank(values, percentile):
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, math.ceil(percentile * len(ordered)) - 1)
    return ordered[index]


def write_results(output, rows):
    output.mkdir(parents=True, exist_ok=True)
    raw_fields = list(rows[0].keys()) if rows else list(base_row(1).keys())
    raw_path = output / "reconnection_raw.csv"
    with raw_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=raw_fields)
        writer.writeheader()
        writer.writerows(rows)

    successful = [float(row["delivery_ms"]) for row in rows if row["status"] == "success"]
    failures = len(rows) - len(successful)
    summary_path = output / "reconnection_summary.csv"
    fields = [
        "metric", "n_total", "n_success", "n_failures", "mean_ms", "median_ms",
        "stddev_sample_ms", "min_ms", "max_ms", "p95_ms",
    ]
    with summary_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        if successful:
            writer.writerow({
                "metric": "delivery_after_reconnection",
                "n_total": len(rows),
                "n_success": len(successful),
                "n_failures": failures,
                "mean_ms": f"{statistics.mean(successful):.6f}",
                "median_ms": f"{statistics.median(successful):.6f}",
                "stddev_sample_ms": f"{statistics.stdev(successful) if len(successful) > 1 else 0.0:.6f}",
                "min_ms": f"{min(successful):.6f}",
                "max_ms": f"{max(successful):.6f}",
                "p95_ms": f"{nearest_rank(successful, 0.95):.6f}",
            })
        else:
            writer.writerow({
                "metric": "delivery_after_reconnection",
                "n_total": len(rows), "n_success": 0, "n_failures": failures,
                "mean_ms": "", "median_ms": "", "stddev_sample_ms": "",
                "min_ms": "", "max_ms": "", "p95_ms": "",
            })

    errors_path = output / "reconnection_errors.csv"
    with errors_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=["iteration", "message_id", "status", "error"])
        writer.writeheader()
        writer.writerows({key: row[key] for key in writer.fieldnames} for row in rows if row["status"] != "success")

    svg_path = output / "reconnection_delivery.svg"
    write_svg(svg_path, successful)
    return raw_path, summary_path, errors_path, svg_path


def write_svg(path, values):
    width, height = 900, 500
    left, right, top, bottom = 70, 30, 35, 55
    plot_w, plot_h = width - left - right, height - top - bottom
    median = statistics.median(values) if values else None
    ymax = max(values + [median or 1.0]) * 1.15 if values else 1.0
    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        '<text x="450" y="22" text-anchor="middle" font-family="sans-serif" font-size="16">CT_SHARE delivery after reconnection</text>',
        f'<line x1="{left}" y1="{top}" x2="{left}" y2="{height-bottom}" stroke="black"/>',
        f'<line x1="{left}" y1="{height-bottom}" x2="{width-right}" y2="{height-bottom}" stroke="black"/>',
        f'<text x="18" y="{top + plot_h/2}" transform="rotate(-90 18 {top + plot_h/2})" text-anchor="middle" font-family="sans-serif">delay (ms)</text>',
        f'<text x="{width/2}" y="{height-12}" text-anchor="middle" font-family="sans-serif">repetition</text>',
    ]
    if values:
        points = []
        for i, value in enumerate(values, start=1):
            x = left + (i - 1) * plot_w / max(1, len(values) - 1)
            y = top + plot_h * (1 - value / ymax)
            points.append((x, y))
            lines.append(f'<circle cx="{x:.2f}" cy="{y:.2f}" r="4" fill="#1f77b4"/>')
            lines.append(f'<text x="{x:.2f}" y="{height-bottom+18}" text-anchor="middle" font-family="sans-serif" font-size="10">{i}</text>')
        if len(points) > 1:
            lines.append('<polyline points="' + " ".join(f"{x:.2f},{y:.2f}" for x, y in points) + '" fill="none" stroke="#1f77b4"/>')
        median_y = top + plot_h * (1 - median / ymax)
        lines.append(f'<line x1="{left}" y1="{median_y:.2f}" x2="{width-right}" y2="{median_y:.2f}" stroke="#d62728" stroke-dasharray="6,4"/>')
        lines.append(f'<text x="{width-right-4}" y="{median_y-5:.2f}" text-anchor="end" font-family="sans-serif" font-size="11" fill="#d62728">median={median:.3f} ms</text>')
    else:
        lines.append(f'<text x="{width/2}" y="{height/2}" text-anchor="middle" font-family="sans-serif">no successful observations</text>')
    lines.append('</svg>')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--short", action="store_true", help="one repetition, one second outage, ten second timeout")
    parser.add_argument("--repetitions", type=int)
    parser.add_argument("--outage-seconds", type=float)
    parser.add_argument("--timeout-seconds", type=float)
    parser.add_argument("--output", type=Path, default=Path("benchmark_results/reconnection_latency"))
    args = parser.parse_args(argv)
    defaults = (1, 1.0, 10.0) if args.short else (10, 30.0, 60.0)
    args.repetitions = defaults[0] if args.repetitions is None else args.repetitions
    args.outage_seconds = defaults[1] if args.outage_seconds is None else args.outage_seconds
    args.timeout_seconds = defaults[2] if args.timeout_seconds is None else args.timeout_seconds
    if args.repetitions < 1 or args.outage_seconds < 0 or args.timeout_seconds <= 0:
        parser.error("repetitions >= 1, outage-seconds >= 0 and timeout-seconds > 0 are required")
    return args


def main(argv=None):
    args = parse_args(argv)
    base = Path(os.environ.get("D3CS_BASE_DIR", Path.cwd())).resolve()
    output = (base / args.output).resolve() if not args.output.is_absolute() else args.output.resolve()
    campaign = output / f"run-{int(time.time())}"
    cluster = None
    rows = []
    try:
        print("démarrage du cluster LEPTON/DoDWAN à deux nœuds")
        event_spacing_ms = int(
            (args.outage_seconds + RECONNECTION_SCHEDULE_MARGIN_SECONDS + 5.0)
            * 1000
        )
        edge_events = []
        # Leave enough time for process startup and the initial KEY_REQUEST /
        # KEY_RESPONSE exchange, while staying below run_repetition's 90 s
        # scheduled-disconnection wait.
        first_event_ms = 20000
        for index in range(args.repetitions):
            disconnect_at = first_event_ms + index * event_spacing_ms
            reconnect_after_ms = int(
                (args.outage_seconds + RECONNECTION_SCHEDULE_MARGIN_SECONDS) * 1000
            )
            edge_events.extend(
                [(disconnect_at, "DISCONNECTED"),
                 (disconnect_at + reconnect_after_ms, "CONNECTED")]
            )
        cluster = mh.start(base, 1, campaign, edge_events=edge_events)
        source_api = mh.Api(18081)
        destination_api = mh.Api(18080)
        login = "reconnection_u1"
        source_api.signup(login)
        mh.key_latency(cluster["logs"], login, SOURCE_NODE, 120)
        mh.wait_for(lambda: mh.ready(source_api), 120, "clés D3CS U1")
        mh.wait_for(lambda: link_operational(source_api, destination_api), 30, "liaison initiale")
        for iteration in range(1, args.repetitions + 1):
            print(f"répétition {iteration}/{args.repetitions}")
            row = run_repetition(
                cluster, source_api, destination_api, iteration,
                args.outage_seconds, args.timeout_seconds,
            )
            rows.append(row)
            print(f"  {row['status']}: {row['message_id'] or row['error']}")
    finally:
        if cluster:
            mh.stop(cluster)
    paths = write_results(output, rows)
    for path in paths:
        print(path)
    return 0 if rows and all(row["status"] == "success" for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
