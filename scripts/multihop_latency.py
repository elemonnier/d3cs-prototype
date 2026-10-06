#!/usr/bin/env python3
import csv
import json
import os
import socket
import signal
import shutil
import statistics
import subprocess
import sys
import time
import traceback
from http.client import HTTPConnection
from pathlib import Path

HOPS = (1, 2, 3, 4, 5, 10, 20)


def wait_for(fn, timeout, name):
    end = time.monotonic() + timeout
    last = None
    while time.monotonic() < end:
        try:
            value = fn()
            if value:
                return value
        except Exception as exc:
            last = exc
        time.sleep(0.2)
    raise RuntimeError(f"timeout {name}: {last}" if last else f"timeout {name}")



def terminate_matching(pattern, timeout=15):
    """Kill residual LEPTON/DoDWAN processes without touching the runner ancestors."""
    protected = {os.getpid()}
    current = os.getpid()
    while current > 1:
        result = subprocess.run(["ps", "-o", "ppid=", "-p", str(current)],
                                capture_output=True, text=True)
        try:
            parent = int(result.stdout.strip())
        except ValueError:
            break
        protected.add(parent)
        current = parent
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = subprocess.run(["ps", "-eo", "pid=,args="],
                                capture_output=True, text=True)
        pids = []
        for line in result.stdout.splitlines():
            parts = line.strip().split(None, 1)
            if len(parts) != 2 or pattern not in parts[1]:
                continue
            try:
                pid = int(parts[0])
            except ValueError:
                continue
            if pid not in protected:
                pids.append(pid)
        for pid in pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
        if not pids:
            return
        time.sleep(0.2)
    result = subprocess.run(["ps", "-eo", "pid=,args="],
                            capture_output=True, text=True)
    remaining = []
    for line in result.stdout.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) != 2 or pattern not in parts[1]:
            continue
        try:
            pid = int(parts[0])
        except ValueError:
            continue
        if pid not in protected:
            remaining.append(str(pid))
    if remaining:
        raise RuntimeError(f"leftover processes for {pattern}: {' '.join(remaining)}")


class Api:
    def __init__(self, port):
        self.port, self.cookie = port, None

    def request(self, method, path, data=None):
        body = json.dumps(data).encode() if data is not None else b""
        headers = {"Host": "127.0.0.1", "Connection": "close",
                   "Content-Type": "application/json",
                   "Content-Length": str(len(body))}
        if self.cookie:
            headers["Cookie"] = self.cookie
        c = HTTPConnection("127.0.0.1", self.port, timeout=30)
        c.request(method, path, body=body, headers=headers)
        r, raw = c.getresponse(), None
        raw = r.read()
        cookie = r.getheader("Set-Cookie")
        if cookie:
            self.cookie = cookie.split(";", 1)[0]
        status = r.status
        c.close()
        value = json.loads(raw.decode())
        if status != 200 or value.get("ok") is False:
            raise RuntimeError(f"{method} {path} status={status}: {value}")
        return value

    def get(self, path):
        return self.request("GET", path)

    def signup(self, login):
        return self.request("POST", "/api/signup", {
            "login": login, "password": "bench",
            "clearance": {"classification": "FR-DR", "mission": "M1"}})

    def encrypt(self):
        return self.request("POST", "/api/encrypt", {
            "message": "test", "classification": "FR-DR", "mission": "M1"})

    def revoke(self):
        return self.request("POST", "/api/revoke", {"missions": ["BENCH_ARL"]})

    def unrevoke(self):
        return self.request("POST", "/api/unrevoke", {"missions": ["BENCH_ARL"]})


def port_file(node):
    user = os.environ.get("USER") or os.environ.get("USERNAME") or "etienne"
    return Path(f"/run/shm/{user}/dodwan/var/node/{node}/ports")


def dodwan_port(node):
    path = port_file(node)

    def probe():
        if path.exists():
            for line in path.read_text(errors="replace").splitlines():
                if line.startswith("dodwan_napi_ws.port="):
                    p = int(line.split("=", 1)[1])
                    with socket.create_connection(("127.0.0.1", p), 1):
                        return p
        return None

    return wait_for(probe, 45, f"DoDWAN {node}")


def make_config(run, base, hops):
    lepton = run / "lepton"
    lepton.mkdir(parents=True, exist_ok=True)
    node_count = hops + 1
    profiles = []
    for i in range(node_count):
        prefix = "Authority" if i == 0 else f"U{i}"
        profiles.append(
            f"[n{i:02d}]\nprefix={prefix}\nmobile=false\n"
            f"coord=car:{i*50},0\nseed={200001+i}\n")
    profile = run / "node_profiles.txt"
    profile.write_text("\n".join(profiles), encoding="utf-8")

    labels = run / "node_labels.txt"
    labels.write_text("\n".join(
        f"N{i:02d}={'Authority' if i == 0 else f'U{i}'}"
        for i in range(node_count)
    ) + "\n", encoding="utf-8")

    chain_dgs = run / "chain.dgs"
    dgs = ["DGS004", "SIMUL 0 0", "st 0"]
    for i in range(node_count):
        label = "Authority" if i == 0 else f"U{i}"
        dgs.append(f"an N{i:02d} x={i*50} y=0 label=\"{label}\"")
    for i in range(hops):
        dgs.append(f"ae N{i:02d}-N{i+1:02d} N{i:02d} N{i+1:02d}")
    for i in range(hops):
        dgs.append(f"ce N{i:02d}-N{i+1:02d} status=\"CONNECTED\"")
    chain_dgs.write_text("\n".join(dgs) + "\n", encoding="utf-8")

    node_hist = run / "nodes.hist"
    node_hist.write_text(
        "# start end duration node_id\n" +
        "".join(f"0 -1 -1 N{i:02d}\n" for i in range(node_count)),
        encoding="utf-8")
    area_max = hops * 50 + 50
    config = run / "lepton.conf"
    config.write_text(
        f"log_dir={lepton}\nlepton_host=localhost\njitter=0\ntime_margin=0\n"
        f"nodes_deferred=0\naccel=1\nsimul_area=car:-20,-20,{area_max},40\n"
        f"edge_default_status=DISCONNECTED\nnode_default_status=NONE\nrange=60\n"
        f"lepton_console_port=5100\nin_dgs={chain_dgs}\nin_hist={node_hist}\n"
        f"make_edges=false\nnodes=0\nperiod=1.0\n"
        f"duration=-1\nout_dgs={lepton/'lepton.dgs'}\n"
        f"nodes_profiles={profile}\nnode_labels={labels}\n", encoding="utf-8")
    return config, lepton, node_count

def spawn_app(base, node, port, net_node, ws, run):
    exe = base / "target/release/d3cs-prototype"
    if not exe.exists():
        raise RuntimeError(f"{exe} absent ; lancer cargo build --release --bins")
    state = run/"state"/node
    users, tm, auth = state/"users", state/"tm", state/"authority"
    net = run/"network"/node.lower()
    for p in (users, tm, auth, net):
        p.mkdir(parents=True, exist_ok=True)
    log, events = run/f"{node}.d3cs.log", run/f"{node}.events.log"
    events.write_text("", encoding="utf-8")
    env = os.environ.copy()
    env.update({
        "D3CS_HOST": "127.0.0.1", "D3CS_PORT": str(port),
        "D3CS_NODE_ID": node, "D3CS_BASE_DIR": str(base),
        "D3CS_DODWAN_NODE_ID": net_node, "D3CS_DODWAN_WS_PORT": str(ws),
        "D3CS_DODWAN_EXTERNAL": "1", "D3CS_CONFIG_DIR": str(base/"src/config"),
        "D3CS_USERS_DIR": str(users), "D3CS_TM_DIR": str(tm),
        "D3CS_AUTHORITY_DIR": str(auth), "D3CS_IHM_DIR": str(base/"src/ihm"),
        "D3CS_NETWORK_DIR": str(net), "D3CS_LOG_FILE": str(log),
        "D3CS_BENCHMARK_EVENT_LOG": str(events), "D3CS_QUIET_STARTUP": "1"})
    fp = log.open("w", encoding="utf-8")
    child = subprocess.Popen([str(exe), "network", node], cwd=base, env=env,
                             stdout=fp, stderr=subprocess.STDOUT)
    return child, events


def start(base, hops, run):
    run.mkdir(parents=True, exist_ok=True)
    lepton_home, dodwan = base/"src/network/tools/lepton", base/"src/network/tools/dodwan"
    config, lepton_log_dir, node_count = make_config(run, base, hops)
    adapter = base/"src/network/tools/dodwan-adapter/bin/multihop_adapter.sh"
    env = os.environ.copy()
    env.update({"DODWAN_HOME": str(dodwan),
                "DODWAN_ADAPTER_HOME": str(base/"src/network/tools/dodwan-adapter"),
                "dodwan_plugins": "dodwan-napi,dodwan-napi-ws",
                "jvm_opts": "-Ddodwan_napi_ws.port=0 -Ddodwan_napi_ws.serial_method=json"})
    node_ids = [f"N{i:02d}" for i in range(node_count)]
    for node_id in node_ids:
        node_env = {**os.environ, "DODWAN_HOME": str(dodwan),
                    "DODWAN_ADAPTER_HOME": str(base/"src/network/tools/dodwan-adapter"),
                    "node_id": node_id}
        # Stop first so stale PID files cannot prevent native cache clearing.
        subprocess.run([str(dodwan/"bin/dodwan.sh"), "stop"], cwd=dodwan,
                       env=node_env, timeout=10, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        subprocess.run([str(dodwan/"bin/dodwan.sh"), "clear"], cwd=dodwan,
                       env=node_env, timeout=10, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        # DoDWAN's native clear flushes cache/* but keeps the persistent
        # reception history. Remove only that state between isolated runs;
        # duplicate suppression remains enabled throughout each experiment.
        user = os.environ.get("USER") or os.environ.get("USERNAME") or "etienne"
        node_dir = Path(f"/run/shm/{user}/dodwan/var/node/{node_id}")
        for stale in (node_dir / "pubsub" / "history",
                      node_dir / "pubsub" / "history.bak"):
            if stale.is_dir():
                shutil.rmtree(stale)
            elif stale.exists():
                stale.unlink()
        queue = node_dir / "queue"
        if queue.is_dir():
            for entry in queue.iterdir():
                if entry.is_dir():
                    shutil.rmtree(entry)
                else:
                    entry.unlink()
    launch_log = (run/"lepton.launch.log").open("w", encoding="utf-8")
    lepton = subprocess.Popen(
        [str(lepton_home/"bin/lepton.sh"), "start", f"conf={config}",
         f"oppnet_adapter={adapter}"], cwd=lepton_home, env=env,
        stdout=launch_log, stderr=subprocess.STDOUT, start_new_session=True)
    apps = []
    try:
        ports = {node: dodwan_port(node) for node in node_ids}
        logs = []
        for i, node_id in enumerate(node_ids):
            node = "Authority" if i == 0 else f"U{i}"
            child, events = spawn_app(base, node, 18080+i, node_id,
                                      ports[node_id], run)
            apps.append(child)
            logs.append(events)
        wait_for(lambda: socket.create_connection(("127.0.0.1", 18080), 1), 30,
                 "HTTP Authority")
        wait_for(lambda: socket.create_connection(("127.0.0.1", 18080+hops), 1), 30,
                 "HTTP subject")
        # Wait for LEPTON to advertise every expected adjacent relationship.
        # This is readiness only and remains outside all workflow timings.
        wait_for(lambda: lepton_chain_ready(lepton_log_dir / "lepton.out", hops),
                 max(60, hops * 8), f"LEPTON chain h={hops}")
        time.sleep(5)
        return {"lepton": lepton, "apps": apps, "lepton_home": lepton_home,
                "dodwan": dodwan, "config": config, "nodes": node_ids,
                "logs": logs, "run": run}
    except Exception:
        stop({"lepton": lepton, "apps": apps, "lepton_home": lepton_home,
              "dodwan": dodwan, "config": config, "nodes": node_ids,
              "run": run})
        raise


def stop(cluster):
    for child in cluster.get("apps", []):
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
    # Stop only the LEPTON daemon belonging to this run.
    pid_file = cluster["run"]/"lepton"/"lepton-pid"
    if pid_file.exists():
        try:
            pid = int(pid_file.read_text().strip())
            probe = subprocess.run(["ps", "-p", str(pid), "-o", "args="],
                                   capture_output=True, text=True)
            if "casa.lepton.leptond" in probe.stdout:
                os.kill(pid, signal.SIGKILL)
        except (OSError, ValueError):
            pass
        try:
            pid_file.unlink()
        except FileNotFoundError:
            pass
    if cluster.get("lepton") and cluster["lepton"].poll() is None:
        cluster["lepton"].terminate()
        try:
            cluster["lepton"].wait(5)
        except subprocess.TimeoutExpired:
            cluster["lepton"].kill()
            cluster["lepton"].wait()
    terminate_matching("casa.lepton.leptond")
    for node_id in cluster.get("nodes", []):
        try:
            subprocess.run([str(cluster["dodwan"]/"bin/dodwan.sh"), "stop"],
                           cwd=cluster["dodwan"],
                           env={**os.environ, "DODWAN_HOME": str(cluster["dodwan"]),
                                "DODWAN_ADAPTER_HOME": str(cluster["lepton_home"].parent / "dodwan-adapter"),
                                "node_id": node_id}, timeout=10,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
    terminate_matching("casa.dodwan.run.dodwand")

def fields(line):
    return dict(x.split("=", 1) for x in line.split() if "=" in x)


def lepton_neighbors(log_path):
    observed = {}
    if not log_path.exists():
        return observed
    for line in log_path.read_text(errors="replace").splitlines():
        marker = "hub hub:   > sdr="
        if marker not in line:
            continue
        value = line.split(marker, 1)[1].strip()
        if ",rcv=" not in value:
            continue
        node, neighbors = value.split(",rcv=", 1)
        observed[node] = set(x for x in neighbors.split(",") if x)
    return observed


def expected_chain_neighbors(hops):
    return {
        f"N{i:02d}": set(
            ([f"N{i-1:02d}"] if i else [])
            + ([f"N{i+1:02d}"] if i < hops else [])
        )
        for i in range(hops + 1)
    }


def lepton_chain_ready(log_path, hops):
    expected = expected_chain_neighbors(hops)
    observed = lepton_neighbors(log_path)
    return all(observed.get(node) == neighbors for node, neighbors in expected.items())


def find_event(logs, event, workflow, run_id, node=None):
    for path in logs:
        if path.exists():
            for line in reversed(path.read_text(errors="replace").splitlines()):
                f = fields(line)
                if (f.get("event") == event and f.get("workflow") == workflow
                        and f.get("run_id") == str(run_id)
                        and (node is None or f.get("node") == node)):
                    return f
    return None


def pair(logs, workflow, run_id, source_node, destination_node, timeout=90):
    def probe():
        send = find_event(logs, "send", workflow, run_id, source_node)
        recv = find_event(logs, "receive", workflow, run_id, destination_node)
        if send and recv:
            value = (int(recv["timestamp_ns"]) - int(send["timestamp_ns"])) / 1_000_000
            if value >= 0:
                return value
        return None
    return wait_for(probe, timeout, f"{workflow} {run_id}")


def key_latency(logs, login, node, timeout=120):
    def probe():
        event = find_event(logs, "key_latency", "KEY_REQUEST_RESPONSE", login, node)
        return float(event["duration_ns"]) / 1_000_000 if event else None
    return wait_for(probe, timeout, f"KEY_REQUEST_RESPONSE {login}")


def add(raw, workflow, hops, iteration, run_id, source, destination, value):
    raw.append({"workflow": workflow, "hops": hops, "iteration": iteration,
                "run_id": run_id, "source_node": source,
                "destination_node": destination,
                "latency_ms": "" if value is None else f"{value:.6f}",
                "success": "true" if value is not None else "false",
                "_value": value})


def measure(raw, workflow, hops, iteration, run_id, source, destination, action):
    try:
        add(raw, workflow, hops, iteration, run_id, source, destination, action())
    except Exception as exc:
        print(f"�chec {workflow} h={hops} i={iteration}: {exc}", file=sys.stderr)
        add(raw, workflow, hops, iteration, run_id, source, destination, None)


def ready(subject):
    data = subject.get("/api/network/status").get("data", {})
    return data.get("has_user_secret_key") and data.get("has_tm_delegate_key")


def run_hop(hops, warmups, measurements, cluster, raw):
    subject, authority, logs = Api(18080+hops), Api(18080), cluster["logs"]
    setup = f"bench_h{hops}_setup"
    preparation_timeout = max(90, hops * 15)
    subject.signup(setup)
    wait_for(lambda: key_latency(logs, setup, f"U{hops}", 1),
             preparation_timeout, "clé setup")
    wait_for(lambda: ready(subject), preparation_timeout, "clés sujet")

    for i in range(1, warmups+1):
        doc = str(subject.encrypt()["data"]["id"])
        pair(logs, "CT_SHARE", doc, f"U{hops}", "Authority")
    for i in range(1, measurements+1):
        def ct():
            doc = str(subject.encrypt()["data"]["id"])
            return pair(logs, "CT_SHARE", doc, f"U{hops}", "Authority")
        measure(raw, "CT_SHARE", hops, i, f"CT_SHARE_h{hops}_{i:03d}",
                f"U{hops}", "Authority", ct)

    def unrev():
        version = str(authority.unrevoke()["data"]["version"])
        pair(logs, "ARL_UPDATE", version, "Authority", f"U{hops}")

    for i in range(1, warmups+1):
        version = str(authority.revoke()["data"]["version"])
        pair(logs, "ARL_UPDATE", version, "Authority", f"U{hops}")
        unrev()
    for i in range(1, measurements+1):
        run_id = f"ARL_UPDATE_h{hops}_{i:03d}"
        try:
            version = str(authority.revoke()["data"]["version"])
            value = pair(logs, "ARL_UPDATE", version, "Authority", f"U{hops}")
            add(raw, "ARL_UPDATE", hops, i, run_id, "Authority", f"U{hops}", value)
        except Exception as exc:
            print(f"�chec ARL_UPDATE h={hops} i={i}: {exc}", file=sys.stderr)
            add(raw, "ARL_UPDATE", hops, i, run_id, "Authority", f"U{hops}", None)
        finally:
            try:
                unrev()
            except Exception as exc:
                print(f"nettoyage ARL impossible h={hops}: {exc}", file=sys.stderr)

    for i in range(1, warmups+1):
        login = f"bench_h{hops}_key_w{i}"
        subject.signup(login)
        key_latency(logs, login, f"U{hops}")
    for i in range(1, measurements+1):
        login = f"bench_h{hops}_key_{i:03d}"
        measure(raw, "KEY_REQUEST_RESPONSE", hops, i, login, f"U{hops}", "Authority",
                lambda login=login: (subject.signup(login), key_latency(logs, login, f"U{hops}"))[1])


def topology(hops, cluster):
    authority, subject = Api(18080), Api(18080+hops)
    observed = lepton_neighbors(cluster["run"] / "lepton" / "lepton.out")
    rows = []
    node_count = hops + 1
    for i in range(node_count):
        expected = ([f"N{i-1:02d}"] if i else []) + ([f"N{i+1:02d}"] if i < hops else [])
        actual = sorted(observed.get(f"N{i:02d}", set()))
        expected_sorted = sorted(expected)
        rows.append({"hops": hops, "node_id": f"N{i:02d}", "x_m": i*50,
                     "expected_neighbors": ";".join(expected),
                     "observed_neighbors": ";".join(actual),
                     "validated": str(actual == expected_sorted).lower()})
    return rows

def write_csv(output, raw, topo):
    output.mkdir(parents=True, exist_ok=True)
    with (output/"multihop_latency_raw.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["workflow","hops","iteration","run_id",
            "source_node","destination_node","latency_ms","success"])
        writer.writeheader()
        writer.writerows({k: v for k, v in row.items() if k != "_value"} for row in raw)
    groups = {}
    for row in raw:
        groups.setdefault((row["workflow"], row["hops"]), []).append(row["_value"])
    with (output/"multihop_latency_summary.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["workflow","hops","n_total","n_success","delivery_rate_percent",
                         "mean_ms","stddev_ms","median_ms","min_ms","max_ms"])
        for (workflow, hops), values in sorted(groups.items()):
            good = [x for x in values if x is not None]
            stats = (statistics.mean(good), statistics.stdev(good) if len(good)>1 else 0,
                     statistics.median(good), min(good), max(good)) if good else (0,0,0,0,0)
            rate = 100*len(good)/len(values) if values else 0
            writer.writerow([workflow,hops,len(values),len(good),f"{rate:.3f}",
                             *(f"{x:.6f}" for x in stats)])
    with (output/"multihop_topology.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["hops","node_id","x_m",
            "expected_neighbors","observed_neighbors","validated"])
        writer.writeheader()
        writer.writerows(topo)


def main():
    warmups, measurements, hops, output = 5, 30, [10, 20], Path("benchmark_results/multihop_extended")
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--short":
            warmups, measurements = 1, 2
        elif args[i] in ("--warmups","--measurements","--hops","--output"):
            option = args[i]
            i += 1
            if i >= len(args):
                raise RuntimeError(f"{option} attend une valeur")
            value = args[i]
            if option == "--warmups": warmups = int(value)
            elif option == "--measurements": measurements = int(value)
            elif option == "--hops":
                hops = [int(x) for x in value.split(",")]
                if any(x not in HOPS for x in hops):
                    raise RuntimeError("les sauts autoris�s sont 1, 2, 3, 4, 5, 10 et 20")
            else: output = Path(value)
        elif args[i] in ("-h","--help"):
            print("python3 scripts/multihop_latency.py [--short] [--warmups N] [--measurements N] [--hops 1,2,3,4,5,10,20]")
            return
        else:
            raise RuntimeError(f"option inconnue: {args[i]}")
        i += 1
    base = Path(os.environ.get("D3CS_BASE_DIR", Path.cwd())).resolve()
    output = (base/output).resolve() if not output.is_absolute() else output.resolve()
    campaign = output/f"run-{int(time.time())}"
    raw, topo = [], []
    for h in hops:
        cluster = None
        try:
            print(f"d�marrage cha�ne h={h}")
            cluster = start(base, h, campaign/f"hops-{h}")
            topo.extend(topology(h, cluster))
            run_hop(h, warmups, measurements, cluster, raw)
        finally:
            if cluster:
                stop(cluster)
    write_csv(output, raw, topo)
    print(output/"multihop_latency_raw.csv")
    print(output/"multihop_latency_summary.csv")
    print(output/"multihop_topology.csv")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception as exc:
        print(f"campagne interrompue: {exc}", file=sys.stderr)
        traceback.print_exc()
        raise SystemExit(1)
