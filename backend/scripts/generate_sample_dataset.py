#!/usr/bin/env python3
"""
Generate the bundled sample datasets.

Creates three files under backend/datasets:

* sample_network_traffic.csv   - 24h of labeled traffic (training + evaluation)
* sample_attack_burst.json     - CIC-style column names (schema-adaptation demo)
* sample_unlabeled_traffic.csv - unlabeled flows (detection-only demo)

Traffic is synthetic and defensive in purpose: it reproduces the *shape* of
benign enterprise traffic and of common attack patterns so the detection and
forecasting pipeline can be exercised without any real capture.

Usage:  python backend/scripts/generate_sample_dataset.py [--rows 6000]
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import random
import sys
from datetime import datetime, timedelta, timezone

BACKEND_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(BACKEND_ROOT, "datasets")
sys.path.insert(0, BACKEND_ROOT)

INTERNAL_HOSTS = [
    "10.20.1.15", "10.20.1.22", "10.20.1.37", "10.20.1.48", "10.20.2.11", "10.20.2.64",
    "10.20.3.9", "10.20.3.120", "10.20.4.5", "192.168.40.18", "192.168.40.77", "192.168.40.201",
]
SERVERS = {
    "web": ("10.20.10.5", [80, 443, 8080]),
    "dns": ("10.20.10.53", [53]),
    "ssh": ("10.20.10.22", [22]),
    "db": ("10.20.10.90", [3306, 5432]),
    "mail": ("10.20.10.25", [25, 587]),
}
EXTERNAL = [
    "203.0.113.14", "203.0.113.88", "198.51.100.23", "198.51.100.177", "192.0.2.45",
    "192.0.2.210", "185.220.101.7", "91.240.118.52", "45.33.32.101", "104.21.7.190",
    "142.250.190.46", "13.107.42.14", "151.101.65.140", "8.8.8.8", "1.1.1.1",
]
C2 = ["185.220.101.7", "91.240.118.52", "45.33.32.101"]
C2_PORTS = [4444, 6667, 9999, 1337]

CSV_COLUMNS = [
    "timestamp", "source_ip", "destination_ip", "source_port", "destination_port", "protocol",
    "packet_count", "byte_count", "packet_length", "flow_duration", "packets_per_second",
    "bytes_per_second", "connection_count", "tcp_flags", "failed_connections", "request_frequency",
    "attack_type",
]

MIX = [
    ("Benign", 0.70), ("DDoS", 0.075), ("DoS", 0.05), ("Port Scan", 0.06),
    ("Brute Force", 0.05), ("Bot Activity", 0.035), ("Intrusion", 0.02), ("Network Anomaly", 0.01),
]


def make_flow(rng: random.Random, attack: str, when: datetime) -> dict:
    if attack == "Benign":
        service = rng.choice(list(SERVERS.keys())) if rng.random() < 0.45 else "web"
        server_ip, ports = SERVERS[service]
        outbound = rng.random() < 0.5
        src = rng.choice(INTERNAL_HOSTS) if outbound else rng.choice(EXTERNAL)
        dst = rng.choice(EXTERNAL) if outbound else server_ip
        dst_port = rng.choice([443, 80, 53, 22, 8080, 3306]) if outbound else rng.choice(ports)
        protocol = rng.choice(["HTTPS", "HTTP", "DNS", "TCP", "UDP"])
        packets = max(1, int(rng.gauss(48, 32)))
        length = rng.randint(64, 1460)
        duration = round(max(0.02, rng.gauss(3.4, 2.6)), 3)
        flags = rng.choice(["ACK", "PSH-ACK", "SYN-ACK", "FIN-ACK"])
        failed = 1 if rng.random() < 0.05 else 0
        connections = max(1, int(rng.gauss(2, 1)))
    elif attack == "DDoS":
        src = f"{rng.randint(11, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        dst, dst_port = SERVERS["web"][0], rng.choice([80, 443, 53])
        protocol = rng.choice(["TCP", "TCP", "UDP", "ICMP"])
        packets = int(rng.uniform(6000, 42000))
        length = rng.choice([64, 96, 512, 1460])
        duration = round(rng.uniform(4.0, 26.0), 3)
        flags, failed, connections = "SYN", int(packets * rng.uniform(0.3, 0.7)), int(rng.uniform(40, 400))
    elif attack == "DoS":
        src, dst = rng.choice(EXTERNAL), SERVERS["web"][0]
        dst_port = rng.choice([80, 443, 8080])
        protocol, flags = "TCP", rng.choice(["SYN", "PSH-ACK"])
        packets = int(rng.uniform(1500, 7500))
        length = rng.randint(900, 1500)
        duration = round(rng.uniform(15.0, 85.0), 2)
        failed, connections = int(packets * rng.uniform(0.2, 0.5)), int(rng.uniform(5, 40))
    elif attack == "Port Scan":
        src = rng.choice(EXTERNAL[:9])
        dst = rng.choice([s[0] for s in SERVERS.values()] + INTERNAL_HOSTS)
        dst_port = rng.randint(20, 1024)
        protocol, flags = "TCP", rng.choice(["SYN", "XMAS", "NULL", "RST", "FIN"])
        packets = rng.randint(1, 3)
        length = rng.randint(40, 60)
        duration = round(rng.uniform(0.001, 0.03), 4)
        failed, connections = packets, 1
    elif attack == "Brute Force":
        src = rng.choice(EXTERNAL)
        dst = SERVERS["ssh"][0] if rng.random() < 0.7 else SERVERS["db"][0]
        dst_port = rng.choice([22, 3389, 3306, 21])
        protocol, flags = "TCP", "PSH-ACK"
        packets = int(rng.uniform(120, 720))
        length = rng.randint(120, 360)
        duration = round(rng.uniform(4.0, 42.0), 2)
        failed, connections = int(packets * rng.uniform(0.55, 0.95)), int(rng.uniform(20, 180))
    elif attack == "Bot Activity":
        src, dst = rng.choice(INTERNAL_HOSTS), rng.choice(C2)
        dst_port = rng.choice(C2_PORTS)
        protocol, flags = rng.choice(["TCP", "UDP"]), "ACK"
        packets = int(rng.uniform(20, 190))
        length = rng.randint(60, 400)
        duration = round(rng.uniform(30.0, 320.0), 2)
        failed, connections = 0, int(rng.uniform(1, 6))
    elif attack == "Intrusion":
        src, dst = rng.choice(INTERNAL_HOSTS), rng.choice(EXTERNAL)
        dst_port = rng.choice([443, 8443, 4444, 21])
        protocol, flags = rng.choice(["HTTPS", "TCP"]), "PSH-ACK"
        packets = int(rng.uniform(400, 4200))
        length = rng.randint(900, 1500)
        duration = round(rng.uniform(25.0, 240.0), 2)
        failed, connections = int(packets * rng.uniform(0.0, 0.1)), int(rng.uniform(1, 8))
    else:  # Network Anomaly
        src = rng.choice(EXTERNAL + INTERNAL_HOSTS)
        dst = rng.choice([s[0] for s in SERVERS.values()] + INTERNAL_HOSTS)
        dst_port = rng.choice([0, 7, 111, 135, 139, 161, 500, 1900, 3128, 5900, 7000, 9100])
        protocol = rng.choice(["ICMP", "UDP", "TCP", "ARP"])
        packets = int(rng.uniform(5, 900))
        length = rng.choice([0, 28, 64, 68, 1500])
        duration = round(rng.uniform(0.001, 12.0), 3)
        flags = rng.choice(["NULL", "XMAS", "URG", "RST", "FIN"])
        failed, connections = int(packets * rng.uniform(0.1, 0.6)), max(1, int(rng.uniform(1, 25)))

    packets = max(1, packets)
    byte_count = packets * length
    safe = max(duration, 0.001)
    return {
        "timestamp": when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "source_ip": src,
        "destination_ip": dst,
        "source_port": rng.randint(1024, 65535),
        "destination_port": dst_port,
        "protocol": protocol,
        "packet_count": packets,
        "byte_count": byte_count,
        "packet_length": round(byte_count / packets, 2),
        "flow_duration": duration,
        "packets_per_second": round(packets / safe, 2),
        "bytes_per_second": round(byte_count / safe, 2),
        "connection_count": connections,
        "tcp_flags": flags,
        "failed_connections": failed,
        "request_frequency": round(packets / safe / max(connections, 1), 2),
        "attack_type": attack,
    }


def add_ambiguity(rng: random.Random, flow: dict, attack: str) -> dict:
    """Inject realistic overlap between classes.

    A share of flows deliberately look like the *other* regime (heavy benign
    transfers, low-and-slow attacks). The label stays correct, which is what
    makes the resulting accuracy believable instead of artificially perfect.
    """
    if rng.random() > 0.24:
        return flow
    out = dict(flow)
    if attack == "Benign":
        factor = rng.uniform(3.0, 26.0)
        out["packet_count"] = int(out["packet_count"] * factor)
        out["byte_count"] = int(out["packet_count"] * out["packet_length"])
        out["connection_count"] = int(out["connection_count"] * rng.uniform(2, 12))
        out["failed_connections"] = int(out["packet_count"] * rng.uniform(0.02, 0.25))
        out["flow_duration"] = round(out["flow_duration"] * rng.uniform(0.3, 1.6), 3)
        if rng.random() < 0.5:
            out["tcp_flags"] = rng.choice(["SYN", "RST", "NULL"])
        if rng.random() < 0.4:
            out["destination_port"] = rng.choice([22, 3389, 8443, 5900, 4444])
        if rng.random() < 0.25:
            out["protocol"] = rng.choice(["ICMP", "UDP", "ARP"])
    else:
        shrink = rng.uniform(0.03, 0.5)
        out["packet_count"] = max(1, int(out["packet_count"] * shrink))
        out["byte_count"] = int(out["packet_count"] * out["packet_length"])
        out["failed_connections"] = int(out["failed_connections"] * shrink)
        out["connection_count"] = max(1, int(out["connection_count"] * shrink))
        out["flow_duration"] = round(out["flow_duration"] * rng.uniform(1.2, 9.0), 3)
        if rng.random() < 0.55:
            out["tcp_flags"] = rng.choice(["ACK", "PSH-ACK", "SYN-ACK"])
        if rng.random() < 0.45:
            out["destination_port"] = rng.choice([80, 443, 53, 8080])
        if rng.random() < 0.3:
            out["protocol"] = rng.choice(["HTTPS", "DNS", "HTTP"])
    safe = max(out["flow_duration"], 0.001)
    out["packets_per_second"] = round(out["packet_count"] / safe, 2)
    out["bytes_per_second"] = round(out["byte_count"] / safe, 2)
    out["packet_length"] = round(out["byte_count"] / max(out["packet_count"], 1), 2)
    out["request_frequency"] = round(out["packet_count"] / safe / max(out["connection_count"], 1), 2)
    return out


def pick(rng: random.Random, progress: float) -> str:
    """Time-varying mix so the dataset contains escalating campaigns."""
    weights = dict(MIX)
    if progress > 0.55:  # attack wave in the second half of the window
        for key in ("DDoS", "DoS", "Port Scan", "Brute Force"):
            weights[key] *= 1.9
        weights["Benign"] *= 0.72
    names = list(weights)
    total = sum(weights.values())
    return rng.choices(names, weights=[weights[n] / total for n in names], k=1)[0]


def write_csv(path: str, rows: list) -> None:
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate bundled sample datasets")
    parser.add_argument("--rows", type=int, default=6000, help="rows for the main CSV (default 6000)")
    parser.add_argument("--burst", type=int, default=220, help="rows for the JSON burst dataset")
    parser.add_argument("--unlabeled", type=int, default=400, help="rows for the unlabeled CSV")
    parser.add_argument("--seed", type=int, default=20260929)
    args = parser.parse_args()

    rng = random.Random(args.seed)
    os.makedirs(DATASET_DIR, exist_ok=True)
    now = datetime.now(timezone.utc)

    # 1. Main labeled dataset spread over the last 24 hours.
    rows = []
    for index in range(args.rows):
        progress = index / max(args.rows - 1, 1)
        when = now - timedelta(seconds=int((1 - progress) * 24 * 3600)) + timedelta(seconds=rng.uniform(0, 12))
        attack = pick(rng, progress)
        rows.append(add_ambiguity(rng, make_flow(rng, attack, when), attack))
    rows.sort(key=lambda r: r["timestamp"])
    main_path = os.path.join(DATASET_DIR, "sample_network_traffic.csv")
    write_csv(main_path, rows)

    # 2. JSON burst dataset using CIC-style column names (schema adaptation demo).
    burst = []
    for index in range(args.burst):
        progress = index / max(args.burst - 1, 1)
        when = now - timedelta(minutes=int((1 - progress) * 45))
        attack = "Benign" if rng.random() > (0.25 + 0.6 * progress) else rng.choice(["DDoS", "Port Scan", "Brute Force"])
        flow = add_ambiguity(rng, make_flow(rng, attack, when), attack)
        burst.append({
            "Flow ID": f"{flow['source_ip']}-{flow['destination_ip']}-{flow['destination_port']}",
            "Timestamp": flow["timestamp"],
            "Src IP": flow["source_ip"],
            "Dst IP": flow["destination_ip"],
            "Src Port": flow["source_port"],
            "Dst Port": flow["destination_port"],
            "Protocol": flow["protocol"],
            "Tot Fwd Pkts": flow["packet_count"],
            "Tot Fwd Bytes": flow["byte_count"],
            "Flow Duration (ms)": round(flow["flow_duration"] * 1000, 2),
            "Flow Packets/s": flow["packets_per_second"],
            "Flow Bytes/s": flow["bytes_per_second"],
            "Flag": flow["tcp_flags"],
            "Failed Connections": flow["failed_connections"],
            "Label": flow["attack_type"],
        })
    burst_path = os.path.join(DATASET_DIR, "sample_attack_burst.json")
    with open(burst_path, "w", encoding="utf-8") as handle:
        json.dump({"dataset": "CyberForecast AI - attack burst (CIC-style columns)", "records": burst}, handle, indent=1)

    # 3. Unlabeled detection dataset.
    unlabeled = []
    for index in range(args.unlabeled):
        progress = index / max(args.unlabeled - 1, 1)
        when = now - timedelta(minutes=int((1 - progress) * 120))
        attack = pick(rng, progress)
        flow = add_ambiguity(rng, make_flow(rng, attack, when), attack)
        flow.pop("attack_type")
        unlabeled.append(flow)
    unlabeled_path = os.path.join(DATASET_DIR, "sample_unlabeled_traffic.csv")
    with open(unlabeled_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=[c for c in CSV_COLUMNS if c != "attack_type"])
        writer.writeheader()
        writer.writerows(unlabeled)

    distribution: dict = {}
    for row in rows:
        distribution[row["attack_type"]] = distribution.get(row["attack_type"], 0) + 1

    print(f"Wrote {main_path} ({len(rows)} rows, {os.path.getsize(main_path) / 1024:.0f} KB)")
    print(f"Wrote {burst_path} ({len(burst)} records)")
    print(f"Wrote {unlabeled_path} ({len(unlabeled)} rows)")
    print("Label distribution:", json.dumps(distribution, indent=2))


if __name__ == "__main__":
    main()
