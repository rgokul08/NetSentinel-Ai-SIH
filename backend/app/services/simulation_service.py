"""
Cybersecurity simulation engine (clearly labelled synthetic traffic).

Generates realistic network flows - benign traffic plus attack campaigns - and
pushes them through exactly the same analysis pipeline used for uploaded
datasets: preprocessing -> ML inference -> risk scoring -> alerts -> ledger.

Nothing here is presented as live capture: every record is tagged
source='simulation', is_simulated=True and surfaced in the UI as Simulation Mode.
"""

from __future__ import annotations

import logging
import random
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import pandas as pd

from app.core.config import settings
from app.core.utils import iso, utcnow
from app.services.realtime import hub

logger = logging.getLogger("cyberforecast.simulation")

SCENARIOS = {
    "mixed": {
        "label": "Mixed campaign (recommended demo)",
        "description": "Benign baseline with reconnaissance, credential attacks and a volumetric flood that ramps up.",
        "phases": [
            {"until": 0.18, "weights": {"Benign": 0.97, "Port Scan": 0.02, "Network Anomaly": 0.01}},
            {"until": 0.38, "weights": {"Benign": 0.88, "Port Scan": 0.09, "Brute Force": 0.02, "Network Anomaly": 0.01}},
            {"until": 0.58, "weights": {"Benign": 0.72, "Port Scan": 0.08, "Brute Force": 0.14, "Bot Activity": 0.05, "Network Anomaly": 0.01}},
            {"until": 0.80, "weights": {"Benign": 0.55, "DDoS": 0.22, "DoS": 0.08, "Bot Activity": 0.08, "Port Scan": 0.05, "Network Anomaly": 0.02}},
            {"until": 1.01, "weights": {"Benign": 0.80, "DDoS": 0.08, "Bot Activity": 0.05, "Port Scan": 0.04, "Network Anomaly": 0.03}},
        ],
    },
    "normal": {
        "label": "Benign baseline",
        "description": "Normal enterprise traffic only - useful to show a clean dashboard and low false positives.",
        "phases": [{"until": 1.01, "weights": {"Benign": 0.985, "Network Anomaly": 0.015}}],
    },
    "ddos": {
        "label": "DDoS / volumetric flood",
        "description": "Rapid escalation into a distributed SYN/UDP flood against a single service.",
        "phases": [
            {"until": 0.25, "weights": {"Benign": 0.9, "Port Scan": 0.1}},
            {"until": 0.55, "weights": {"Benign": 0.6, "DDoS": 0.3, "DoS": 0.1}},
            {"until": 1.01, "weights": {"Benign": 0.35, "DDoS": 0.5, "DoS": 0.15}},
        ],
    },
    "port_scan": {
        "label": "Port scan / reconnaissance",
        "description": "Sequential service-port sweeping from a small set of hostile sources.",
        "phases": [
            {"until": 0.3, "weights": {"Benign": 0.85, "Port Scan": 0.15}},
            {"until": 1.01, "weights": {"Benign": 0.55, "Port Scan": 0.42, "Network Anomaly": 0.03}},
        ],
    },
    "brute_force": {
        "label": "Brute force / credential stuffing",
        "description": "Sustained authentication attempts against SSH/RDP with a high failure ratio.",
        "phases": [
            {"until": 0.3, "weights": {"Benign": 0.9, "Brute Force": 0.1}},
            {"until": 1.01, "weights": {"Benign": 0.6, "Brute Force": 0.37, "Network Anomaly": 0.03}},
        ],
    },
    "botnet": {
        "label": "Botnet / C2 beaconing",
        "description": "Compromised internal hosts beaconing to command-and-control infrastructure.",
        "phases": [
            {"until": 0.35, "weights": {"Benign": 0.9, "Bot Activity": 0.1}},
            {"until": 1.01, "weights": {"Benign": 0.62, "Bot Activity": 0.33, "Intrusion": 0.05}},
        ],
    },
    "intrusion": {
        "label": "Intrusion / exfiltration",
        "description": "Post-compromise behaviour: large outbound sessions and anomalous protocol usage.",
        "phases": [
            {"until": 0.4, "weights": {"Benign": 0.88, "Intrusion": 0.12}},
            {"until": 1.01, "weights": {"Benign": 0.6, "Intrusion": 0.3, "Network Anomaly": 0.1}},
        ],
    },
}

INTERNAL_HOSTS = [
    "10.20.1.15", "10.20.1.22", "10.20.1.37", "10.20.1.48", "10.20.2.11", "10.20.2.64",
    "10.20.3.9", "10.20.3.120", "10.20.4.5", "192.168.40.18", "192.168.40.77",
]
SERVERS = {
    "web": ("10.20.10.5", [80, 443, 8080]),
    "dns": ("10.20.10.53", [53]),
    "ssh": ("10.20.10.22", [22]),
    "db": ("10.20.10.90", [3306, 5432]),
    "mail": ("10.20.10.25", [25, 587]),
}
EXTERNAL_POOL = [
    "203.0.113.14", "203.0.113.88", "198.51.100.23", "198.51.100.177", "192.0.2.45",
    "192.0.2.210", "185.220.101.7", "91.240.118.52", "45.33.32.101", "104.21.7.190",
    "142.250.190.46", "13.107.42.14", "151.101.65.140", "8.8.8.8", "1.1.1.1",
]
C2_HOSTS = ["185.220.101.7", "91.240.118.52", "45.33.32.101"]
C2_PORTS = [4444, 6667, 9999, 1337]

REGIONS = [
    "North America", "South America", "Western Europe", "Eastern Europe", "Northern Europe",
    "Middle East", "South Asia", "East Asia", "South-East Asia", "Africa", "Oceania",
]


def region_for_ip(ip: str) -> str:
    """Deterministic, privacy-preserving region abstraction for the threat map."""
    if not ip:
        return "Unknown"
    digest = sum(ord(ch) * (index + 1) for index, ch in enumerate(ip))
    return REGIONS[digest % len(REGIONS)]


@dataclass
class SimulationState:
    status: str = "stopped"          # stopped | running | paused
    scenario: str = "mixed"
    intensity: int = 5               # 1..10 -> flows per tick
    tick_seconds: float = 1.0
    duration_seconds: int = 600
    started_at: Optional[str] = None
    ends_at: Optional[str] = None
    paused_at: Optional[str] = None
    elapsed_seconds: float = 0.0
    generated_flows: int = 0
    analyzed_flows: int = 0
    alerts_created: int = 0
    attacks_generated: int = 0
    anomalies_generated: int = 0
    last_error: Optional[str] = None
    last_tick_at: Optional[str] = None
    label: str = "Simulation Mode"

    def to_dict(self) -> Dict[str, Any]:
        data = self.__dict__.copy()
        data["scenario_label"] = SCENARIOS.get(self.scenario, {}).get("label", self.scenario)
        data["scenario_description"] = SCENARIOS.get(self.scenario, {}).get("description", "")
        data["flows_per_second"] = round(self.intensity * 1.2, 1)
        data["remaining_seconds"] = max(0, int(self.duration_seconds - self.elapsed_seconds)) if self.started_at else self.duration_seconds
        data["progress"] = round(min(1.0, self.elapsed_seconds / max(self.duration_seconds, 1)), 3)
        data["is_simulated"] = True
        return data


class SimulationEngine:
    def __init__(self) -> None:
        self.state = SimulationState(intensity=settings.simulation_default_rate // 2 or 5)
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._pause = threading.Event()
        self._lock = threading.Lock()
        self._rng = random.Random(20260929)

    # -- control -----------------------------------------------------------
    def start(self, scenario: str = "mixed", intensity: int = 5, duration_seconds: int = 600,
              tick_seconds: float = 1.0) -> Dict[str, Any]:
        scenario = scenario if scenario in SCENARIOS else "mixed"
        with self._lock:
            if self.state.status == "paused":
                self.resume()
                return self.status()
            if self.state.status == "running":
                self.stop()
            self._stop.clear()
            self._pause.clear()
            self.state = SimulationState(
                status="running",
                scenario=scenario,
                intensity=max(1, min(10, int(intensity))),
                tick_seconds=max(0.25, float(tick_seconds)),
                duration_seconds=max(30, min(7200, int(duration_seconds))),
                started_at=iso(utcnow()),
                ends_at=iso(utcnow() + timedelta(seconds=max(30, min(7200, int(duration_seconds))))),
            )
            self._thread = threading.Thread(target=self._run, name="cyberforecast-simulation", daemon=True)
            self._thread.start()
        return self.status()

    def pause(self) -> Dict[str, Any]:
        with self._lock:
            if self.state.status != "running":
                return self.status()
            self._pause.set()
            self.state.status = "paused"
            self.state.paused_at = iso(utcnow())
        return self.status()

    def resume(self) -> Dict[str, Any]:
        with self._lock:
            if self.state.status != "paused":
                return self.status()
            self._pause.clear()
            self.state.status = "running"
            self.state.paused_at = None
        return self.status()

    def stop(self) -> Dict[str, Any]:
        with self._lock:
            self._stop.set()
            self._pause.clear()
            self.state.status = "stopped"
        return self.status()

    def update(self, intensity: Optional[int] = None, scenario: Optional[str] = None,
               duration_seconds: Optional[int] = None) -> Dict[str, Any]:
        with self._lock:
            if intensity is not None:
                self.state.intensity = max(1, min(10, int(intensity)))
            if scenario and scenario in SCENARIOS:
                self.state.scenario = scenario
            if duration_seconds is not None:
                self.state.duration_seconds = max(30, min(7200, int(duration_seconds)))
        return self.status()

    def status(self) -> Dict[str, Any]:
        with self._lock:
            return self.state.to_dict()

    # -- generation --------------------------------------------------------
    def _phase_weights(self, progress: float) -> Dict[str, float]:
        phases = SCENARIOS[self.state.scenario]["phases"]
        for phase in phases:
            if progress <= phase["until"]:
                return phase["weights"]
        return phases[-1]["weights"]

    def _pick_attack(self, progress: float) -> str:
        weights = self._phase_weights(progress)
        names = list(weights.keys())
        return self._rng.choices(names, weights=[weights[n] for n in names], k=1)[0]

    def generate_flow(self, attack_type: str, when: datetime) -> Dict[str, Any]:
        rng = self._rng
        jitter = rng.uniform(0.85, 1.18)

        if attack_type == "Benign":
            service = rng.choice(list(SERVERS.keys())) if rng.random() < 0.45 else "web"
            server_ip, ports = SERVERS.get(service, SERVERS["web"])
            outbound = rng.random() < 0.5
            src = rng.choice(INTERNAL_HOSTS) if outbound else rng.choice(EXTERNAL_POOL)
            dst = rng.choice(EXTERNAL_POOL) if outbound else server_ip
            dst_port = rng.choice(ports) if not outbound else rng.choice([443, 80, 53, 22, 8080, 3306])
            protocol = rng.choice(["HTTPS", "HTTP", "DNS", "TCP", "UDP"])
            packet_count = max(1, int(rng.gauss(45, 30) * jitter))
            packet_length = rng.randint(64, 1460)
            flow_duration = round(max(0.01, rng.gauss(3.2, 2.4)), 3)
            tcp_flags = rng.choice(["ACK", "PSH-ACK", "SYN-ACK", "FIN-ACK"])
            failed = 1 if rng.random() < 0.05 else 0
            connections = max(1, int(rng.gauss(2, 1)))
        elif attack_type == "DDoS":
            src = f"{rng.randint(11, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
            dst = SERVERS["web"][0]
            dst_port = rng.choice([80, 443, 53])
            protocol = rng.choice(["TCP", "UDP", "TCP", "ICMP"])
            packet_count = int(rng.uniform(6000, 40000) * jitter)
            packet_length = rng.choice([64, 96, 512, 1460])
            flow_duration = round(rng.uniform(4.0, 25.0), 3)
            tcp_flags = "SYN"
            failed = int(packet_count * rng.uniform(0.3, 0.7))
            connections = int(rng.uniform(40, 400))
        elif attack_type == "DoS":
            src = rng.choice(EXTERNAL_POOL)
            dst = SERVERS["web"][0]
            dst_port = rng.choice([80, 443, 8080])
            protocol = "TCP"
            packet_count = int(rng.uniform(1500, 7000) * jitter)
            packet_length = rng.randint(900, 1500)
            flow_duration = round(rng.uniform(15.0, 80.0), 2)
            tcp_flags = rng.choice(["SYN", "PSH-ACK"])
            failed = int(packet_count * rng.uniform(0.2, 0.5))
            connections = int(rng.uniform(5, 40))
        elif attack_type == "Port Scan":
            src = rng.choice(EXTERNAL_POOL[:9])
            dst = rng.choice([s[0] for s in SERVERS.values()] + INTERNAL_HOSTS)
            dst_port = rng.randint(20, 1024)
            protocol = "TCP"
            packet_count = rng.randint(1, 3)
            packet_length = rng.randint(40, 60)
            flow_duration = round(rng.uniform(0.001, 0.03), 4)
            tcp_flags = rng.choice(["SYN", "XMAS", "NULL", "RST", "FIN"])
            failed = packet_count
            connections = 1
        elif attack_type == "Brute Force":
            src = rng.choice(EXTERNAL_POOL)
            dst = SERVERS["ssh"][0] if rng.random() < 0.7 else SERVERS["db"][0]
            dst_port = rng.choice([22, 3389, 3306, 21])
            protocol = "TCP"
            packet_count = int(rng.uniform(120, 700) * jitter)
            packet_length = rng.randint(120, 360)
            flow_duration = round(rng.uniform(4.0, 40.0), 2)
            tcp_flags = "PSH-ACK"
            failed = int(packet_count * rng.uniform(0.55, 0.95))
            connections = int(rng.uniform(20, 180))
        elif attack_type == "Bot Activity":
            src = rng.choice(INTERNAL_HOSTS)
            dst = rng.choice(C2_HOSTS)
            dst_port = rng.choice(C2_PORTS)
            protocol = rng.choice(["TCP", "UDP"])
            packet_count = int(rng.uniform(20, 180))
            packet_length = rng.randint(60, 400)
            flow_duration = round(rng.uniform(30.0, 320.0), 2)
            tcp_flags = "ACK"
            failed = 0
            connections = int(rng.uniform(1, 6))
        elif attack_type == "Intrusion":
            src = rng.choice(INTERNAL_HOSTS)
            dst = rng.choice(EXTERNAL_POOL)
            dst_port = rng.choice([443, 8443, 4444, 21])
            protocol = rng.choice(["HTTPS", "TCP"])
            packet_count = int(rng.uniform(400, 4000) * jitter)
            packet_length = rng.randint(900, 1500)
            flow_duration = round(rng.uniform(25.0, 240.0), 2)
            tcp_flags = "PSH-ACK"
            failed = int(packet_count * rng.uniform(0.0, 0.1))
            connections = int(rng.uniform(1, 8))
        else:  # Network Anomaly
            src = rng.choice(EXTERNAL_POOL + INTERNAL_HOSTS)
            dst = rng.choice([s[0] for s in SERVERS.values()] + INTERNAL_HOSTS)
            dst_port = rng.choice([0, 7, 111, 135, 139, 161, 500, 1900, 3128, 5900, 7000, 9100])
            protocol = rng.choice(["ICMP", "UDP", "TCP", "ARP"])
            packet_count = int(rng.uniform(5, 900))
            packet_length = rng.choice([0, 28, 64, 68, 1500])
            flow_duration = round(rng.uniform(0.001, 12.0), 3)
            tcp_flags = rng.choice(["NULL", "XMAS", "URG", "RST", "FIN"])
            failed = int(packet_count * rng.uniform(0.1, 0.6))
            connections = max(1, int(rng.uniform(1, 25)))

        packet_count = max(1, int(packet_count))
        byte_count = int(packet_count * packet_length)
        safe_duration = max(flow_duration, 0.001)
        return {
            "timestamp": when.astimezone(timezone.utc),
            "source_ip": src,
            "destination_ip": dst,
            "source_port": rng.randint(1024, 65535),
            "destination_port": int(dst_port),
            "protocol": protocol,
            "packet_count": packet_count,
            "byte_count": byte_count,
            "packet_length": float(packet_length),
            "flow_duration": float(flow_duration),
            "packets_per_second": round(packet_count / safe_duration, 2),
            "bytes_per_second": round(byte_count / safe_duration, 2),
            "connection_count": int(connections),
            "tcp_flags": tcp_flags,
            "failed_connections": int(failed),
            "request_frequency": round(packet_count / safe_duration / max(connections, 1), 2),
            "attack_type": attack_type,   # ground truth of the synthetic scenario
        }

    # -- worker ------------------------------------------------------------
    def _run(self) -> None:
        from app.ml.features import detect_columns, normalize_frame
        from app.services import pipeline_service

        started = time.monotonic()
        paused_total = 0.0
        pause_started: Optional[float] = None

        while not self._stop.is_set():
            if self._pause.is_set():
                if pause_started is None:
                    pause_started = time.monotonic()
                time.sleep(0.2)
                continue
            if pause_started is not None:
                paused_total += time.monotonic() - pause_started
                pause_started = None

            elapsed = time.monotonic() - started - paused_total
            with self._lock:
                self.state.elapsed_seconds = round(elapsed, 1)
                if elapsed >= self.state.duration_seconds:
                    self.state.status = "stopped"
                    break
                progress = min(1.0, elapsed / max(self.state.duration_seconds, 1))
                flows_per_tick = max(1, int(round(self.state.intensity * 6)))

            now = datetime.now(timezone.utc)
            flows: List[Dict[str, Any]] = []
            for index in range(flows_per_tick):
                attack = self._pick_attack(progress)
                when = now - timedelta(milliseconds=self._rng.randint(0, int(self.state.tick_seconds * 1000)))
                flow = self.generate_flow(attack, when)
                flows.append(flow)

            try:
                raw = pd.DataFrame(flows)
                normalized = normalize_frame(raw, detect_columns(raw))
                result = pipeline_service.analyze_frame(
                    normalized, source="simulation", persist=True, create_alerts=True, explain=False,
                )
                summary = result.get("summary") or {}
                with self._lock:
                    self.state.generated_flows += len(flows)
                    self.state.analyzed_flows += int(summary.get("rows") or 0)
                    self.state.alerts_created += int(summary.get("alerts_created") or 0)
                    self.state.attacks_generated += sum(1 for f in flows if f["attack_type"] != "Benign")
                    self.state.anomalies_generated += int(summary.get("anomalies") or 0)
                    self.state.last_tick_at = iso(utcnow())

                hub.publish({
                    "type": "simulation_tick",
                    "timestamp": iso(utcnow()),
                    "flows": len(flows),
                    "attacks": summary.get("attacks_detected", 0),
                    "anomalies": summary.get("anomalies", 0),
                    "mean_risk_score": summary.get("mean_risk_score", 0.0),
                    "max_risk_score": summary.get("max_risk_score", 0.0),
                    "alerts_created": summary.get("alerts_created", 0),
                    "class_distribution": summary.get("class_distribution", {}),
                    "engine": summary.get("engine"),
                    "is_simulated": True,
                    "state": self.status(),
                })
            except Exception as exc:  # pragma: no cover - keep the worker alive
                logger.exception("simulation tick failed")
                with self._lock:
                    self.state.last_error = str(exc)[:300]

            time.sleep(self.state.tick_seconds)

        with self._lock:
            self.state.status = "stopped"
        hub.publish({"type": "simulation_stopped", "timestamp": iso(utcnow()), "state": self.status()})


engine = SimulationEngine()


def scenarios() -> List[Dict[str, Any]]:
    return [
        {"key": key, "label": spec["label"], "description": spec["description"],
         "phases": [{"until": round(p["until"], 2), "mix": p["weights"]} for p in spec["phases"]]}
        for key, spec in SCENARIOS.items()
    ]
