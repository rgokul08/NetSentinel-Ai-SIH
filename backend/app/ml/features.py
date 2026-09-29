"""
Feature schema, dataset adaptation and label normalization.

Real-world traffic exports use wildly different column names (CIC-IDS, UNSW-NB15,
Zeek, custom SIEM CSVs). This module maps whatever it finds onto one canonical
schema so the rest of the ML pipeline is dataset-agnostic.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

CANONICAL_COLUMNS: List[str] = [
    "timestamp",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "protocol",
    "packet_count",
    "byte_count",
    "packet_length",
    "flow_duration",
    "packets_per_second",
    "bytes_per_second",
    "connection_count",
    "tcp_flags",
    "failed_connections",
    "request_frequency",
    "attack_type",
]

# normalized-name -> canonical column
ALIASES: Dict[str, str] = {
    "timestamp": "timestamp", "time": "timestamp", "datetime": "timestamp", "date": "timestamp",
    "flowstart": "timestamp", "starttime": "timestamp", "firstseen": "timestamp", "ts": "timestamp",
    "sourceip": "source_ip", "srcip": "source_ip", "sip": "source_ip", "sourceaddress": "source_ip",
    "srcaddr": "source_ip", "source": "source_ip", "src": "source_ip", "ipsrc": "source_ip",
    "destinationip": "destination_ip", "dstip": "destination_ip", "dip": "destination_ip",
    "destinationaddress": "destination_ip", "dstaddr": "destination_ip", "destip": "destination_ip",
    "destination": "destination_ip", "dst": "destination_ip", "ipdst": "destination_ip",
    "target": "destination_ip", "targetip": "destination_ip", "targethost": "destination_ip",
    "sourceport": "source_port", "srcport": "source_port", "sport": "source_port", "portsrc": "source_port",
    "destinationport": "destination_port", "dstport": "destination_port", "dport": "destination_port",
    "destport": "destination_port", "portdst": "destination_port", "targetport": "destination_port",
    "protocol": "protocol", "proto": "protocol", "protocolname": "protocol", "transport": "protocol",
    "packetcount": "packet_count", "packets": "packet_count", "totalpackets": "packet_count",
    "pktcount": "packet_count", "flowpacketcount": "packet_count", "totfwdpkts": "packet_count",
    # CICIoT2023 / CIC-IDS style headers ("tot pkts", "TotPkts", "Pkts", "NumPackets")
    "totpkts": "packet_count", "totpackets": "packet_count", "pkts": "packet_count",
    "npkts": "packet_count", "numpackets": "packet_count", "packettotal": "packet_count",
    "bytecount": "byte_count", "bytes": "byte_count", "totalbytes": "byte_count", "flowbytes": "byte_count",
    "bytelen": "byte_count", "totlenfwdpkts": "byte_count", "size": "byte_count",
    "totbytes": "byte_count", "totlen": "byte_count", "nbytes": "byte_count",
    "numbytes": "byte_count", "bytestotal": "byte_count",
    "packetlength": "packet_length", "pktlen": "packet_length", "avgpacketlen": "packet_length",
    "avgpktlen": "packet_length", "packetlen": "packet_length", "meanpacketlength": "packet_length",
    "flowduration": "flow_duration", "duration": "flow_duration", "durationms": "flow_duration",
    "flowdurationms": "flow_duration", "flowdurationseconds": "flow_duration", "elapsed": "flow_duration",
    "packetspersecond": "packets_per_second", "pps": "packets_per_second", "packetrate": "packets_per_second",
    "flowpacketspersecond": "packets_per_second", "pktspersec": "packets_per_second",
    # "Flow Packets/s" (CIC-IDS2017) normalizes to "flowpacketss"
    "flowpacketss": "packets_per_second", "packetspersec": "packets_per_second",
    "pktspersecond": "packets_per_second", "pktss": "packets_per_second",
    "bytespersecond": "bytes_per_second", "bps": "bytes_per_second", "bandwidth": "bytes_per_second",
    "throughput": "bytes_per_second", "flowbytespersecond": "bytes_per_second", "bytessentpersec": "bytes_per_second",
    # "Flow Bytes/s" (CIC-IDS2017) normalizes to "flowbytess"
    "flowbytess": "bytes_per_second", "bytespersec": "bytes_per_second", "bytess": "bytes_per_second",
    "connectioncount": "connection_count", "connections": "connection_count", "conn": "connection_count",
    "numconnections": "connection_count", "sessioncount": "connection_count",
    "tcpflags": "tcp_flags", "flags": "tcp_flags", "flag": "tcp_flags", "tcpflag": "tcp_flags",
    "failedconnections": "failed_connections", "failedconnectionscount": "failed_connections",
    "failedloginattempts": "failed_connections", "authfailures": "failed_connections",
    "failures": "failed_connections", "rejectedconnections": "failed_connections",
    "requestfrequency": "request_frequency", "requestrate": "request_frequency",
    "requestspersecond": "request_frequency", "frequency": "request_frequency", "reqfreq": "request_frequency",
    "attacktype": "attack_type", "attack": "attack_type", "attackname": "attack_type", "label": "attack_type",
    "class": "attack_type", "category": "attack_type", "attackcategory": "attack_type",
    "attacklabel": "attack_type", "threattype": "attack_type", "attacktarget": "attack_type",
    "targetlabel": "attack_type", "targetclass": "attack_type", "anomaly": "attack_type",
}

PROTOCOL_VOCAB = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "SSH", "ARP", "OTHER"]
TCP_FLAG_VOCAB = ["SYN", "ACK", "SYN-ACK", "PSH-ACK", "FIN", "FIN-ACK", "RST", "URG", "XMAS", "NULL", "OTHER"]

# Canonical attack taxonomy (mirrors app.storage.schema.ATTACK_CLASSES)
ATTACK_CLASSES: List[str] = [
    "Benign", "DoS", "DDoS", "Port Scan", "Brute Force", "Bot Activity", "Intrusion", "Network Anomaly",
]
BENIGN = "Benign"

LABEL_RULES: List[Tuple[str, str]] = [
    (r"ddos|distributed|hulk|slowloris.*distributed|amplification|syn.*flood.*(multi|distributed)", "DDoS"),
    (r"\bdos\b|denial|flood|slowloris|slow.?htt|resource.?exhaust", "DoS"),
    (r"scan|recon|sweep|nmap|probe|enumerat", "Port Scan"),
    (r"brute|patator|credential|password.?guess|auth.?fail|login.?attempt", "Brute Force"),
    (r"bot|botnet|c2|c&c|command.?and.?control|mirai|beacon", "Bot Activity"),
    (r"intrus|infiltrat|malware|exploit|backdoor|web.?attack|sql.?inject|xss|shellcode|ransom|trojan|worm|virus|apt", "Intrusion"),
    (r"anomal|unknown|suspicious|other.?attack|unclassified", "Network Anomaly"),
]

BENIGN_TOKENS = {"benign", "normal", "0", "no attack", "none", "clean", "legit", "legitimate", "ok", "false"}


def normalize_name(name: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


def normalize_label(raw: Any) -> str:
    """Map arbitrary dataset labels onto the canonical attack taxonomy."""
    if raw is None or (isinstance(raw, float) and np.isnan(raw)):
        return BENIGN
    text = str(raw).strip()
    lowered = text.lower()
    normalized = normalize_name(lowered)
    if lowered in BENIGN_TOKENS or normalized in {"benign", "normal", "0"}:
        return BENIGN
    try:
        if float(text) == 0:
            return BENIGN
        if float(text) == 1:
            return "Network Anomaly"
    except (TypeError, ValueError):
        pass
    for pattern, label in LABEL_RULES:
        if re.search(pattern, lowered):
            return label
    return "Network Anomaly"


def detect_columns(df: pd.DataFrame) -> Dict[str, Any]:
    """Map a raw dataframe onto the canonical schema and report what was found."""
    mapping: Dict[str, str] = {}
    used: set = set()
    for column in df.columns:
        key = normalize_name(column)
        canonical = ALIASES.get(key)
        if canonical and canonical not in used:
            mapping[column] = canonical
            used.add(canonical)
    # Second pass for unmapped canonical columns (handles odd separators).
    for column in df.columns:
        if column in mapping:
            continue
        key = normalize_name(column)
        for alias, canonical in ALIASES.items():
            if canonical in used:
                continue
            if alias and (alias in key or key in alias) and len(alias) > 5:
                mapping[column] = canonical
                used.add(canonical)
                break
    missing = [c for c in CANONICAL_COLUMNS if c not in used]
    return {
        "mapping": mapping,
        "canonical_found": sorted(used),
        "missing_canonical": missing,
        "unmapped_columns": [str(c) for c in df.columns if c not in mapping],
        "coverage": round(len(used) / len(CANONICAL_COLUMNS), 3),
    }


def normalize_frame(df: pd.DataFrame, detection: Optional[Dict[str, Any]] = None) -> pd.DataFrame:
    """Return a dataframe with canonical column names and sane dtypes/defaults."""
    detection = detection or detect_columns(df)
    out = df.rename(columns=detection["mapping"]).copy()

    for column in CANONICAL_COLUMNS:
        if column not in out.columns:
            out[column] = np.nan

    numeric_columns = [
        "source_port", "destination_port", "packet_count", "byte_count", "packet_length",
        "flow_duration", "packets_per_second", "bytes_per_second", "connection_count",
        "failed_connections", "request_frequency",
    ]
    for column in numeric_columns:
        out[column] = pd.to_numeric(out[column], errors="coerce")

    # Heuristic unit fix: durations reported in micro/milliseconds.
    duration = out["flow_duration"]
    if duration.notna().any() and float(duration.median(skipna=True) or 0) > 1000:
        out["flow_duration"] = duration / 1000.0
        out["flow_duration_seconds"] = out["flow_duration"]

    out["packet_count"] = out["packet_count"].fillna(1).clip(lower=1)
    out["byte_count"] = out["byte_count"].fillna(0).clip(lower=0)
    out["packet_length"] = out["packet_length"].fillna(
        (out["byte_count"] / out["packet_count"]).replace([np.inf, -np.inf], 0)
    ).clip(lower=0)
    out["flow_duration"] = out["flow_duration"].fillna(0.0).clip(lower=0.0)
    out["connection_count"] = out["connection_count"].fillna(1).clip(lower=1)
    out["failed_connections"] = out["failed_connections"].fillna(0).clip(lower=0)

    safe_duration = out["flow_duration"].replace(0, np.nan)
    out["packets_per_second"] = out["packets_per_second"].fillna(
        (out["packet_count"] / safe_duration).replace([np.inf, -np.inf], 0)
    ).clip(lower=0)
    out["bytes_per_second"] = out["bytes_per_second"].fillna(
        (out["byte_count"] / safe_duration).replace([np.inf, -np.inf], 0)
    ).clip(lower=0)
    out["request_frequency"] = out["request_frequency"].fillna(out["packets_per_second"]).clip(lower=0)

    out["protocol"] = out["protocol"].fillna("TCP").astype(str).str.upper().str.strip()
    out["protocol"] = out["protocol"].where(out["protocol"].isin(PROTOCOL_VOCAB), "OTHER")
    out["tcp_flags"] = out["tcp_flags"].fillna("ACK").astype(str).str.upper().str.strip()
    out["tcp_flags"] = out["tcp_flags"].where(out["tcp_flags"].isin(TCP_FLAG_VOCAB), "OTHER")

    for column in ("source_ip", "destination_ip"):
        out[column] = out[column].fillna("0.0.0.0").astype(str)

    parsed_ts = pd.to_datetime(out["timestamp"], errors="coerce", utc=True)
    out["timestamp"] = parsed_ts.astype("datetime64[ns, UTC]")
    missing_ts = out["timestamp"].isna()
    if bool(missing_ts.any()):
        # No usable timestamp: synthesize a recent, evenly spread one so that
        # time-series features and ordering still behave.
        now = pd.Timestamp.now(tz="UTC").to_datetime64()
        count = int(missing_ts.sum())
        offsets = np.linspace(0, 3600 * 6, count)
        synthetic = pd.DatetimeIndex(
            [now - np.timedelta64(int(o), "s") for o in offsets], dtype="datetime64[ns, UTC]"
        )
        patch = pd.Series(synthetic, index=out.index[missing_ts]).reindex(out.index)
        out["timestamp"] = out["timestamp"].fillna(patch)

    label_column_present = any(v == "attack_type" for v in detection["mapping"].values())
    out["attack_type"] = out["attack_type"].apply(normalize_label) if label_column_present else "Unknown"
    out["is_labeled"] = bool(label_column_present)
    return out


def engineered_features(df: pd.DataFrame) -> pd.DataFrame:
    """Deterministic derived features (ratios, flags, log scales)."""
    out = df.copy()
    packets = out["packet_count"].clip(lower=1)
    duration = out["flow_duration"].replace(0, np.nan)

    out["bytes_per_packet"] = (out["byte_count"] / packets).replace([np.inf, -np.inf], 0).fillna(0)
    out["packets_per_connection"] = (packets / out["connection_count"].clip(lower=1)).fillna(1)
    out["failed_connection_ratio"] = (out["failed_connections"] / out["connection_count"].clip(lower=1)).clip(0, 1).fillna(0)
    out["is_well_known_port"] = (out["destination_port"].fillna(0) <= 1024).astype(float)
    out["is_ephemeral_source_port"] = (out["source_port"].fillna(0) >= 49152).astype(float)
    out["is_auth_port"] = out["destination_port"].fillna(0).isin([21, 22, 23, 3389, 445, 1433, 3306]).astype(float)
    out["is_c2_port"] = out["destination_port"].fillna(0).isin([4444, 6667, 6668, 6669, 9999, 1337, 31337]).astype(float)
    out["log_packet_count"] = np.log1p(packets)
    out["log_byte_count"] = np.log1p(out["byte_count"].clip(lower=0))
    out["log_packets_per_second"] = np.log1p(out["packets_per_second"].clip(lower=0))
    out["log_bytes_per_second"] = np.log1p(out["bytes_per_second"].clip(lower=0))
    out["log_flow_duration"] = np.log1p(out["flow_duration"].clip(lower=0))
    out["short_flow"] = (out["flow_duration"].fillna(0) < 0.05).astype(float)
    out["syn_flag"] = (out["tcp_flags"] == "SYN").astype(float)
    out["scan_like_flags"] = out["tcp_flags"].isin(["XMAS", "NULL", "SYN", "RST"]).astype(float)
    out["hour_sin"] = np.sin(2 * np.pi * out["timestamp"].dt.hour.fillna(12) / 24.0)
    out["hour_cos"] = np.cos(2 * np.pi * out["timestamp"].dt.hour.fillna(12) / 24.0)
    return out


MODEL_NUMERIC_FEATURES: List[str] = [
    "source_port", "destination_port", "packet_count", "byte_count", "packet_length",
    "flow_duration", "packets_per_second", "bytes_per_second", "connection_count",
    "failed_connections", "request_frequency",
    "bytes_per_packet", "packets_per_connection", "failed_connection_ratio",
    "is_well_known_port", "is_ephemeral_source_port", "is_auth_port", "is_c2_port",
    "log_packet_count", "log_byte_count", "log_packets_per_second", "log_bytes_per_second",
    "log_flow_duration", "short_flow", "syn_flag", "scan_like_flags", "hour_sin", "hour_cos",
]

FEATURE_LABELS: Dict[str, str] = {
    "source_port": "Source port",
    "destination_port": "Destination port",
    "packet_count": "Packet count",
    "byte_count": "Byte count",
    "packet_length": "Packet length",
    "flow_duration": "Flow duration",
    "packets_per_second": "Packet rate (pps)",
    "bytes_per_second": "Bandwidth (B/s)",
    "connection_count": "Connection count",
    "failed_connections": "Failed connections",
    "request_frequency": "Request frequency",
    "bytes_per_packet": "Bytes per packet",
    "packets_per_connection": "Packets per connection",
    "failed_connection_ratio": "Failed connection ratio",
    "is_well_known_port": "Well-known service port",
    "is_ephemeral_source_port": "Ephemeral source port",
    "is_auth_port": "Authentication service port",
    "is_c2_port": "Known C2 / botnet port",
    "log_packet_count": "Packet count (log)",
    "log_byte_count": "Byte count (log)",
    "log_packets_per_second": "Packet rate (log)",
    "log_bytes_per_second": "Bandwidth (log)",
    "log_flow_duration": "Flow duration (log)",
    "short_flow": "Ultra-short flow",
    "syn_flag": "Bare SYN flag",
    "scan_like_flags": "Scan-like TCP flags",
    "hour_sin": "Time of day (sin)",
    "hour_cos": "Time of day (cos)",
}


def categorical_matrix(df: pd.DataFrame) -> pd.DataFrame:
    """One-hot encode protocol + TCP flags against the fixed vocabularies."""
    encoded = pd.DataFrame(index=df.index)
    for value in PROTOCOL_VOCAB:
        encoded[f"proto_{value}"] = (df["protocol"] == value).astype(float)
    for value in TCP_FLAG_VOCAB:
        encoded[f"flag_{value}"] = (df["tcp_flags"] == value).astype(float)
    return encoded


def build_feature_frame(df: pd.DataFrame) -> Tuple[pd.DataFrame, List[str]]:
    """Full model matrix: engineered numerics + one-hot categoricals."""
    engineered = engineered_features(df)
    categoricals = categorical_matrix(engineered)
    matrix = pd.concat([engineered[MODEL_NUMERIC_FEATURES].astype(float), categoricals], axis=1)
    matrix = matrix.replace([np.inf, -np.inf], 0).fillna(0.0)
    return matrix, list(matrix.columns)
