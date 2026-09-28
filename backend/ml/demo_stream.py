"""
Demo & Live Network Traffic Stream Generator
Provides dynamic realistic packet flows and attack injections for live SOC demonstrations.
"""

import random
from datetime import datetime
from typing import Dict, Any, List

INTERNAL_IPS = [
    "192.168.1.10", "192.168.1.15", "192.168.1.25", "192.168.1.42",
    "192.168.1.105", "192.168.1.180", "10.0.0.12", "10.0.0.45", "172.16.0.8"
]

EXTERNAL_IPS = [
    "45.33.32.156", "185.220.101.5", "103.251.167.20", "91.240.118.168",
    "194.26.29.112", "198.51.100.42", "203.0.113.195", "8.8.8.8", "1.1.1.1",
    "142.250.190.46", "151.101.65.140", "13.107.42.14"
]

ATTACK_PROB_DIST = [
    ("Normal", 0.60),
    ("DoS", 0.08),
    ("DDoS", 0.08),
    ("Port Scan", 0.08),
    ("Brute Force", 0.06),
    ("Botnet", 0.04),
    ("Malware", 0.04),
    ("Other Attack", 0.02)
]

def generate_live_packet(forced_attack: str = None) -> Dict[str, Any]:
    """Generates a single realistic live network traffic packet flow"""
    if forced_attack:
        attack = forced_attack
    else:
        types, weights = zip(*ATTACK_PROB_DIST)
        attack = random.choices(types, weights=weights, k=1)[0]
        
    now = datetime.now()
    
    if attack == "Normal":
        src_ip = random.choice(INTERNAL_IPS)
        dst_ip = random.choice(EXTERNAL_IPS)
        src_port = random.randint(32768, 65535)
        dst_port = random.choice([80, 443, 53, 22, 8080])
        protocol = random.choice(["HTTPS", "HTTP", "DNS", "TCP", "UDP"])
        packet_count = random.randint(5, 80)
        packet_size = random.randint(64, 1420)
        flow_duration = round(random.uniform(0.05, 8.5), 3)
        tcp_flags = random.choice(["ACK", "PSH-ACK", "SYN-ACK"])
        confidence = round(random.uniform(0.92, 0.99), 2)
        risk_level = "LOW"
        is_anomaly = False
        anomaly_score = round(random.uniform(0.05, 0.28), 3)
        
    elif attack == "DoS":
        src_ip = random.choice(EXTERNAL_IPS)
        dst_ip = "192.168.1.10" # Web Server
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 8080])
        protocol = "TCP"
        packet_count = random.randint(1200, 6000)
        packet_size = random.randint(1200, 1500)
        flow_duration = round(random.uniform(15.0, 90.0), 2)
        tcp_flags = "SYN"
        confidence = round(random.uniform(0.88, 0.97), 2)
        risk_level = "HIGH"
        is_anomaly = True
        anomaly_score = round(random.uniform(0.72, 0.94), 3)
        
    elif attack == "DDoS":
        src_ip = f"{random.randint(11, 220)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        dst_ip = "192.168.1.10"
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 53])
        protocol = random.choice(["TCP", "UDP"])
        packet_count = random.randint(5000, 30000)
        packet_size = random.randint(64, 1460)
        flow_duration = round(random.uniform(20.0, 120.0), 2)
        tcp_flags = "SYN"
        confidence = round(random.uniform(0.91, 0.99), 2)
        risk_level = "CRITICAL"
        is_anomaly = True
        anomaly_score = round(random.uniform(0.85, 0.99), 3)
        
    elif attack == "Port Scan":
        src_ip = random.choice(EXTERNAL_IPS)
        dst_ip = random.choice(INTERNAL_IPS)
        src_port = random.randint(40000, 65000)
        dst_port = random.randint(20, 1024)
        protocol = "TCP"
        packet_count = random.randint(1, 3)
        packet_size = random.randint(40, 60)
        flow_duration = round(random.uniform(0.001, 0.02), 4)
        tcp_flags = random.choice(["SYN", "XMAS", "NULL"])
        confidence = round(random.uniform(0.86, 0.96), 2)
        risk_level = "MEDIUM"
        is_anomaly = True
        anomaly_score = round(random.uniform(0.68, 0.88), 3)
        
    elif attack == "Brute Force":
        src_ip = random.choice(EXTERNAL_IPS)
        dst_ip = "192.168.1.25" # SSH Gateway
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([22, 3389, 8080])
        protocol = "TCP"
        packet_count = random.randint(100, 500)
        packet_size = random.randint(120, 350)
        flow_duration = round(random.uniform(5.0, 30.0), 2)
        tcp_flags = "PSH-ACK"
        confidence = round(random.uniform(0.85, 0.94), 2)
        risk_level = "HIGH"
        is_anomaly = True
        anomaly_score = round(random.uniform(0.70, 0.90), 3)
        
    elif attack == "Botnet":
        src_ip = random.choice(INTERNAL_IPS)
        dst_ip = "185.220.101.5" # Command & Control IP
        src_port = random.randint(30000, 60000)
        dst_port = random.choice([6667, 4444, 9999])
        protocol = "TCP"
        packet_count = random.randint(30, 200)
        packet_size = random.randint(80, 400)
        flow_duration = round(random.uniform(40.0, 300.0), 2)
        tcp_flags = "ACK"
        confidence = round(random.uniform(0.82, 0.93), 2)
        risk_level = "CRITICAL"
        is_anomaly = True
        anomaly_score = round(random.uniform(0.78, 0.95), 3)
        
    elif attack == "Malware":
        src_ip = random.choice(INTERNAL_IPS)
        dst_ip = random.choice(EXTERNAL_IPS)
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([443, 8443])
        protocol = "HTTPS"
        packet_count = random.randint(40, 400)
        packet_size = random.randint(800, 1500)
        flow_duration = round(random.uniform(10.0, 60.0), 2)
        tcp_flags = "PSH-ACK"
        confidence = round(random.uniform(0.80, 0.91), 2)
        risk_level = "HIGH"
        is_anomaly = True
        anomaly_score = round(random.uniform(0.74, 0.92), 3)
        
    else: # Other Attack
        src_ip = random.choice(EXTERNAL_IPS)
        dst_ip = random.choice(INTERNAL_IPS)
        src_port = random.randint(1024, 65535)
        dst_port = random.randint(1024, 8000)
        protocol = random.choice(["TCP", "UDP"])
        packet_count = random.randint(20, 250)
        packet_size = random.randint(200, 1000)
        flow_duration = round(random.uniform(1.0, 20.0), 2)
        tcp_flags = "SYN"
        confidence = round(random.uniform(0.75, 0.88), 2)
        risk_level = "MEDIUM"
        is_anomaly = True
        anomaly_score = round(random.uniform(0.65, 0.85), 3)

    bytes_per_sec = round((packet_count * packet_size) / max(flow_duration, 0.01), 2)
    packets_per_sec = round(packet_count / max(flow_duration, 0.01), 2)

    return {
        "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "source_port": src_port,
        "destination_port": dst_port,
        "protocol": protocol,
        "packet_count": packet_count,
        "packet_size": packet_size,
        "flow_duration": flow_duration,
        "bytes_per_second": bytes_per_sec,
        "packets_per_second": packets_per_sec,
        "tcp_flags": tcp_flags,
        "label": 0 if attack == "Normal" else 1,
        "attack_type": attack,
        "confidence": confidence,
        "risk_level": risk_level,
        "is_anomaly": is_anomaly,
        "anomaly_score": anomaly_score,
        "is_demo": True
    }
