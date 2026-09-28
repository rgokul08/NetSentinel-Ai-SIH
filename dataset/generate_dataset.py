"""
Dataset Generator for SIH Project: AI-Based Network Attack Forecasting
Generates realistic multi-class network traffic flow data with realistic statistical distributions.
"""

import os
import csv
import random
from datetime import datetime, timedelta

def generate_network_traffic_dataset(output_path: str, num_records: int = 3500):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    protocols = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "SSH"]
    attack_types = [
        "Normal",
        "DoS",
        "DDoS",
        "Port Scan",
        "Brute Force",
        "Botnet",
        "Malware",
        "Other Attack"
    ]
    
    # Class distribution weights (Normal traffic dominant, attacks present in realistic proportions)
    weights = [0.55, 0.10, 0.08, 0.08, 0.06, 0.05, 0.05, 0.03]
    
    internal_subnets = ["192.168.1.", "10.0.0.", "172.16.0."]
    external_ips = [
        "45.33.32.156", "185.220.101.5", "103.251.167.20", "91.240.118.168",
        "194.26.29.112", "198.51.100.42", "203.0.113.195", "8.8.8.8", "1.1.1.1",
        "142.250.190.46", "151.101.65.140", "13.107.42.14"
    ]
    
    start_time = datetime.now() - timedelta(days=7)
    
    fieldnames = [
        "timestamp",
        "source_ip",
        "destination_ip",
        "source_port",
        "destination_port",
        "protocol",
        "packet_count",
        "packet_size",
        "flow_duration",
        "bytes_per_second",
        "packets_per_second",
        "tcp_flags",
        "label",
        "attack_type"
    ]
    
    with open(output_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        current_time = start_time
        
        for i in range(num_records):
            current_time += timedelta(seconds=random.randint(5, 180))
            
            attack = random.choices(attack_types, weights=weights, k=1)[0]
            is_attack = 0 if attack == "Normal" else 1
            
            # Realistic parameter synthesis based on attack characteristics
            if attack == "Normal":
                src_ip = f"{random.choice(internal_subnets)}{random.randint(2, 254)}"
                dst_ip = random.choice(external_ips)
                src_port = random.randint(32768, 65535)
                dst_port = random.choice([80, 443, 53, 22, 8080, 3000])
                protocol = random.choice(["TCP", "UDP", "HTTPS", "HTTP", "DNS"])
                packet_count = random.randint(5, 120)
                packet_size = random.randint(64, 1500)
                flow_duration = round(random.uniform(0.1, 15.0), 3)
                bytes_per_sec = round((packet_count * packet_size) / max(flow_duration, 0.1), 2)
                packets_per_sec = round(packet_count / max(flow_duration, 0.1), 2)
                tcp_flags = random.choice(["ACK", "PSH-ACK", "SYN-ACK", "FIN-ACK"])
                
            elif attack == "DoS":
                src_ip = random.choice(external_ips)
                dst_ip = f"192.168.1.{random.randint(10, 50)}" # targeted internal server
                src_port = random.randint(1024, 65535)
                dst_port = random.choice([80, 443, 8080])
                protocol = "TCP"
                packet_count = random.randint(500, 5000)
                packet_size = random.randint(1200, 1500)
                flow_duration = round(random.uniform(10.0, 120.0), 3)
                bytes_per_sec = round((packet_count * packet_size) / max(flow_duration, 0.1), 2)
                packets_per_sec = round(packet_count / max(flow_duration, 0.1), 2)
                tcp_flags = random.choice(["SYN", "ACK", "PSH-ACK"])
                
            elif attack == "DDoS":
                src_ip = f"{random.randint(11, 220)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
                dst_ip = "192.168.1.10" # high value target
                src_port = random.randint(1024, 65535)
                dst_port = random.choice([80, 443, 53, 123])
                protocol = random.choice(["TCP", "UDP"])
                packet_count = random.randint(2000, 20000)
                packet_size = random.randint(64, 1460)
                flow_duration = round(random.uniform(5.0, 60.0), 3)
                bytes_per_sec = round((packet_count * packet_size) / max(flow_duration, 0.1), 2)
                packets_per_sec = round(packet_count / max(flow_duration, 0.1), 2)
                tcp_flags = random.choice(["SYN", "RST", "ACK"])
                
            elif attack == "Port Scan":
                src_ip = random.choice(external_ips)
                dst_ip = f"192.168.1.{random.randint(2, 254)}"
                src_port = random.randint(40000, 60000)
                dst_port = random.randint(1, 1024) # scanning standard ports
                protocol = "TCP"
                packet_count = random.randint(1, 5)
                packet_size = random.randint(40, 64)
                flow_duration = round(random.uniform(0.001, 0.05), 4)
                bytes_per_sec = round((packet_count * packet_size) / max(flow_duration, 0.001), 2)
                packets_per_sec = round(packet_count / max(flow_duration, 0.001), 2)
                tcp_flags = random.choice(["SYN", "NULL", "FIN-PSH-URG", "XMAS"])
                
            elif attack == "Brute Force":
                src_ip = random.choice(external_ips)
                dst_ip = f"192.168.1.{random.randint(20, 30)}"
                src_port = random.randint(1024, 65535)
                dst_port = random.choice([22, 3389, 21, 8080]) # SSH, RDP, FTP, Auth endpoint
                protocol = "TCP"
                packet_count = random.randint(50, 400)
                packet_size = random.randint(100, 300)
                flow_duration = round(random.uniform(2.0, 30.0), 3)
                bytes_per_sec = round((packet_count * packet_size) / max(flow_duration, 0.1), 2)
                packets_per_sec = round(packet_count / max(flow_duration, 0.1), 2)
                tcp_flags = "PSH-ACK"
                
            elif attack == "Botnet":
                src_ip = f"192.168.1.{random.randint(50, 150)}" # compromised internal host
                dst_ip = random.choice(["185.220.101.5", "194.26.29.112", "91.240.118.168"]) # C2 server
                src_port = random.randint(30000, 60000)
                dst_port = random.choice([6667, 4444, 8000, 9999]) # IRC or custom C2
                protocol = "TCP"
                packet_count = random.randint(20, 300)
                packet_size = random.randint(60, 500)
                flow_duration = round(random.uniform(30.0, 600.0), 2)
                bytes_per_sec = round((packet_count * packet_size) / max(flow_duration, 0.1), 2)
                packets_per_sec = round(packet_count / max(flow_duration, 0.1), 2)
                tcp_flags = "ACK"
                
            elif attack == "Malware":
                src_ip = f"192.168.1.{random.randint(100, 200)}"
                dst_ip = random.choice(external_ips)
                src_port = random.randint(1024, 65535)
                dst_port = random.choice([443, 80, 8443])
                protocol = random.choice(["HTTPS", "HTTP", "DNS"])
                packet_count = random.randint(15, 800)
                packet_size = random.randint(500, 1500)
                flow_duration = round(random.uniform(5.0, 90.0), 3)
                bytes_per_sec = round((packet_count * packet_size) / max(flow_duration, 0.1), 2)
                packets_per_sec = round(packet_count / max(flow_duration, 0.1), 2)
                tcp_flags = "PSH-ACK"
                
            else: # Other Attack
                src_ip = random.choice(external_ips)
                dst_ip = f"192.168.1.{random.randint(2, 254)}"
                src_port = random.randint(1024, 65535)
                dst_port = random.randint(1024, 9000)
                protocol = random.choice(["TCP", "UDP", "ICMP"])
                packet_count = random.randint(10, 500)
                packet_size = random.randint(64, 1200)
                flow_duration = round(random.uniform(1.0, 45.0), 3)
                bytes_per_sec = round((packet_count * packet_size) / max(flow_duration, 0.1), 2)
                packets_per_sec = round(packet_count / max(flow_duration, 0.1), 2)
                tcp_flags = random.choice(["SYN", "ACK", "FIN"])

            record = {
                "timestamp": current_time.strftime("%Y-%m-%d %H:%M:%S"),
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
                "label": is_attack,
                "attack_type": attack
            }
            writer.writerow(record)
            
    print(f"Dataset generated with {num_records} records at: {output_path}")

if __name__ == "__main__":
    target = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_network_traffic.csv")
    generate_network_traffic_dataset(target, 3500)
