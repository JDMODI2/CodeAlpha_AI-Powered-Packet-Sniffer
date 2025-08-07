from scapy.all import sniff, IP, TCP, UDP, Raw
from datetime import datetime
import argparse
import math
from collections import defaultdict, deque
import csv
import sys

SUSPICIOUS_KEYWORDS = [b'password', b'login', b'secret', b'admin', b'confidential']
SUSPICIOUS_PORTS = [21, 23, 3389, 4444, 8080]

stats = {
    "total": 0,
    "suspicious": 0,
    "large": 0,
    "unknown_proto": 0,
    "suspicious_port": 0,
    "high_entropy": 0,
    "tcp": 0,
    "udp": 0,
    "ip_counts": defaultdict(int)
}

ip_window = deque(maxlen=100)
packet_log = []

def is_suspicious(payload):
    payload_lower = payload.lower()
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in payload_lower:
            return True, keyword.decode(errors='replace')
    return False, None

def check_ports(packet):
    ports = []
    if TCP in packet:
        ports = [packet[TCP].sport, packet[TCP].dport]
    elif UDP in packet:
        ports = [packet[UDP].sport, packet[UDP].dport]
    for port in ports:
        if port in SUSPICIOUS_PORTS:
            return True, port
    return False, None

def calculate_entropy(data):
    if not data:
        return 0
    occurences = defaultdict(int)
    for x in data:
        occurences[x] += 1
    entropy = 0
    for x in occurences.values():
        p_x = x / len(data)
        entropy -= p_x * math.log2(p_x)
    return entropy

def packet_callback(packet):
    stats["total"] += 1
    log_lines = []
    if IP in packet:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        proto_name = {6: 'TCP', 17: 'UDP'}.get(proto, f"Unknown({proto})")
        payload = b""
        if Raw in packet:
            payload = packet[Raw].load
        log_lines.append(f"[{timestamp}] Source: {ip_src} -> Destination: {ip_dst} | Protocol: {proto_name}")

        # Protocol stats
        if proto_name == "TCP":
            stats["tcp"] += 1
        elif proto_name == "UDP":
            stats["udp"] += 1

        # Frequency-based anomaly detection
        ip_window.append(ip_src)
        stats["ip_counts"][ip_src] += 1
        if ip_window.count(ip_src) > 20:
            log_lines.append(f"⚠️  High frequency of packets from {ip_src} (possible scan or DDoS)")

        # AI Feature 1: Suspicious keyword detection
        suspicious = False
        keyword = None
        if payload:
            try:
                decoded_payload = payload[:32].decode(errors='replace')
                log_lines.append(f"Payload (first 32 bytes): {decoded_payload}")
                suspicious, keyword = is_suspicious(payload)
                if suspicious:
                    log_lines.append(f"⚠️  Suspicious keyword detected: '{keyword}'")
                    stats["suspicious"] += 1
            except Exception:
                log_lines.append(f"Payload (first 32 bytes): {payload[:32]}")

        # AI Feature 2: Large payload warning
        large_payload = False
        if len(payload) > 1000:
            log_lines.append(f"⚠️  Large payload detected: {len(payload)} bytes")
            stats["large"] += 1
            large_payload = True

        # AI Feature 3: Suspicious port detection
        port_flag, port = check_ports(packet)
        if port_flag:
            log_lines.append(f"⚠️  Suspicious port detected: {port}")
            stats["suspicious_port"] += 1

        # AI Feature 4: Unknown protocol anomaly
        unknown_proto = False
        if proto_name.startswith("Unknown"):
            log_lines.append(f"⚠️  Unknown protocol number: {proto}")
            stats["unknown_proto"] += 1
            unknown_proto = True

        # AI Feature 5: High entropy payload detection
        high_entropy = False
        if payload:
            entropy = calculate_entropy(payload)
            if entropy > args.entropy_threshold and len(payload) > 20:
                log_lines.append(f"⚠️  High-entropy payload detected (entropy={entropy:.2f})")
                stats["high_entropy"] += 1
                high_entropy = True

        log_lines.append("-" * 60)
        output = "\n".join(log_lines)
        print(output)
        if args.logfile:
            with open(args.logfile, "a") as f:
                f.write(output + "\n")

        # Log packet to CSV
        packet_log.append([
            timestamp, ip_src, ip_dst, proto_name,
            decoded_payload if payload else "",
            "Yes" if suspicious else "",
            keyword if suspicious else "",
            "Yes" if large_payload else "",
            "Yes" if port_flag else "",
            "Yes" if unknown_proto else "",
            f"{entropy:.2f}" if payload else "",
            "Yes" if high_entropy else ""
        ])

        # Live packet count display
        if stats["total"] % args.live_count == 0:
            print(f"--- {stats['total']} packets captured so far ---")

def main():
    global args
    parser = argparse.ArgumentParser(description="Professional AI/ML Packet Tracer")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on (default: all)", default=None)
    parser.add_argument("-l", "--logfile", help="Log output to a file", default=None)
    parser.add_argument("-c", "--csv", help="CSV file to save all packets", default=None)
    parser.add_argument("-f", "--filter", help="Protocol filter: tcp, udp, or all", default="all")
    parser.add_argument("-e", "--entropy-threshold", type=float, help="High-entropy threshold", default=5.0)
    parser.add_argument("--live-count", type=int, help="Show live packet count every N packets", default=50)
    parser.add_argument("--summary-file", help="Save summary to this file on exit", default=None)
    args = parser.parse_args()

    # Set BPF filter
    bpf_filter = "ip"
    if args.filter.lower() == "tcp":
        bpf_filter = "tcp"
    elif args.filter.lower() == "udp":
        bpf_filter = "udp"

    print("Starting AI/ML Packet Tracer... Press Ctrl+C to stop.")
    try:
        sniff(prn=packet_callback, store=0, filter=bpf_filter, iface=args.interface)
    except KeyboardInterrupt:
        print("\n--- Packet Capture Summary ---")
        print(f"Total packets captured: {stats['total']}")
        print(f"Suspicious payloads: {stats['suspicious']}")
        print(f"Large payloads: {stats['large']}")
        print(f"Packets with suspicious ports: {stats['suspicious_port']}")
        print(f"Unknown protocol packets: {stats['unknown_proto']}")
        print(f"High-entropy payloads: {stats['high_entropy']}")
        print(f"TCP packets: {stats['tcp']} ({stats['tcp']/stats['total']*100:.1f}%)")
        print(f"UDP packets: {stats['udp']} ({stats['udp']/stats['total']*100:.1f}%)")
        print("Top talkers (most frequent source IPs):")
        for ip, count in sorted(stats["ip_counts"].items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {ip}: {count} packets")
        print("Exiting.")

        # Save CSV log if requested
        if args.csv:
            with open(args.csv, "w", newline='', encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "Timestamp", "Source", "Destination", "Protocol", "Payload",
                    "Suspicious", "Keyword", "LargePayload", "SuspiciousPort",
                    "UnknownProto", "Entropy", "HighEntropy"
                ])
                for row in packet_log:
                    writer.writerow(row)
            print(f"Packet log saved to {args.csv}")

        # Save summary if requested
        if args.summary_file:
            with open(args.summary_file, "w", encoding="utf-8") as f:
                f.write("--- Packet Capture Summary ---\n")
                f.write(f"Total packets captured: {stats['total']}\n")
                f.write(f"Suspicious payloads: {stats['suspicious']}\n")
                f.write(f"Large payloads: {stats['large']}\n")
                f.write(f"Packets with suspicious ports: {stats['suspicious_port']}\n")
                f.write(f"Unknown protocol packets: {stats['unknown_proto']}\n")
                f.write(f"High-entropy payloads: {stats['high_entropy']}\n")
                f.write(f"TCP packets: {stats['tcp']} ({stats['tcp']/stats['total']*100:.1f}%)\n")
                f.write(f"UDP packets: {stats['udp']} ({stats['udp']/stats['total']*100:.1f}%)\n")
                f.write("Top talkers (most frequent source IPs):\n")
                for ip, count in sorted(stats["ip_counts"].items(), key=lambda x: x[1], reverse=True)[:5]:
                    f.write(f"  {ip}: {count} packets\n")
            print(f"Summary saved to {args.summary_file}")

if __name__ == "__main__":
    main()