import threading
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
from scapy.all import sniff, IP, TCP, UDP, Raw
from datetime import datetime
from collections import defaultdict
import math

# Try to import transformers for GenAI
try:
    from transformers import pipeline
    transformers_available = True
except ImportError:
    transformers_available = False

SUSPICIOUS_KEYWORDS = [b'password', b'login', b'secret', b'admin', b'confidential']
SUSPICIOUS_PORTS = [21, 23, 3389, 4444, 8080]

class PacketSnifferGUI:
    def __init__(self, master):
        self.master = master
        master.title("AI Packet Tracer + GenAI")
        self.text = ScrolledText(master, width=110, height=30, bg="#1e1e1e", fg="#d4d4d4", font=("Consolas", 10))
        self.text.pack(padx=10, pady=10)
        self.text.tag_config("alert", foreground="red")
        self.text.tag_config("info", foreground="cyan")
        self.text.tag_config("payload", foreground="yellow")
        self.text.tag_config("normal", foreground="#d4d4d4")
        self.text.tag_config("large", foreground="orange")
        self.text.tag_config("entropy", foreground="magenta")
        # Buttons
        self.start_button = tk.Button(master, text="Start Sniffing", command=self.start_sniffing, bg="green", fg="white")
        self.start_button.pack(side=tk.LEFT, padx=5, pady=5)
        self.stop_button = tk.Button(master, text="Stop Sniffing", command=self.stop, bg="red", fg="white", state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5, pady=5)
        self.save_button = tk.Button(master, text="Save Log", command=self.save_log, bg="blue", fg="white")
        self.save_button.pack(side=tk.LEFT, padx=5, pady=5)
        self.clear_button = tk.Button(master, text="Clear Output", command=self.clear_output, bg="gray", fg="white")
        self.clear_button.pack(side=tk.LEFT, padx=5, pady=5)
        self.analyze_button = tk.Button(master, text="Show Analysis", command=self.show_analysis, bg="purple", fg="white")
        self.analyze_button.pack(side=tk.LEFT, padx=5, pady=5)
        self.genai_button = tk.Button(master, text="GenAI Text", command=self.open_genai_window, bg="orange", fg="black")
        self.genai_button.pack(side=tk.LEFT, padx=5, pady=5)
        self.status = tk.Label(master, text="Status: Idle", anchor="w")
        self.status.pack(fill=tk.X, padx=10, pady=5)
        # Stats
        self.packet_count = 0
        self.suspicious_count = 0
        self.large_count = 0
        self.unknown_count = 0
        self.entropy_count = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.ip_counts = defaultdict(int)
        self.sniffing = False
        self.log_lines = []

        # GenAI pipeline
        if transformers_available:
            self.genai = pipeline("text-generation", model="gpt2")
        else:
            self.genai = None

    def is_suspicious(self, payload):
        payload_lower = payload.lower()
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in payload_lower:
                return True, keyword.decode(errors='replace')
        return False, None

    def check_ports(self, packet):
        ports = []
        if TCP in packet:
            ports = [packet[TCP].sport, packet[TCP].dport]
        elif UDP in packet:
            ports = [packet[UDP].sport, packet[UDP].dport]
        for port in ports:
            if port in SUSPICIOUS_PORTS:
                return True, port
        return False, None

    def calculate_entropy(self, data):
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

    def packet_callback(self, packet):
        if not self.sniffing:
            return True  # Stop sniffing
        if IP in packet:
            self.packet_count += 1
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            proto = packet[IP].proto
            proto_name = {6: 'TCP', 17: 'UDP'}.get(proto, f"Unknown({proto})")
            payload = b""
            if Raw in packet:
                payload = packet[Raw].load
            timestamp = datetime.now().strftime("%H:%M:%S")
            line = f"[{timestamp}] {ip_src} -> {ip_dst} | {proto_name}"
            tag = "normal"
            alert_msgs = []

            # Protocol stats
            self.ip_counts[ip_src] += 1
            if proto_name == "TCP":
                self.tcp_count += 1
            elif proto_name == "UDP":
                self.udp_count += 1
            else:
                self.unknown_count += 1

            # Suspicious keyword detection
            if payload:
                suspicious, keyword = self.is_suspicious(payload)
                if suspicious:
                    alert_msgs.append(f"Suspicious keyword: '{keyword}'")
                    tag = "alert"
                    self.suspicious_count += 1
                try:
                    decoded_payload = payload[:32].decode(errors='replace')
                    self.text.insert(tk.END, f"\nPayload: {decoded_payload}", "payload")
                    self.log_lines.append(f"Payload: {decoded_payload}")
                except Exception:
                    self.text.insert(tk.END, f"\nPayload: {payload[:32]}", "payload")
                    self.log_lines.append(f"Payload: {payload[:32]}")

            # Large payload
            if len(payload) > 1000:
                alert_msgs.append(f"Large payload: {len(payload)} bytes")
                tag = "large"
                self.large_count += 1

            # High-entropy payload (AI feature)
            if payload:
                entropy = self.calculate_entropy(payload)
                if entropy > 5.0 and len(payload) > 20:
                    alert_msgs.append(f"High-entropy payload (entropy={entropy:.2f})")
                    tag = "entropy"
                    self.entropy_count += 1

            # Suspicious port detection
            port_flag, port = self.check_ports(packet)
            if port_flag:
                alert_msgs.append(f"Suspicious port: {port}")
                tag = "alert"

            # Unknown protocol
            if proto_name.startswith("Unknown"):
                alert_msgs.append(f"Unknown protocol: {proto}")
                tag = "alert"

            # Print main line
            self.text.insert(tk.END, f"\n{line}", tag)
            self.log_lines.append(line)
            # Print alerts
            for msg in alert_msgs:
                self.text.insert(tk.END, f"\n⚠️ {msg}", tag)
                self.log_lines.append(f"⚠️ {msg}")
            self.text.see(tk.END)
            # Update status bar
            self.status.config(
                text=f"Status: Sniffing | Packets: {self.packet_count} | Suspicious: {self.suspicious_count} | Large: {self.large_count} | High-entropy: {self.entropy_count}"
            )
        return False

    def start_sniffing(self):
        if not self.sniffing:
            self.sniffing = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.status.config(text="Status: Sniffing...")
            threading.Thread(target=self.sniff_packets, daemon=True).start()

    def sniff_packets(self):
        sniff(prn=self.packet_callback, store=0, filter="ip", stop_filter=lambda x: not self.sniffing)

    def stop(self):
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status.config(
            text=f"Status: Stopped | Packets: {self.packet_count} | Suspicious: {self.suspicious_count} | Large: {self.large_count} | High-entropy: {self.entropy_count}"
        )
        self.show_analysis()

    def save_log(self):
        with open("packet_sniffer_log.txt", "w", encoding="utf-8") as f:
            for line in self.log_lines:
                f.write(line + "\n")
        self.text.insert(tk.END, "\nLog saved to packet_sniffer_log.txt", "info")
        self.text.see(tk.END)

    def clear_output(self):
        self.text.delete(1.0, tk.END)
        self.log_lines.clear()

    def show_analysis(self):
        self.text.insert(tk.END, "\n\n--- Packet Analysis ---\n", "info")
        self.text.insert(tk.END, f"Total packets: {self.packet_count}\n", "info")
        self.text.insert(tk.END, f"Suspicious payloads: {self.suspicious_count}\n", "info")
        self.text.insert(tk.END, f"Large payloads: {self.large_count}\n", "info")
        self.text.insert(tk.END, f"High-entropy payloads: {self.entropy_count}\n", "info")
        self.text.insert(tk.END, f"TCP packets: {self.tcp_count}\n", "info")
        self.text.insert(tk.END, f"UDP packets: {self.udp_count}\n", "info")
        self.text.insert(tk.END, f"Unknown protocol packets: {self.unknown_count}\n", "info")
        # Top talkers
        self.text.insert(tk.END, "Top talkers (most frequent source IPs):\n", "info")
        for ip, count in sorted(self.ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
            self.text.insert(tk.END, f"  {ip}: {count} packets\n", "info")
        self.text.see(tk.END)

    def open_genai_window(self):
        win = tk.Toplevel(self.master)
        win.title("Generative AI Text")
        tk.Label(win, text="Enter prompt:").pack(padx=10, pady=5)
        prompt_entry = tk.Entry(win, width=80)
        prompt_entry.pack(padx=10, pady=5)
        output_box = ScrolledText(win, width=90, height=10)
        output_box.pack(padx=10, pady=5)

        def generate():
            prompt = prompt_entry.get()
            if not transformers_available or self.genai is None:
                output_box.insert(tk.END, "Transformers library not installed.\n")
                return
            output_box.insert(tk.END, "Generating...\n")
            win.update()
            try:
                results = self.genai(prompt, max_length=100, num_return_sequences=1)
                output_box.insert(tk.END, results[0]['generated_text'] + "\n")
            except Exception as e:
                output_box.insert(tk.END, f"Error: {e}\n")

        gen_btn = tk.Button(win, text="Generate", command=generate, bg="orange")
        gen_btn.pack(pady=5)

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()