from scapy.all import sniff, IP, TCP, UDP
from collections import Counter, defaultdict
from datetime import datetime
import threading
import time
from rich.console import Console
from rich.table import Table

traffic_counter = Counter()
ip_counter = defaultdict(int)
console = Console()

LOG_FILE = "logs/alerts.log"

def log_alert(message):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.now()} - {message}\n")

def process_packet(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto

        ip_counter[src] += 1
        traffic_counter[proto] += 1

        if ip_counter[src] > 100:  # Threshold for suspicious traffic
            log_alert(f"Suspicious activity from {src}")
            console.print(f"[bold red]Alert: Suspicious traffic from {src}[/]")

def start_sniffing():
    sniff(prn=process_packet, store=0)

def show_live_stats():
    while True:
        time.sleep(5)
        console.clear()
        table = Table(title="📡 Live Network Traffic Stats")
        table.add_column("Protocol", justify="center")
        table.add_column("Count", justify="center")

        proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}

        for proto, count in traffic_counter.items():
            name = proto_map.get(proto, f"Other({proto})")
            table.add_row(name, str(count))

        console.print(table)

        top_ips = sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)[:5]
        console.print("\n[bold]Top 5 Source IPs:[/]")
        for ip, count in top_ips:
            console.print(f"{ip}: {count} packets")

if __name__ == "__main__":
    console.print("[bold green]Starting Python Network Monitor...[/]")
    threading.Thread(target=show_live_stats, daemon=True).start()
    start_sniffing()
