from scapy.all import IP, TCP, UDP, Raw
from scapy.utils import PcapWriter
import random
from datetime import datetime
import os

OUTPUT_FILE = "scenario_5min.pcap"
DURATION = 300  # 5 minut
SERVER_IP = "10.0.0.50"
PUBLIC_IP = "45.33.22.11"

random.seed(42)
if os.path.exists(OUTPUT_FILE):
    os.remove(OUTPUT_FILE)
    print(f"Usunięto stary plik {OUTPUT_FILE}.")

print(f"Generowanie testowego pliku PCAP: {OUTPUT_FILE}...")

base_time = datetime.now().replace(hour=12, minute=0, second=0, microsecond=0).timestamp()

def make_background(t):
    pkts = []
    src = f"192.168.1.{random.randint(100, 200)}"
    sport = random.randint(30000, 60000)
    p1 = IP(src=src, dst=SERVER_IP)/TCP(sport=sport, dport=443, flags="PA", seq=100, ack=100)/Raw(load="GET /bg HTTP/1.1\r\n")
    p1.time = t
    p2 = IP(src=SERVER_IP, dst=src)/TCP(sport=443, dport=sport, flags="PA", seq=100, ack=120)/Raw(load="HTTP/1.1 200 OK\r\n")
    p2.time = t + 0.02
    pkts.extend([p1, p2])
    return pkts

def make_ssh_mismatch(t):
    pkts = []
    attacker = "192.168.1.66"
    sport = random.randint(10000, 60000)
    syn = IP(src=attacker, dst=SERVER_IP)/TCP(sport=sport, dport=80, flags="S", seq=1000)
    synack = IP(src=SERVER_IP, dst=attacker)/TCP(sport=80, dport=sport, flags="SA", seq=5000, ack=1001)
    ack = IP(src=attacker, dst=SERVER_IP)/TCP(sport=sport, dport=80, flags="A", seq=1001, ack=5001)
    payload = IP(src=attacker, dst=SERVER_IP)/TCP(sport=sport, dport=80, flags="PA", seq=1001, ack=5001)/Raw(load="SSH-2.0-OpenSSH_Fixed\r\n")
    syn.time = t; synack.time = t+0.01; ack.time = t+0.02; payload.time = t+0.03
    pkts.extend([syn, synack, ack, payload])
    return pkts

def make_dns_tunnel(t):
    pkts = []
    src = "192.168.1.77"
    sport = random.randint(10000, 60000)
    data = "FIXED_TUNNEL" * 1000
    req = IP(src=src, dst="8.8.8.8")/UDP(sport=sport, dport=53)/Raw(load=data)
    req.time = t
    resp = IP(src="8.8.8.8", dst=src)/UDP(sport=53, dport=sport)/Raw(load=data)
    resp.time = t + 0.05
    pkts.extend([req, resp])
    return pkts

def make_exfiltration(t):
    pkts = []
    src = "192.168.1.88"
    sport = random.randint(10000, 60000)
    payload = "Z" * 1400
    count = 750
    for i in range(count):
        p = IP(src=src, dst=PUBLIC_IP)/TCP(sport=sport, dport=443, flags="PA", seq=i*1400)/Raw(load=payload)
        p.time = t + (i * 0.001)
        pkts.append(p)
    return pkts

with PcapWriter(OUTPUT_FILE, append=False, sync=False) as dumper:
    
    for t in range(DURATION):
        now = base_time + t
        packets_batch = []
        
        # 1. Tło (co 2 sekundy)
        if t % 2 == 0:
            packets_batch.extend(make_background(now))

        # 2. SSH Mismatch (co 45 sekund)
        if t % 45 == 0:
            packets_batch.extend(make_ssh_mismatch(now))

        # 3. DNS Tunnel (co 70 sekund)
        if t % 70 == 0:
            packets_batch.extend(make_dns_tunnel(now))

        # 4. Exfiltration (W 100. i 250. sekundzie testu)
        if t == 100 or t == 250:
            packets_batch.extend(make_exfiltration(now))

        packets_batch.sort(key=lambda x: x.time)
        for p in packets_batch:
            dumper.write(p)
            
        if t % 60 == 0:
            print(f" -> Postęp: {t//60} min / 5 min")

print(f"Plik {OUTPUT_FILE} wygenerowany pomyślnie.")