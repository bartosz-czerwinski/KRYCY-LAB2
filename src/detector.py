from nfstream import NFStreamer
import pandas as pd
from datetime import datetime
from matplotlib import pyplot as plt
from matplotlib.ticker import MaxNLocator

INPUT_FILE = "scenario_5min.pcap"

class MaliciousDetector:
    @staticmethod
    def detect_exfiltration(flow):
        """Wykrywa duży transfer wychodzący."""
        if flow.src2dst_bytes > 1_000_000:
            if not flow.dst_ip.startswith("192.168.") and not flow.dst_ip.startswith("10."):
                return f"EXFILTRATION (>1MB)"

    @staticmethod
    def detect_protocol_mismatch(flow):
        """Wykrywa ukrywanie usług (SSH na 80)."""
        if not flow.application_name:
            return None

        if flow.dst_port == 80 and 'SSH' in flow.application_name:
            return f"PROTOCOL_MISMATCH (SSH on HTTP)"
        return None

    @staticmethod
    def detect_dns_tunneling(flow):
        """Wykrywa tunelowanie w DNS (duży wolumen)."""
        if flow.protocol == 17 and flow.dst_port == 53:
            if flow.bidirectional_bytes > 10000:
                return "DNS_TUNNELING"
        return None

    @staticmethod
    def analyze_flow(flow):
        """Orkiestrator reguł - sprawdza wszystkie po kolei"""
        
        checks = [
            MaliciousDetector.detect_exfiltration,
            MaliciousDetector.detect_protocol_mismatch,
            MaliciousDetector.detect_dns_tunneling,
        ]
        
        for check in checks:
            alert = check(flow)
            if alert:
                return alert 
        return "SAFE"

def analyze_and_plot():
    print(f"[*] Analiza pliku: {INPUT_FILE}...")
    
    streamer = NFStreamer(source=INPUT_FILE, statistical_analysis=True)
    
    alerts = []
    
    for flow in streamer:
        verdict = MaliciousDetector.analyze_flow(flow)
        
        if verdict != "SAFE":
            print(f"[ALARM] {verdict} | {flow.src_ip} -> {flow.dst_ip}")
            alerts.append({
                'timestamp': datetime.fromtimestamp(flow.bidirectional_first_seen_ms / 1000.0),
                'alert_type': verdict,
                'count': 1
            })

    if not alerts:
        print("Nie wykryto żadnych zagrożeń.")
        return

    df = pd.DataFrame(alerts)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df.set_index('timestamp', inplace=True)
    df_grouped = df.groupby('alert_type').resample('15S')['count'].sum().unstack(level=0).fillna(0)

    ax = df_grouped.plot(kind='bar', stacked=True, figsize=(12, 6), rot=0)
    ax.yaxis.set_major_locator(MaxNLocator(integer=True))

    step = 2 
    
    ticks = range(0, len(df_grouped.index), step)
    ax.set_xticks(ticks)

    labels = [item.strftime('%H:%M:%S') for item in df_grouped.index[::step]]
    
    ax.set_xticklabels(labels, rotation=45, ha='right')
    
    plt.title('Wykryte ataki w czasie (interwał 15s)')
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    analyze_and_plot()