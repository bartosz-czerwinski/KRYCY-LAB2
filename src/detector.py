from nfstream import NFStreamer
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from datetime import datetime
import signal
import sys

class MaliciousDetector:
    """Klasa przechowująca logikę detekcji"""
    
    @staticmethod
    def is_syn_scan(flow):
        """
        Wykrywa podejrzane przepływy TCP, które mają tylko flagę SYN 
        (brak nawiązania połączenia) i celują w nasz 'złośliwy' port.
        """
        if flow.protocol != 6:
            return False
            
        if flow.dst_port == 6666:
            return True
            
        return False

    @staticmethod
    def analyze_flow(flow):
        """Główna funkcja oceniająca przepływ"""
        if MaliciousDetector.is_syn_scan(flow):
            return "MALICIOUS_SYN_FLOOD"
        return "BENIGN"

detected_alerts = []

def process_traffic(interface_name="lo"):
    print(f"[*] Nasłuchiwanie na interfejsie: {interface_name}...")
    print("[*] Naciśnij Ctrl+C, aby zakończyć zbieranie i wygenerować wykres.")

    # NFStreamer nasłuchuje na żywo
    # statistical_analysis=True zapewnia dodatkowe metryki
    my_streamer = NFStreamer(source=interface_name, 
                             statistical_analysis=True) 

    try:
        for flow in my_streamer:
            verdict = MaliciousDetector.analyze_flow(flow)
            
            if verdict != "BENIGN":
                print(f"[ALARM] Wykryto: {verdict} | Src: {flow.src_ip} -> Dst: {flow.dst_port}")
                
                detected_alerts.append({
                    'timestamp': datetime.fromtimestamp(flow.bidirectional_first_seen_ms / 1000.0),
                    'alert_type': verdict,
                    'dst_port': flow.dst_port,
                    'packets': flow.bidirectional_packets
                })
                
    except KeyboardInterrupt:
        print("\n[!] Zatrzymano zbieranie danych. Generowanie raportu...")
        generate_report()

def generate_report():
    if not detected_alerts:
        print("Brak alertów do wyświetlenia.")
        sys.exit(0)

    #Tworzenie DataFrame z alertami
    df = pd.DataFrame(detected_alerts)
    df.set_index('timestamp', inplace=True)
    alerts_over_time = df.resample('1S').count()['alert_type']

    #Tworzenie wykresu
    plt.figure(figsize=(12, 6))
    
    plt.plot(alerts_over_time.index, alerts_over_time.values, 
             marker='o', linestyle='-', color='red', label='Liczba alertów')
    
    plt.title('Detekcja złośliwych przepływów w czasie rzeczywistym', fontsize=16)
    plt.xlabel('Czas', fontsize=12)
    plt.ylabel('Liczba wykrytych incydentów', fontsize=12)
    
    # Formatowanie osi czasu
    plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
    plt.gcf().autofmt_xdate()
    
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.legend()
    
    # Wyświetlenie lub zapisanie
    print("[*] Wyświetlanie wykresu...")
    plt.show()
    sys.exit(0)

if __name__ == "__main__":
    process_traffic(interface_name="lo")