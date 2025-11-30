from scapy.all import IP, TCP, Raw, send
import time
import random

# --- KONFIGURACJA SYMULACJI ---

# Nasz "chroniony" serwer (wymyślone IP, ale celujemy w nie)
SERVER_IP = "10.0.0.50" 

# Pula adresów IP "Pracowników" (Ruch normalny)
EMPLOYEE_IPS = ["192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.55"]

# Pula adresów IP "Atakujących" (Ruch złośliwy - udajemy obce kraje)
ATTACKER_IPS = ["45.33.22.11", "185.200.10.1", "103.55.44.22"]

def get_random_src(ip_list):
    return random.choice(ip_list)

def generate_normal_traffic():
    """Pracownik łączy się z serwerem HTTP"""
    src_ip = get_random_src(EMPLOYEE_IPS)
    print(f"[+] Normalny ruch: {src_ip} -> {SERVER_IP}:80")
    
    pkt = IP(src=src_ip, dst=SERVER_IP)/TCP(dport=80, flags="PA")/Raw(load="GET /invoice.pdf HTTP/1.1\r\n")
    send(pkt, verbose=0, iface="lo")

def generate_malicious_traffic():
    """Atakujący robi SYN Flood na serwer"""
    src_ip = get_random_src(ATTACKER_IPS)
    print(f"[!] ATAK: {src_ip} -> {SERVER_IP}:6666")
    
    for _ in range(10): # Krótka seria
        pkt = IP(src=src_ip, dst=SERVER_IP)/TCP(sport=random.randint(1024, 65535), dport=6666, flags="S")
        send(pkt, verbose=0, iface="lo")
        time.sleep(0.01)

if __name__ == "__main__":
    print("--- Start Symulatora Sieci (Spoofing IP) ---")
    print("Wysyłanie pakietów na interfejs loopback ('lo')...")
    
    try:
        while True:
            # Losujemy co się dzieje w sieci
            if random.random() < 0.7: # 70% szans na normalny ruch
                generate_normal_traffic()
            else:
                generate_malicious_traffic()
            
            time.sleep(random.uniform(0.5, 1.5))
            
    except KeyboardInterrupt:
        print("\nZatrzymano symulację.")