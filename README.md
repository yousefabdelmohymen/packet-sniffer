from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        
        # Check the protocol
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print(f"Protocol: TCP")
            print(f"Source Port: {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print(f"Protocol: UDP")
            print(f"Source Port: {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")
        
        # Optionally, display payload data
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"Payload: {payload}")
        
        print("\n")

# Capture packets
def start_sniffing(interface):
    print(f"Starting packet capture on interface {interface}...")
    sniff(iface=interface, prn=packet_callback, store=0)

if __name__ == "__main__":
    # Replace 'eth0' with the appropriate network interface
    interface = 'eth0'
    start_sniffing(interface)
