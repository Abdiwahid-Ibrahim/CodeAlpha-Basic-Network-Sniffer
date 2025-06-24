from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def packet_callback(packet):
    # Display the basic packet details
    print("\n=== Packet Captured ===")
    
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")
        
        # Check if it's TCP/UDP/ICMP and display ports or type
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"TCP Segment | Src Port: {tcp_layer.sport} -> Dst Port: {tcp_layer.dport}")
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"UDP Datagram | Src Port: {udp_layer.sport} -> Dst Port: {udp_layer.dport}")
        elif ICMP in packet:
            print("ICMP Packet")
        
        # Display raw payload if available
        if Raw in packet:
            payload = packet[Raw].load
            try:
                print("Payload:", payload.decode('utf-8', errors='replace'))
            except Exception as e:
                print("Payload (raw):", payload)
    else:
        print("Non-IP packet detected")

# Start sniffing
print("Starting packet capture... Press Ctrl+C to stop.\n")
sniff(prn=packet_callback, store=False)