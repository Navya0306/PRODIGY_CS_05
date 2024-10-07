from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

# Function to handle captured packets
def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        
        # Extracting information from IP layer
        source_ip = ip_layer.src
        destination_ip = ip_layer.dst
        protocol = ip_layer.proto
        
        print(f"[+] Packet: {source_ip} -> {destination_ip} | Protocol: {protocol}", end="")

        # Check if it's a TCP, UDP or ICMP packet for additional analysis
        if TCP in packet:
            print(f" | TCP | Source Port: {packet[TCP].sport} | Destination Port: {packet[TCP].dport}")
        elif UDP in packet:
            print(f" | UDP | Source Port: {packet[UDP].sport} | Destination Port: {packet[UDP].dport}")
        elif ICMP in packet:
            print(f" | ICMP | Type: {packet[ICMP].type} | Code: {packet[ICMP].code}")
        
        # Optionally, display payload data (comment out if not needed)
        if packet.haslayer(Raw):
            print(f" | Payload: {bytes(packet[Raw].load)}")
        else:
            print()
    else:
        print("[-] Non-IP packet captured.")

# Start the packet sniffer (ensure to specify the correct network interface)
if __name__ == "__main__":
    print("Starting packet sniffer...")
    sniff(filter="ip", prn=packet_callback, store=0)