from scapy.all import sniff, IP, TCP, UDP, ICMP
from scapy.arch.windows import get_windows_if_list

# List available interfaces
interfaces = get_windows_if_list()
print("Available Interfaces:", [iface['name'] for iface in interfaces])


def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "ICMP" if packet.haslayer(
            ICMP) else "Other"

        print(f"Source: {src_ip} -> Destination: {dst_ip} | Protocol: {protocol}")


# Sniff packets on a specific interface (replace "Wi-Fi" with your actual interface name)
sniff(iface="Wi-Fi", prn=packet_callback, store=False)
