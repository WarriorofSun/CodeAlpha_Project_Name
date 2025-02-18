**Network Sniffer in Python 🕵️‍♂️📡**
**Overview**
This project is a basic network sniffer built using Python and Scapy. It captures and analyzes network traffic in real time, helping users understand how data flows on a network and how network packets are structured.

**Features 🚀**
✅ Captures live network packets 📡
✅ Extracts source & destination IPs 🌍
✅ Identifies protocols (TCP, UDP, ICMP) 📦
✅ Supports multiple network interfaces 🌐
✅ Runs on Windows 🖥️

**How It Works 🛠️**
The program sniffs incoming and outgoing network packets.
It extracts key details such as IP addresses and protocol types.
The output is displayed in the terminal, showing real-time traffic analysis.

**Installation & Setup 🏗️**
1️⃣ _Install Python_
Make sure you have Python 3.x installed. You can download it from python.org.

**2️⃣ Install Dependencies**
_Run the following command to install Scapy:_
pip install scapy

**3️⃣ Run the Sniffer**
_Execute the script using:_
python network_sniffer.py

_If you need admin privileges, run:_
sudo python network_sniffer.py  # For Linux/macOS

_powershell:_
python network_sniffer.py       # For Windows (Run as Administrator)

**Code Explanation 📜**
Here’s the core part of the network sniffer:

from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "ICMP" if packet.haslayer(ICMP) else "Other"
        
        print(f"Source: {src_ip} -> Destination: {dst_ip} | Protocol: {protocol}")

# List available network interfaces
print("Available Interfaces:", get_if_list())

# Sniff packets on the default network interface
sniff(prn=packet_callback, store=False)

**How It Works:**
📌 Lists available network interfaces.
📌 Captures packets in real time.
📌 Extracts source & destination IPs.
📌 Identifies the protocol type (TCP, UDP, ICMP).

**Example Output 🖥️**
Available Interfaces: ['Ethernet', 'Wi-Fi', 'VMware Network Adapter', 'Loopback']
Source: 192.168.1.5 -> Destination: 142.250.182.99 | Protocol: TCP
Source: 192.168.1.5 -> Destination: 8.8.8.8 | Protocol: UDP
Source: 192.168.1.1 -> Destination: 192.168.1.5 | Protocol: ICMP

**Use Cases 🎯**
🔹 Network monitoring 🖥️
🔹 Packet analysis 📊
🔹 Cybersecurity learning 🔐
🔹 Identifying suspicious traffic 🚨

**Limitations & Improvements 🚧**
❌ Requires admin/root privileges.
❌ Only captures unencrypted traffic.
✅ Can be improved by logging packets to a file.
✅ Can add deep packet inspection for more details.

**Contributing🤝**
_If you’d like to improve this project, feel free to:_
1. Fork the repository 🔄
2. Create a branch (_git checkout -b new-feature_) 🌿
3. Commit changes (_git commit -m "Added feature"_) 💾
4. Push to GitHub (_git push origin new-feature_) 🚀
5. Open a Pull Request
   
**License 📜**
This project is open-source under the MIT License.

📢 Feel free to ⭐ star this repository if you find it useful!
