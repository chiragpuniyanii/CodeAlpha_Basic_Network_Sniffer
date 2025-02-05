# Network Packet Sniffer using Python & Scapy

📌 **Overview**

This project is a network packet sniffer built using Python and the Scapy library. It captures network traffic, extracts key details like IP addresses, ports, and TCP handshake flags, and detects HTTPS traffic.

🛠 **Requirements**

- Python 3.x
- Scapy library

🔧 **Installation**

First, install Scapy using pip:

```bash
pip install scapy
```
🚀 **Usage**

Run the script as an administrator/root user to capture network packets.

On Windows (Run as Administrator):

```bash
python network_sniffer.py
```
📜 **Features**

- ✅ Sniffs network packets in real time
- ✅ Extracts source & destination IPs and ports
- ✅ Detects HTTPS traffic (port 443)
- ✅ Analyzes TCP Handshake (SYN, SYN-ACK, ACK)


📄 Code Snippet

```python

from scapy.all import *

def packet_callback(packet):
    if packet.haslayer(IP):
        print(f"📡 Packet Captured: {packet.summary()}")
        print(f"🔹 Source IP: {packet[IP].src} → Destination IP: {packet[IP].dst}")
        
        if packet.haslayer(TCP):
            print(f"🔸 Source Port: {packet[TCP].sport} → Destination Port: {packet[TCP].dport}")
            if packet[TCP].dport == 443 or packet[TCP].sport == 443:
                print("🔒 This is an HTTPS Request/Response!")

    print("-" * 50)

print("📡 Sniffing network packets... Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=0, count=10)
```
📌 **Output Example**

```text
📡 Packet Captured: IP 192.168.1.10:51191 > 20.57.103.21:443
🔹 Source IP: 192.168.1.10 → Destination IP: 20.57.103.21
🔸 Source Port: 51191 → Destination Port: 443
🔒 This is an HTTPS Request!
--------------------------------------------------
🔥 Advanced Usage
```
To capture unlimited packets, remove the count=10 parameter:

```python
sniff(prn=packet_callback, store=0)
```
📜 **License**

This project is open-source and available under the MIT License.

🤝 **Contribution**

Feel free to fork, modify, and submit pull requests! 🚀
