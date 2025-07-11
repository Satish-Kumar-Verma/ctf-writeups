---
title: "Modbus Register Exfiltration"
date: 2025-07-11
platform: TryHackMe
event: Industrial CTF 2025
category: Network Forensics
difficulty: Medium
tags: [Modbus, PCAP, Scapy, Network Forensics, Beginner-Friendly]
---

## 📝 Challenge Overview
In this challenge, we analyze a PCAP file named `rogue-poller-1750969333044.pcapng` that contains Modbus/TCP traffic (port 502). An attacker scanned a Programmable Logic Controller (PLC) to read its memory registers. Our goal is to extract a hidden flag in the format `THM{...}` from the register responses.

## 🔍 Tools & Key Concepts
- **Wireshark**: A graphical tool to inspect network traffic.
- **Modbus/TCP**: Protocol for communication with PLC registers over TCP port 502.
- **Scapy**: A Python library for packet manipulation and analysis.
- **PCAP**: Packet Capture file format.

## 🚀 Step-by-Step Solution
1. **Open the PCAP in Wireshark**  
   - Launch Wireshark and open `rogue-poller-1750969333044.pcapng`. (present in the assets/tryhackme/industrial-ctf-2025)
   - You will see many network packets; we only need Modbus/TCP packets.

2. **Filter for Modbus/TCP Traffic**  
   - In the Wireshark filter bar, type `tcp.port == 502` and press Enter.  
   - This filter shows only packets sent to or from port 502 (Modbus).

3. **Write a Python Extraction Script**  
   - Create a new file named `extract_flag.py` and add the following code:
   ```python
   from scapy.all import rdpcap, TCP, Raw
   import re

   # Read all packets from the PCAP file
   packets = rdpcap('rogue-poller-1750969333044.pcapng')
   data = bytearray()

   for pkt in packets:
       # Consider only packets with TCP and Raw payload
       if TCP in pkt and Raw in pkt:
           # Check source or destination port 502 for Modbus
           if pkt[TCP].sport == 502 or pkt[TCP].dport == 502:
               payload = pkt[Raw].load
               # Byte 7: function code (3 or 4 = Read Registers)
               if payload[7] in (3, 4):
                   # Byte 8: number of data bytes
                   count = payload[8]
                   # Bytes 9 to 9+count: register values
                   data.extend(payload[9:9 + count])

   # Decode to ASCII and search for flag
   text = data.decode('ascii', errors='ignore')
   match = re.search(r'THM\{.*?\}', text)
   if match:
       print('Flag found:', match.group(0))
   else:
       print('Flag not found')
   ```

4. **Run the Script**  
   ```bash
   python3 extract_flag.py
   ```
   - The script will print the flag, for example: `THM{industrial_data_leak}`.

## 🚩 Flag
```
THM{industrial_data_leak}
```

## 💡 Lessons Learned
- How to filter and interpret Modbus/TCP packets in Wireshark.
- How to use Scapy to automate PCAP parsing.
- Basics of extracting and decoding data from network traffic.
