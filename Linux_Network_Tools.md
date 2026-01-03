## Connect and Listen

### `nc` (Netcat)

#### Connect
Connect to a specific host/port:
```bash
nc <ip> <port>
UDP connect: nc -u <ip> <port>  
```

**Examples:**
```bash
# Connect to web server
nc google.com 80

# Connect to SSH server
nc 192.168.1.100 22
```

#### Disconnect Options
```bash
# Auto disconnect after sending data (Ctrl + D)
nc -q 0 <ip> <port>
# -q 0: wait 0 seconds before closing connection
```

**Example:**
```bash
# Send HTTP request and close immediately
echo -e "GET / HTTP/1.0\r\n\r\n" | nc -q 0 google.com 80
```

#### Listen Mode
Open a port to listen for connections:
```bash
nc -l <port>
```

**Practical Examples:**

1. **Simple chat between 2 machines:**
   ```bash
   # Machine A (Server - listening)
   nc -l 1234
   
   # Machine B (Client - connecting)
   nc <machine_A_ip> 1234
   ```

2. **File transfer:**
   ```bash
   # Receiving machine (Server)
   nc -l 1234 > received_file.txt
   
   # Sending machine (Client)
   nc <server_ip> 1234 < file_to_send.txt
   ```

3. **Port scanning:**
   ```bash
   # Scan a single port
   nc -zv 192.168.1.1 22
   
   # Scan port range
   nc -zv 192.168.1.1 20-100
   ```

4. **Simple web server:**
   ```bash
   # Serve an HTML file
   while true; do nc -l 8080 < index.html; done
   ```

#### Useful Options
```bash
-v          # Verbose mode
-z          # Zero-I/O mode (scanning)
-u          # UDP mode (default is TCP)
-w timeout  # Connection timeout
-k          # Keep listening (multiple connections)
```

---

## Network Configuration

### `iptables` - Firewall Configuration

#### Basic Structure
```bash
iptables [-t table] -[A|I|D] chain rule-specification
```

#### Main Tables
- **filter**: Default table for firewall (INPUT, OUTPUT, FORWARD)
- **nat**: Network Address Translation (PREROUTING, POSTROUTING)
- **mangle**: Modify packet headers
- **raw**: Configuration exemptions

#### Basic Examples

1. **View current rules:**
   ```bash
   # View all rules
   sudo iptables -L -v -n
   
   # View rules with line numbers
   sudo iptables -L --line-numbers
   ```

2. **Allow traffic:**
   ```bash
   # Allow SSH (port 22)
   sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
   
   # Allow HTTP and HTTPS
   sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
   sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
   
   # Allow ping
   sudo iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
   ```

3. **Block traffic:**
   ```bash
   # Block specific IP
   sudo iptables -A INPUT -s 192.168.1.100 -j DROP
   
   # Block a subnet
   sudo iptables -A INPUT -s 192.168.1.0/24 -j DROP
   
   # Block outgoing traffic to a port
   sudo iptables -A OUTPUT -p tcp --dport 25 -j DROP
   ```

4. **Prevent DoS attacks:**
   ```bash
   # Limit new connections (anti-SYN flood)
   sudo iptables -A INPUT -p tcp --syn -m limit --limit 1/s -j ACCEPT
   
   # Limit connections from one IP
   sudo iptables -A INPUT -p tcp --syn --dport 80 -m connlimit \
     --connlimit-above 20 -j REJECT
   ```

5. **NAT and Port Forwarding:**
   ```bash
   # Port forwarding (redirect port 80 -> 8080)
   sudo iptables -t nat -A PREROUTING -p tcp --dport 80 \
     -j REDIRECT --to-port 8080
   
   # Masquerade (internet sharing)
   sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
   ```

6. **Complete basic firewall setup:**
   ```bash
   # Flush all old rules
   sudo iptables -F
   
   # Default policy: DROP everything
   sudo iptables -P INPUT DROP
   sudo iptables -P FORWARD DROP
   sudo iptables -P OUTPUT ACCEPT
   
   # Allow loopback
   sudo iptables -A INPUT -i lo -j ACCEPT
   
   # Allow established connections
   sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
   
   # Allow SSH from local network
   sudo iptables -A INPUT -p tcp -s 192.168.1.0/24 --dport 22 -j ACCEPT
   
   # Allow HTTP/HTTPS
   sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
   sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
   ```

7. **Save and restore rules:**
   ```bash
   # Save rules (Ubuntu/Debian)
   sudo iptables-save > /etc/iptables/rules.v4
   
   # Restore rules
   sudo iptables-restore < /etc/iptables/rules.v4
   
   # CentOS/RHEL
   sudo service iptables save
   ```

8. **Delete rules:**
   ```bash
   # Delete specific rule by line number
   sudo iptables -D INPUT 3
   
   # Delete all rules in chain
   sudo iptables -F INPUT
   
   # Reset to default
   sudo iptables -F
   sudo iptables -X
   sudo iptables -P INPUT ACCEPT
   sudo iptables -P FORWARD ACCEPT
   sudo iptables -P OUTPUT ACCEPT
   ```

---

### `ip` - Configure Network Interfaces

Cheat sheet: https://access.redhat.com/sites/default/files/attachments/rh_ip_command_cheatsheet_1214_jcs_print.pdf

#### Replacement for ifconfig
The `ip` command is a modern tool that replaces `ifconfig`, `route`, `arp`.

#### Basic Examples

1. **View interface information:**
   ```bash
   # List all interfaces
   ip link show
   ip a         # short for 'ip address show'
   
   # View specific interface
   ip addr show eth0
   
   # IPv4 only
   ip -4 addr show
   
   # IPv6 only
   ip -6 addr show
   ```

2. **Enable/Disable interface:**
   ```bash
   # Enable interface
   sudo ip link set eth0 up
   
   # Disable interface
   sudo ip link set eth0 down
   ```

3. **Configure IP address:**
   ```bash
   # Add IP address
   sudo ip addr add 192.168.1.100/24 dev eth0
   
   # Delete IP address
   sudo ip addr del 192.168.1.100/24 dev eth0
   
   # Flush all IPs on interface
   sudo ip addr flush dev eth0
   ```

4. **Routing:**
   ```bash
   # View routing table
   ip route show
   ip r        # short version
   
   # Add default gateway
   sudo ip route add default via 192.168.1.1
   
   # Add specific route
   sudo ip route add 10.0.0.0/8 via 192.168.1.254 dev eth0
   
   # Delete route
   sudo ip route del 10.0.0.0/8
   
   # View route to an IP
   ip route get 8.8.8.8
   ```

5. **ARP table:**
   ```bash
   # View ARP cache
   ip neigh show
   ip n        # short version
   
   # Add static ARP entry
   sudo ip neigh add 192.168.1.100 lladdr 00:11:22:33:44:55 dev eth0
   
   # Delete ARP entry
   sudo ip neigh del 192.168.1.100 dev eth0
   
   # Flush ARP cache
   sudo ip neigh flush all
   ```

6. **Statistics:**
   ```bash
   # View interface statistics
   ip -s link show eth0
   
   # More detailed view
   ip -s -s link show eth0
   ```

7. **Complete interface configuration:**
   ```bash
   # Enable interface
   sudo ip link set eth0 up
   
   # Set IP and netmask
   sudo ip addr add 192.168.1.100/24 dev eth0
   
   # Add default gateway
   sudo ip route add default via 192.168.1.1
   
   # Set DNS (need to edit /etc/resolv.conf)
   echo "nameserver 8.8.8.8" | sudo tee -a /etc/resolv.conf
   ```

8. **Virtual interfaces (aliases):**
   ```bash
   # Create virtual interface
   sudo ip addr add 192.168.1.101/24 dev eth0 label eth0:1
   
   # View virtual interfaces
   ip addr show eth0
   ```

9. **Change MAC address:**
   ```bash
   # Disable interface first
   sudo ip link set dev eth0 down
   
   # Change MAC
   sudo ip link set dev eth0 address 00:11:22:33:44:55
   
   # Enable interface again
   sudo ip link set dev eth0 up
   ```

---

## Network Monitoring

### `Wireshark` - GUI Packet Analyzer

#### Introduction
Wireshark is a powerful packet analysis tool with a graphical interface.

#### Installation
```bash
# Ubuntu/Debian
sudo apt install wireshark

# CentOS/RHEL
sudo yum install wireshark wireshark-gnome

# Allow regular user to capture
sudo usermod -aG wireshark $USER
```

#### Display Filters (Common Filters)

```
# Protocol filters
http                    # HTTP traffic only
tcp                     # TCP packets only
udp                     # UDP packets only
dns                     # DNS queries/responses
ssh                     # SSH traffic

# IP filters
ip.addr == 192.168.1.1         # Traffic from/to this IP
ip.src == 192.168.1.1          # Source IP
ip.dst == 192.168.1.1          # Destination IP
ip.addr == 192.168.1.0/24      # Subnet

# Port filters
tcp.port == 80                  # Port 80 (HTTP)
tcp.dstport == 443              # Destination port 443
tcp.srcport == 22               # Source port 22

# Combine filters
http && ip.addr == 192.168.1.1  # HTTP traffic from/to IP
tcp.port == 80 || tcp.port == 443  # HTTP or HTTPS

# Content filters
http.request.method == "POST"   # HTTP POST requests
http.host contains "google"     # HTTP host contains "google"
tcp contains "password"         # TCP payload contains "password"Ether type=0xFFFF

# Status codes
http.response.code == 404       # HTTP 404 errors
http.response.code >= 400       # All HTTP errors
```

#### Capture Filters (BPF syntax)
```
# Capture specific host
host 192.168.1.1

# Capture specific port
port 80

# Capture range
portrange 1-1024

# Network
net 192.168.1.0/24

# Combinations
host 192.168.1.1 and port 80
tcp and not port 22
```

#### Practical Usage

1. **Capture HTTP passwords:**
   - Filter: `http.request.method == "POST"`
   - Follow TCP Stream to view form data

2. **Analyze DNS:**
   - Filter: `dns`
   - View DNS queries and responses

3. **Debug slow connections:**
   - Statistics → Flow Graph
   - View TCP handshake and timing

4. **Export objects:**
   - File → Export Objects → HTTP
   - Extract files downloaded via HTTP

---

### `tcpdump` - Command-line Packet Analyzer

#### Basic Syntax
```bash
tcpdump [options] [filter expression]
```

#### Basic Examples

1. **Simple capture:**
   ```bash
   # Capture all traffic on default interface
   sudo tcpdump
   
   # Capture on specific interface
   sudo tcpdump -i eth0
   
   # Capture on all interfaces
   sudo tcpdump -i any
   ```

2. **Useful options:**
   ```bash
   -n          # Don't resolve hostnames
   -nn         # Don't resolve hostnames and port names
   -v, -vv, -vvv   # Verbose levels
   -c 100      # Capture 100 packets then stop
   -A          # Print packet in ASCII
   -X          # Print packet in hex and ASCII
   -w file.pcap    # Write to file
   -r file.pcap    # Read from file
   -s 0        # Capture full packet (snaplen)
   ```

3. **Filter by protocol:**
   ```bash
   # TCP only
   sudo tcpdump tcp
   
   # UDP only
   sudo tcpdump udp
   
   # ICMP (ping)
   sudo tcpdump icmp
   ```

4. **Filter by host:**
   ```bash
   # Traffic from/to specific host
   sudo tcpdump host 192.168.1.100
   
   # Source host
   sudo tcpdump src host 192.168.1.100
   
   # Destination host
   sudo tcpdump dst host 192.168.1.100
   
   # Network
   sudo tcpdump net 192.168.1.0/24
   ```

5. **Filter by port:**
   ```bash
   # Specific port
   sudo tcpdump port 80
   
   # Source port
   sudo tcpdump src port 1234
   
   # Destination port
   sudo tcpdump dst port 443
   
   # Port range
   sudo tcpdump portrange 21-23
   ```

6. **Combine filters:**
   ```bash
   # AND
   sudo tcpdump host 192.168.1.1 and port 80
   
   # OR
   sudo tcpdump port 80 or port 443
   
   # NOT
   sudo tcpdump not port 22
   
   # Complex
   sudo tcpdump 'host 192.168.1.1 and (port 80 or port 443)'
   ```

7. **Practical examples:**

   **a) Capture HTTP traffic:**
   ```bash
   sudo tcpdump -i eth0 -nn -A 'tcp port 80'
   ```

   **b) Capture DNS queries:**
   ```bash
   sudo tcpdump -i any -nn port 53
   ```

   **c) Capture and save to file:**
   ```bash
   # Capture and write to file
   sudo tcpdump -i eth0 -w capture.pcap
   
   # Read from file
   tcpdump -r capture.pcap
   
   # Filter when reading file
   tcpdump -r capture.pcap 'port 80'
   ```

   **d) Monitor traffic between 2 hosts:**
   ```bash
   sudo tcpdump host 192.168.1.1 and host 192.168.1.2
   ```

   **e) Capture SYN packets (port scan detection):**
   ```bash
   sudo tcpdump 'tcp[tcpflags] & (tcp-syn) != 0'
   ```

   **f) Capture SMTP traffic:**
   ```bash
   sudo tcpdump -i eth0 -nn -A port 25
   ```

   **g) Rotate capture files (100MB per file):**
   ```bash
   sudo tcpdump -i eth0 -w capture.pcap -C 100
   ```

   **h) Capture with timestamp:**
   ```bash
   sudo tcpdump -i eth0 -tttt
   ```

8. **Advanced filters:**

   **Capture TCP SYN:**
   ```bash
   sudo tcpdump 'tcp[13] & 2 != 0'
   ```

   **Capture TCP FIN:**
   ```bash
   sudo tcpdump 'tcp[13] & 1 != 0'
   ```

   **Capture TCP RST:**
   ```bash
   sudo tcpdump 'tcp[13] & 4 != 0'
   ```

   **Capture packets larger than 1000 bytes:**
   ```bash
   sudo tcpdump 'greater 1000'
   ```

   **Capture packets smaller than 100 bytes:**
   ```bash
   sudo tcpdump 'less 100'
   ```

9. **Debug connections:**

   **3-way handshake:**
   ```bash
   sudo tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn|tcp-ack) != 0' and host 192.168.1.100
   ```

   **View latency:**
   ```bash
   sudo tcpdump -i eth0 -ttt
   ```

---

## Other Useful Tools

### `netstat` / `ss`
```bash
# View listening ports
sudo netstat -tulpn
sudo ss -tulpn          # faster alternative

# View established connections
netstat -an | grep ESTABLISHED
ss -tan state established
```

### `nmap` - Network Scanner
```bash
# Scan ports
nmap 192.168.1.1

# Scan subnet
nmap 192.168.1.0/24

# OS detection
sudo nmap -O 192.168.1.1

# Service version detection
nmap -sV 192.168.1.1
```

### `ping` and `traceroute`
```bash
# Ping
ping -c 4 google.com

# Traceroute
traceroute google.com
tracepath google.com    # no sudo required
```

### `dig` / `nslookup` - DNS lookup
```bash
# DNS query
dig google.com
nslookup google.com

# Reverse lookup
dig -x 8.8.8.8

# Specify DNS server
dig @8.8.8.8 google.com
```
