#### Scan network range
- `sudo nmap <network>/<subnet> -sn -oA exist_hosts | grep for | cut -d" " -f5`
- `sudo nmap -sn -oA tnet -iL hosts.lst | grep for | cut -d " " -f5`
	- hosts.lst: ip list
#### Port scan
- **Default**: 
	- normal user (connection scan): `-sT`
	- root user (syn scan): `-sS`
- **TCP-SYN scan:** `sudo nmap <target> -p- -Pn -sV -n --disable-arp-ping -oX <file>.xml`
- **TCP-ACK scan:** `sudo nmap <target> -p- -sA -Pn -sV -n --disable-arp-ping -oX <file>.xml`
- **TCP-Connection scan:** `nmap <target> -p- -Pn -sV -n --disable-arp-ping -oX <file>.xml`
- **Read file xml:** `xsltproc <filename>.xml -o <filename>.html | open <filename>.xml`
#### Packet-Trace
- Add: `--packet-trace`
	- Example: `sudo nmap <target> -p445 -Pn -n --disable-arp-ping -oX <file>.xml --packet-trace`
	- Option: `--reason` explain the reason of connection state.
- **TCP-SYN scan:**

| State    | Description                     | Packet-trace                                  | ERROR ICMP                           |
| -------- | ------------------------------- | --------------------------------------------- | ------------------------------------ |
| open     | Port open                       | RCVD: SA (SYN - ACK)                          |                                      |
| closed   | Port close                      | RCVD: RA (RST - ACK)                          |                                      |
| filtered | Unknown or Firewall reject port | don't receive response (firewall drop packet) | RCVD: unreachable<br>(type=3/code=3) |

- **TCP-ACK scan:** Use to detect Firewall.

| State      | Description          | Packet-trace           |
| ---------- | -------------------- | ---------------------- |
| Unfiltered | Firewall allow port  | RCVD: R (RST)          |
| Filtered   | Firewall drop packet | Don't receive response |
- **TCP-Connection scan:** Same TCP-SYN scan, full connection

| State    | Description                     | Packet-trace                                  | ERROR ICMP                           |
| -------- | ------------------------------- | --------------------------------------------- | ------------------------------------ |
| open     | Port open                       | RCVD: SA (SYN - ACK)                          |                                      |
| closed   | Port close                      | RCVD: RA (RST - ACK)                          |                                      |
| filtered | Unknown or Firewall reject port | don't receive response (firewall drop packet) | RCVD: unreachable<br>(type=3/code=3) |

#### Performance
- Template: `-T <0-5>`![[Pasted image 20250407161044.png]]
#### NSE
- Category stores many script.
- Use `--script <category>/script.nse`
	- category: https://nmap.org/nsedoc/categories/default.html
	- `script`: https://nmap.org/nsedoc/scripts/
		- Find scripts:`ls /usr/share/nmap/scripts/`

| **Category**    | **Description**                                                                                                                                                                                                                          | **Examples**                                                                                                   |
|-----------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------|
| **auth**        | Scripts dealing with authentication credentials or bypassing them.                                                                                                                                                                        | x11-access, ftp-anon, oracle-enum-users                                                                       |
| **broadcast**   | Scripts used to discover hosts by broadcasting on the local network.                                                                                                                                                                      | newtargets                                                                                                    |
| **brute**       | Scripts using brute force attacks to guess authentication credentials of a remote server.                                                                                                                                                    | http-brute, oracle-brute, snmp-brute                                                                           |
| **default**     | Default scripts run with `-sC` or `-A`. They are fast, useful, reliable, and non-intrusive.                                                                                                                                                  | identd-owners, http-auth, ftp-anon                                                                            |
| **discovery**   | Scripts for actively discovering more about the network by querying public registries, SNMP-enabled devices, directory services, etc.                                                                                                      | html-title, smb-enum-shares, snmp-sysdescr                                                                    |
| **dos**         | Scripts that may cause a denial of service, either intentionally or as an unintended side effect of testing vulnerabilities.                                                                                                               | Exploit tests                                                                                                 |
| **exploit**     | Scripts that actively exploit known vulnerabilities.                                                                                                                                                                                        | jdwp-exec, http-shellshock                                                                                    |
| **external**    | Scripts that send data to third-party databases or network resources.                                                                                                                                                                       | whois-ip                                                                                                      |
| **fuzzer**      | Scripts designed to send unexpected or randomized fields in each packet to find software bugs and vulnerabilities.                                                                                                                          | dns-fuzz                                                                                                      |
| **intrusive**   | Scripts with high risk of crashing the target system or using significant resources.                                                                                                                                                        | http-open-proxy, snmp-brute                                                                                   |
| **malware**     | Scripts that test whether a platform is infected by malware or backdoors.                                                                                                                                                                | smtp-strangeport, auth-spoof                                                                                  |
| **safe**        | Scripts that are less likely to cause adverse effects, such as crashing services or using large amounts of resources.                                                                                                                      | ssh-hostkey, html-title                                                                                       |
| **version**     | Special scripts for version detection, used when `-sV` is requested.                                                                                                                                                                       | skypev2-version, pptp-version, iax2-version                                                                   |
| **vuln**        | Scripts that check for specific known vulnerabilities and report results if found.                                                                                                                                                         | realvnc-auth-bypass, afp-path-vuln                                                                           |
#### Decoys, Source IP, and Source Port
- **Decoys:** `nmap <target_IP> -p- -sS -Pn -n --disable-arp-ping --packet-trace -D RND:5`
	- RND: generate random 5 IP (maybe flag as SYN-Flooding)
	- **Better:** `-D <realIP_1>,<realIP_2>,...`
- **Source IP:** Inside LAN or Routing
	- `sudo nmap <target_IP> -n -Pn -p <number> -O -S <ip_source> -e tun0`
- **Source Port:** `sudo nmap <target_IP> -p <number> -sS -Pn -n --disable-arp-ping --packet-trace --source-port <number>`
	- **Should:** `--source-port 53` (Firewall, and IDS/IPS usually allow this port)
	- **Better:** `sudo nc -nv -p 53 <target> <target_port>`
#### DNS Proxying
- Use: `--dns-server <ns>,<ns>` (inside: DMZ)

#### Evasion
- `sudo nmap <target_ip> -p <number> -sS -Pn -n --disable-arp-ping --packet-trace --source-port 53`
