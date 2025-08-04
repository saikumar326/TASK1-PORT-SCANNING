🛡️ Internal Network Reconnaissance & Vulnerability Assessment

This repository documents a penetration testing engagement against a local subnet (`192.168.2.0/24`). It includes port scanning, service enumeration, and vulnerability detection using `nmap` and its scripting engine with `vulscan.nse

| File | Description |
|------|-------------|
| `portscan.txt` | Basic TCP SYN scan across subnet (`192.168.2.0/24`) |
| `services.txt` | Service and version detection on active hosts |
| `vulresults.txt` | Vulnerability scan using `vulscan.nse` against a Windows target |
| `sai.pcapng` | Captured packet data (PCAPNG format) for deep network analysis |


## 🛠 Tools Used

- [`Nmap`](https://nmap.org/) v7.95 – Network discovery & auditing
- [`vulscan`](https://github.com/scipag/vulscan) – Nmap vulnerability scanning NSE script
- `Wireshark` or `tshark` (for `.pcapng` analysis)
- Kali Linux (scanning environment)

---

⚙️ How to Use These Tools

🔍 1. Port Scanning – Identify Live Hosts and Open Ports

nmap -sS 192.168.2.0/24 -oN portscan.txt

* `-sS`: SYN (stealth) scan
* `-oN`: Output in normal readable format

👉 Output shows IPs with open TCP ports (e.g., HTTP, MSRPC, MySQL, etc.).

---

### 🔎 2. Service & Version Detection

nmap -sV 192.168.2.0/24 -oN services.txt


* `-sV`: Attempts to detect service versions (useful for banner grabbing & fingerprinting)

👉 This helps identify software used on open ports, e.g., `OpenSSH`, `TP-LINK HTTPD`, `MySQL`, etc.


### 🚨 3. Vulnerability Scanning with Vulscan

nmap --script vulscan/vulscan.nse -sV -oN vulresults.txt 192.168.2.117

> Make sure `vulscan` is cloned into your `nmap/scripts/` directory:

cd /usr/share/nmap/scripts
git clone https://github.com/scipag/vulscan.git

* `--script=vulscan/vulscan.nse`: Uses the VulDB backend to correlate service versions with known CVEs
* `192.168.2.117`: IP of the vulnerable Windows target

👉 Output contains a massive list of matched vulnerabilities with VulDB IDs and CVEs.


🧪 4. Packet Analysis:

wireshark sai.pcapn

 High-Risk Host: `192.168.2.117`

* **Open Ports**: `135`, `139`, `445`, `2179`, `3000`
* **Vulnerable Services**: `Microsoft RPC`, `NetBIOS`, `SMB`, `VMRDP`
* **Key CVEs** Detected:

  * `CVE-2010-3222`: LPC message buffer overflow (RPCSS)
  * `CVE-2009-2523`: Heap overflow in License Logging Server
  * `CVE-2008-3479`: MSMQ heap overflow

### 🔹 Device Summary

| IP Address      | Services Detected                                           |
| --------------- | ----------------------------------------------------------- |
| `192.168.2.1`   | SSH, HTTP, HTTPS, UPnP (TP-LINK router)                     |
| `192.168.2.105` | TP-LINK admin panel on ports 80/443/44443                   |
| `192.168.2.117` | Windows services (MSRPC, SMB, VMRDP), vulnerable            |
| `192.168.2.133` | `MySQL`, `MSRPC`                                            |
| `192.168.2.155` | `RDP`, `SMB`, `HTTP`, `MSRPC`, likely a Windows workstation |
## 📚 References

* [Nmap documentation](https://nmap.org/book/man.html)
* [Vulscan project](https://github.com/scipag/vulscan)
* [CVE database](https://cve.mitre.org/)
* [Wireshark user guide](https://www.wireshark.org/docs/wsug_html_chunked/)
