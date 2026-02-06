# Cheyenne Network Intrusion Detection System (NIDS)

Cheyenne is a lightweight, TAP/SPAN‑based passive network intrusion detection system written in C on top of libpcap, created by Max Gecse.
It is aimed to offer a feature set similar to commercial NIDS solutions, but as a free and open‑source project.

## Features

- TAP/SPAN‑based passive sniffing using libpcap [web:11]  
- IPv4 parsing with TCP, UDP, and ICMP support  
- TCP SYN scan detection using time‑windowed per‑host counters  
- ICMP echo (ping) sweep detection  
- HTTP request/response line parsing on TCP port 80  
- DNS over UDP and TCP inspection with tunneling/DGA heuristics:
  - Long or multi‑label query names
  - High‑entropy subdomain labels
  - Heavy TXT/NULL/CNAME usage
  - Many unique subdomains under the same base domain
  - High NXDOMAIN rate and high per‑host query volume  
- HTTPS (TLS) ClientHello parsing with SNI (Server Name Indication) extraction on TCP port 443  
- Alerts and metadata to:
  - Stdout (human‑readable)
  - Syslog (`LOG_USER` facility) for SIEM / log pipeline ingestion [web:40]  

## Requirements

- Linux or other Unix‑like OS with:
  - `libpcap` development headers and library installed [web:11]  
  - A network interface that can be opened in promiscuous mode (e.g. `eth0`, `enpXsY`, `tap0`, SPAN port, etc.)  
- Root or equivalent privileges to capture live traffic [web:11]  
- Optional: Python 3 if you want to launch it through a small Python wrapper script [web:27].  

Example installation of dependencies on Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install build-essential libpcap-dev python3
```

## Building

Clone the repository and build the C sensor binary:

```bash
git clone https://github.com/<your-user>/Cheyenne-Network-Intrusion-Detection-System.git
cd Cheyenne-Network-Intrusion-Detection-System

gcc -o cheyenne_nids cheyenne_nids.c -lpcap
```

If your file is named differently (e.g. `nids.c`), adjust the compile command:

```bash
gcc -o cheyenne_nids nids.c -lpcap
```

## Usage (direct, from C binary)

Run Cheyenne on a specific interface (requires root):

```bash
sudo ./cheyenne_nids <tap_interface>
```

Examples:

```bash
sudo ./cheyenne_nids eth0
sudo ./cheyenne_nids enp3s0
sudo ./cheyenne_nids tap0
```

When running, the program:

- Opens the given interface with `pcap_open_live` in promiscuous mode and snap length 65535 [web:11].  
- Applies a capture filter of `ip` to focus on IPv4 traffic [web:9].  
- Enters an infinite `pcap_loop`, decoding each packet and:
  - Tracking TCP SYN counts per source
  - Tracking ICMP echo requests
  - Parsing HTTP, DNS, and TLS ClientHello SNI
  - Emitting alerts to stdout and syslog  

To stop it, press `Ctrl+C` in the terminal or manage it via your service supervisor.

## Usage (from Python wrapper)

You can also launch the sensor from a small Python 3 script, which is convenient for automation, orchestration, or later integration with other Python‑based tooling [web:27][web:28].

Create `cheyenne_runner.py` in the repo root:

```python
import subprocess
import sys

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 cheyenne_runner.py <tap_interface>")
        sys.exit(1)

    iface = sys.argv[1]
    cmd = ["./cheyenne_nids", iface]

    try:
        proc = subprocess.Popen(cmd)
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()

if __name__ == "__main__":
    main()
```

Run it like this:

```bash
python3 cheyenne_runner.py eth0
```

This keeps the C binary as the high‑performance sensor engine while Python acts as a simple launcher.

## Output and Alerts

Example outputs you may see:

- TCP SYN scan alert:

  ```text
  [ALERT] Possible SYN scan from 192.0.2.10: 20 SYN in 10 s
  ```

- ICMP ping sweep alert:

  ```text
  [ALERT] Possible ICMP ping sweep (50 echo in 10 s)
  ```

- DNS tunneling heuristics:

  ```text
  [ALERT][DNS] DNS: high-entropy subdomains (possible tunneling) (src=192.0.2.15)
  ```

- HTTPS SNI meta

  ```text
  HTTPS SNI 192.0.2.5:54321 -> 198.51.100.10:443 host="example.com"
  ```

All alerts are also sent to syslog under the `cheyenne_nids` ident (`LOG_USER`), so you can forward them to your SIEM or log management stack [web:40].

## Author

Cheyenne NIDS was designed and implemented by **Max Gecse** as a free alternative that aims to deliver a commercial‑grade feature set for network intrusion detection.

## Disclaimer

Cheyenne is a research/learning‑oriented NIDS prototype. Use it responsibly, only on networks you own or have explicit permission to monitor, and review the code and thresholds before deploying it in production [web:40].
```

Sources
[1] How to use pcap_open_live for a particular ethernet port https://stackoverflow.com/questions/38398357/how-to-use-pcap-open-live-for-a-particular-ethernet-port








