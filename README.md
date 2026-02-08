# Cheyenne Network Intrusion System

Cheyenne is a lightweight, high‑performance network intrusion detection and prevention system written in C, created by **Max Gecse**. It aims to provide a feature set similar to commercial NIDS/IPS solutions, but as a free and open‑source project.

## Features

- TAP/SPAN‑based passive sniffing using **libpcap**
- Optional inline IPS mode using **NFQUEUE** (real packet drops)
- Optional high‑speed capture mode using **PF_RING**
- IPv4 parsing with TCP, UDP, and ICMP support
- Snort‑like rule engine:
  - Actions: `alert`, `log`, `drop`
  - Protocols: `tcp`, `udp`, `icmp`, `ip`
  - Header fields: `any` or single ports
  - Payload options: multiple `content`, `nocase`, `depth`, `offset`
- Built‑in detections:
  - TCP SYN scan detection (time‑windowed per‑host counters)
  - ICMP echo (ping) sweep detection
  - DNS tunneling heuristics (long qnames, high‑entropy labels, unusual RR mix, NXDOMAIN storms, many unique subdomains)
- Application‑layer visibility:
  - HTTP request/response line parsing on TCP/80
  - DNS over UDP and TCP
  - HTTPS (TLS) ClientHello SNI extraction on TCP/443
- JSON logging:
  - Alert events (rule match, action, IPs, ports, protocol)
  - Performance stats (pps, bps, average rule latency, drops)
- Syslog integration for SIEM forwarding

## Build

### Dependencies

- Linux
- `libpcap`
- `pthread`
- `libnetfilter_queue` (for NFQUEUE inline mode)
- `PF_RING` library and kernel module (for PF_RING mode)

Install (example on Debian/Ubuntu, PF_RING from ntop):

```bash
sudo apt-get install libpcap-dev libnetfilter-queue-dev
# PF_RING: follow ntop PF_RING install steps and ensure libpfring is available

Compile
Basic build with all features enabled:

gcc -o cheyenne_nids cheyenne_nids.c \
    -lpcap -lpthread -lnetfilter_queue -lpfring


Adjust include/library paths as needed if PF_RING is in a non‑standard location.

Usage

Cheyenne supports three capture modes:
1. Passive mode (libpcap)
Sniff a TAP/SPAN interface or regular NIC and log alerts:


sudo ./cheyenne_nids eth0 /etc/cheyenne.rules 4

Arguments:
	•	 eth0 : interface to sniff
	•	 /etc/cheyenne.rules : Snort‑like rules file
	•	 4 : number of worker threads
2. Inline IPS mode (NFQUEUE)
Act as an inline IPS using iptables + NFQUEUE:

sudo ./cheyenne_nids nfq /etc/cheyenne.rules 0 0
sudo iptables -I FORWARD -j NFQUEUE --queue-num 0


Arguments:
	•	 nfq : enable NFQUEUE inline mode
	•	 /etc/cheyenne.rules : rules file
	•	 0 : worker threads (not used in the simple NFQUEUE loop)
	•	 0 : NFQUEUE number
Any packet matching a  drop  rule is actually dropped with  NF_DROP .
3. High‑speed mode (PF_RING)
Use PF_RING to capture from a 1/10Gbps interface:


sudo ./cheyenne_nids pfring:eth0 /etc/cheyenne.rules 4


	•	 pfring:eth0 : capture from  eth0  via PF_RING
	•	Other arguments as in passive mode
PF_RING must be correctly installed and the interface bound to PF_RING.
Snort‑like rule syntax
Cheyenne’s rule engine supports a useful subset of Snort syntax:


<action> <proto> <src_ip> <src_port> <direction> <dst_ip> <dst_port> ( <options>; )


Supported:
	•	Actions:  alert ,  log ,  drop 
	•	Protocols:  tcp ,  udp ,  icmp ,  ip 
	•	IPs:  any  (IP/CIDR not yet implemented)
	•	Ports:  any  or a single port number
	•	Direction:  ->  or  <>  (bidirectional flag stored)
Options (subset):
	•	 msg:"text"; 
	•	 sid:number; 
	•	 rev:number; 
	•	 content:"string";  (multiple per rule)
	•	 nocase;  (applies to last  content )
	•	 depth:number;  (applies to last  content )
	•	 offset:number;  (applies to last  content )

Example rules


# HTTP GET detector on port 80
alert tcp any any -> any 80 (msg:"HTTP GET detected"; sid:1000001; rev:1;
    content:"GET "; depth:4; nocase;)

# Login POST attempt
alert tcp any any -> any 80 (msg:"Login POST attempt"; sid:1000002; rev:1;
    content:"POST "; depth:5; nocase;
    content:"/login"; nocase;)

# Drop packets containing 'malware'
drop tcp any any -> any any (msg:"Malware keyword detected"; sid:2000001; rev:1;
    content:"malware"; nocase;)

# DNS query for example.com
alert udp any any -> any 53 (msg:"DNS query for example.com"; sid:3000001; rev:1;
    content:"example.com"; nocase;)
Place rules into  /etc/cheyenne.rules  (or another file you pass on the command line).


JSON logs and SIEM integration
Cheyenne emits structured JSON events to stdout:
	•	 event_type:"alert"  for rule matches:


{"timestamp":"2026-02-08T14:05:12Z","event_type":"alert","action":"drop",
 "src_ip":"192.0.2.10","src_port":54321,"dst_ip":"198.51.100.5","dst_port":80,
 "proto":"TCP","rule_sid":2000001,"rule_rev":1,"rule_msg":"Malware keyword detected"}


	 event_type:"stats"  for periodic performance metrics:


{"timestamp":"2026-02-08T14:05:15Z","event_type":"stats",
 "pkt_total":120000,"bytes_total":80000000,
 "pps":40000.00,"bps":640000000.00,
 "pkt_alerted":120,"pkt_dropped":5,
 "rule_checks":200000,"rule_avg_usec":1.20}


{"timestamp":"2026-02-08T14:05:15Z","event_type":"stats",
 "pkt_total":120000,"bytes_total":80000000,
 "pps":40000.00,"bps":640000000.00,
 "pkt_alerted":120,"pkt_dropped":5,
 "rule_checks":200000,"rule_avg_usec":1.20}


You can:
	•	Pipe stdout into a log file:

sudo ./cheyenne_nids nfq /etc/cheyenne.rules 0 0 \
  | sudo tee -a /var/log/cheyenne_events.json

	•	Use Azure Monitor Agent (AMA) to collect  /var/log/cheyenne_events.json  as a custom JSON log into an Azure Log Analytics workspace connected to Microsoft Sentinel, then build KQL queries and analytics rules on  CheyenneEvents_CL .
Security and usage notes
	•	Use Cheyenne only on networks you own or have explicit permission to monitor.
	•	Review and tune thresholds (SYN scan, ping sweep, DNS heuristics) in this source before production use.
	•	PF_RING and NFQUEUE modes require root privileges and careful iptables/routing design to avoid interrupting legitimate traffic.
Cheyenne was designed and implemented by Max Gecse as a free alternative aiming to deliver a commercial‑grade feature set for network intrusion detection and prevention.







