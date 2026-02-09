# Cheyenne NIDS/IPS

Cheyenne is a single‑binary, experimental Network Intrusion Detection and Prevention System written in C. It focuses on being small, understandable, and easy to extend while borrowing ideas from larger engines like Suricata and Snort.

## Features

- Passive NIDS using libpcap (TAP/SPAN / mirror port)
- Inline IPS mode using NFQUEUE (real `DROP`/`ACCEPT` on Linux)
- Optional high‑speed capture using PF_RING
- IPv4 parsing with TCP, UDP, and ICMP support
- Simple Snort‑style rule engine:
  - Actions: `alert`, `drop`, `log`
  - Protocols: `tcp`, `udp`, `icmp`, `ip`
  - Ports: exact or `any`
  - Payload keywords: `content`, `nocase`, `offset`, `depth`, `distance`, `within`
- Basic detection logic:
  - TCP SYN scan detection
  - ICMP ping sweep detection
  - HTTP request/response line logging (TCP/80)
  - DNS over UDP and TCP parsing
  - DNS tunneling heuristics (long names, high entropy labels, NXDOMAIN storms, many unique subdomains)
  - TLS ClientHello SNI extraction (TCP/443)
- JSON alerts and stats suitable for SIEM ingestion (e.g. Sentinel, Elastic, etc.)
- Multi‑threaded processing with a packet queue and worker threads

## Architecture Overview

- **Capture layer**
  - libpcap capture loop in passive mode
  - NFQUEUE callback in inline mode
  - PF_RING capture loop (optional)
- **Dispatch**
  - One capture thread enqueues packets into a ring buffer
  - Worker threads dequeue and run protocol parsing + rule evaluation
- **Detection**
  - Per‑packet IPv4 + L4 parsing
  - Stateless rule evaluation on application payload
  - Stateful helpers for:
    - SYN counts per source
    - ICMP echo counts
    - DNS per‑source statistics and per‑(src, base domain) tracking
- **Output**
  - JSON alerts: one line per event
  - JSON stats: periodic performance metrics (pps, bps, rule evaluation latency)

## Build

Cheyenne depends on:

- `libpcap`
- `libpthread`
- `libnetfilter_queue` (for NFQUEUE IPS mode)
- `libpfring` (optional, for PF_RING mode)
- Standard C library headers and Linux networking headers

Example build command (adjust libraries and include paths for your distro):

```bash
gcc -O2 -Wall -Wextra -o cheyenne_nids \
    cheyenne_nids.c \
    -lpcap -lpthread -lnetfilter_queue -lpfring
```

If you do not have PF_RING or NFQUEUE installed, you can remove the corresponding libraries and, if needed, compile with small stubs or `#ifdef`s.

## Running

Cheyenne supports three main capture modes:

- Passive pcap (default)
- NFQUEUE inline IPS
- PF_RING

Below are example invocations; adapt to your environment.

### Passive mode (libpcap)

Monitor traffic on an interface using libpcap:

```bash
sudo ./cheyenne_nids -i eth0 -r rules.cheyenne
```

Typical options:

- `-i <iface>`: network interface to sniff (e.g. `eth0`, `ens3`)
- `-r <rules>`: rule file in Snort‑like syntax
- `-w <workers>`: number of worker threads (optional)

### NFQUEUE IPS mode

To run inline with iptables / nftables:

1. Add firewall rules to send traffic to a queue, for example:

   ```bash
   sudo iptables -I FORWARD -j NFQUEUE --queue-num 0
   ```

2. Start Cheyenne in NFQUEUE mode (example):

   ```bash
   sudo ./cheyenne_nids -Q 0 -r rules.cheyenne
   ```

   Here:

   - `-Q <num>` selects the NFQUEUE number
   - `-r <rules>` loads detection rules

Cheyenne will then accept or drop packets based on rule actions.

### PF_RING mode

When PF_RING is installed and configured, you can use a PF_RING interface:

```bash
sudo ./cheyenne_nids -P -i zc:eth0 -r rules.cheyenne
```

Exact option names or details may differ slightly depending on how you wire the arguments in `main()`; check the usage printed by the binary if you pass `-h` or invalid options.

## Rule Syntax

Rules follow a simplified Snort‑style format:

```text
<action> <proto> <src_ip> <src_port> <dir> <dst_ip> <dst_port> (<options>)
```

Examples:

```text
alert tcp any any -> any 80 (
    msg:"Suspicious HTTP";
    content:"GET";
    content:"/evil";
    distance:0;
    within:50;
    sid:1001;
    rev:1;
)

drop udp any any -> any 53 (
    msg:"DNS tunnel?";
    content:"example.com";
    nocase;
    sid:2001;
    rev:1;
)
```

Supported components:

- **Actions**
  - `alert`: log an alert event
  - `drop`: drop the packet (in inline mode) and log
  - `log`: log only
- **Protocols**
  - `tcp`, `udp`, `icmp`, `ip`
- **Addresses and ports**
  - `any` or a single IP/port (CIDR/ranges are not yet implemented)
- **Direction**
  - `->` or `<>` (bidirectional flag is parsed, though IP matching is still basic)
- **Payload keywords**
  - `content:"..."`: match a byte string in the application payload
  - `nocase`: case‑insensitive content matching
  - `offset:n`: start searching at byte offset `n`
  - `depth:n`: limit search to the first `n` bytes from the offset
  - `distance:n`: for subsequent `content`, start search `n` bytes after the previous match start
  - `within:n`: limit search window to `n` bytes after the previous match start

Meta:

- `msg:"..."`: human‑readable message
- `sid:n`: unique rule ID
- `rev:n`: revision

Multiple `content` options in one rule are evaluated in order; `distance` and `within` are interpreted relative to the previous `content` match.

## Output Format

Cheyenne prints JSON on stdout, one object per line.

### Alert events

Example:

```json
{
  "timestamp": "2026-02-09T00:00:00Z",
  "event_type": "alert",
  "action": "drop",
  "src_ip": "10.0.0.10",
  "src_port": 54321,
  "dst_ip": "192.0.2.80",
  "dst_port": 80,
  "proto": "TCP",
  "rule_sid": 1001,
  "rule_rev": 1,
  "rule_msg": "Suspicious HTTP"
}
```

### Stats events

Emitted periodically:

```json
{
  "timestamp": "2026-02-09T00:00:05Z",
  "event_type": "stats",
  "pkt_total": 12345,
  "bytes_total": 9876543,
  "pps": 2469.00,
  "bps": 158024688.00,
  "pkt_alerted": 42,
  "pkt_dropped": 10,
  "rule_checks": 5000,
  "rule_avg_usec": 3.21
}
```

These can be shipped into SIEMs or log pipelines (e.g. `jq`, Logstash, Fluent Bit, etc.).

## Limitations

Cheyenne is intentionally minimal compared to full‑blown IDS/IPS engines:

- No TCP stream reassembly or full flow tracking yet
- IPv4 only; no IPv6 handling
- Basic rule language (small subset of Snort/Suricata keywords)
- No large community rule sets bundled
- No management UI; configuration is via CLI flags and rule files

It’s meant as:

- A learning and experimentation platform
- A small, auditable engine you can extend
- A testbed for new detections (e.g. DNS tunneling heuristics)

## Roadmap Ideas

Potential future enhancements:

- Flow table and TCP reassembly
- IPv6 support
- More rule keywords (flow, stream‑based matching, byte tests)
- File extraction hooks
- EVE‑style JSON for better Suricata/Snort interoperability
- Configuration file for global settings

## License

MIT License

Copyright (c) 2026 Max Gecse

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.


WARNING AND DISCLAIMER

Cheyenne is experimental security software and is provided under the terms
of the MIT license on an "AS IS" basis. It has NOT been formally verified,
certified, or audited for production use.

Running this software on live networks, especially in inline IPS mode, may
cause unintended traffic disruption, performance degradation, or security
gaps. You use Cheyenne entirely at your own risk. The authors and
contributors assume no responsibility or liability for any damage, data
loss, downtime, legal issues, or other consequences arising from the use,
misuse, or inability to use this software.

Always test thoroughly in a controlled environment before deploying to any
production or safety‑critical system.
