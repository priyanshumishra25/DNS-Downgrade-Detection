# 🔐 DNS Downgrade Detector

A cybersecurity-focused Python tool to detect **silent fallbacks from encrypted DNS protocols** (DoH, DoT, DoQ) to **plaintext DNS**.  
It helps analysts and engineers uncover **covert security regressions** in modern DNS behavior that are invisible to most monitoring systems.

---

## 🚨 Why This Matters

Modern systems increasingly rely on encrypted DNS protocols (like **DoH**, **DoT**, **DoQ**) to protect user privacy and prevent DNS hijacking.

But when these encrypted protocols fail—due to censorship, misconfig, firewalls, or network filtering—**clients silently fall back to plaintext DNS**, exposing queries to attackers, ISPs, or surveillance entities. These downgrades are rarely detected.

This tool aims to close that visibility gap.

---

## 🛠️ What It Does

- ✅ Analyzes `.pcapng` files (via PyShark/TShark)
- ✅ Detects DNS-over-HTTPS (DoH), DNS-over-TLS (DoT), DNS-over-QUIC (DoQ)
- ✅ Identifies fallback events where a failed secure DNS query is followed by a plaintext DNS query to the **same domain**
- ✅ Produces structured reports (`JSON` / `CSV`)
- ✅ Includes a test traffic simulator for controlled experiments

---

## 📁 Example Files

- [`capture.pcapng`](Example/capture.pcapng) — Real trace with encrypted DNS and fallbacks  
- [`capture_fallback_analysis.json`](Example/capture_fallback_analysis.json) — Example output report

> ✅ Detected 37 downgrade events in a 2090-packet trace  
> 🔍 Included DNS providers: Cloudflare, Google, Quad9, AdGuard

---

## 📦 Requirements

Listed in [`requirements.txt`](./requirements.txt):

```txt
pyshark>=0.6
requests>=2.31.0
scapy>=2.5.0
dnspython>=2.4.0
```
---

## 📦 Project Structure
├── dns_fallback_detector.py.py # Main detection engine

├── real_dns_simulator.py # Script to simulate real DNS downgrade traffic

├── doh-domains_overall.txt # Known DoH domains

├── doh-ipv4.txt # Known DoH/DoT IPv4 addresses

├── doh-ipv6.txt # Known DoH/DoT IPv6 addresses

---

## 🧪 TL;DR: How to Run a Full Test

### 1️⃣ Split your terminal into two panes

#### Left pane: Capture traffic

```bash
sudo tcpdump -i any -w real_test.pcapng -s 0
```
This starts packet capture across all interfaces (-i any) and saves all packets (-s 0) into a file.

#### Right pane: Simulate DNS traffic with downgrades

```bash
python3 real_dns_simulator.py --duration 60 --failure-rate 0.5
```
Sends a mix of DoH, DoT, DoQ, and plaintext DNS queries for 60 seconds.

50% of encrypted queries will intentionally fail to trigger fallback behavior.

### 2️⃣ Analyze the Capture

```bash
python3 dns_fallback_detector.py real_test.pcapng --doh-domains doh-domains_overall.txt --doh-ipv4 doh-ipv4.txt
```
This parses the .pcapng and detects downgrade patterns:
- Secure DNS attempt (DoH/DoT/DoQ)
- Followed by plaintext DNS to same domain
- Within a 5s time window

---

## Example Output
```json
[
  {
      "timestamp": "2025-07-27 01:57:16.927",
      "src_ip": "172.24.128.101",
      "encrypted_type": "DoH",
      "encrypted_server": "cloudflare-dns.com",
      "encrypted_time": "2025-07-27 01:57:15.859",
      "plaintext_query": "js.stripe.com",
      "plaintext_server": "172.24.0.1",
      "time_to_fallback": "1.068s",
      "likely_failure": false
    }
]
```

---

## 📚 Future Ideas
- Live mode using pyshark.LiveCapture or scapy
- Real-time alerting (Slack/email webhook)
- SIEM export (ELK/Splunk CSV)
- Add fingerprinting for proxy/obfuscation-based DoH bypass
