# 🔐 DNS Downgrade Detector

A Python-based tool for detecting silent fallbacks from encrypted DNS protocols (DoH, DoT, DoQ) to plaintext DNS.  
This project helps uncover real-world security regressions often missed by existing monitoring tools.

## 🚨 Why It Matters

Modern browsers and operating systems use **encrypted DNS protocols** (DNS-over-HTTPS, DNS-over-TLS, DNS-over-QUIC) to protect user privacy. But when these fail—due to censorship, misconfiguration, or filtering—they silently fall back to **insecure plaintext DNS**, leaving users exposed without any warning.

This downgrade can enable:
- DNS **eavesdropping** and **traffic analysis** by attackers or ISPs
- **DNS hijacking** or **spoofing** for phishing or surveillance
- **Loss of compliance** with enterprise privacy policies

---

## 🛠️ What This Tool Does

- ✅ Parses `.pcapng` network captures
- ✅ Detects DNS-over-HTTPS (DoH), DNS-over-TLS (DoT), and DNS-over-QUIC (DoQ)
- ✅ Identifies **downgrade events**: when secure DNS fails and is followed by a plaintext query to the same domain
- ✅ Outputs structured reports in JSON/CSV
- ✅ Includes a traffic simulator for generating realistic downgrade scenarios

---

## 📦 Project Structure
├── improved_dns_detector.py # Main detection engine
├── real_dns_simulator.py # Script to simulate real DNS downgrade traffic
├── doh-domains_overall.txt # Known DoH domains
├── doh-ipv4.txt # Known DoH/DoT IPv4 addresses
├── doh-ipv6.txt # Known DoH/DoT IPv6 addresses
