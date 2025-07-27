#!/usr/bin/env python3
"""
DNS Fallback Detector with Custom DoH Server Lists
Uses doh-domains_overall.txt, doh-ipv4.txt, and doh-ipv6.txt
"""

import pyshark
import argparse
import json
import csv
from datetime import datetime, timedelta
from collections import defaultdict
import sys
import os

class DNSFallbackDetectorWithLists:
    def __init__(self, pcap_file, debug=False, doh_domains_file=None, doh_ipv4_file=None, doh_ipv6_file=None):
        self.pcap_file = pcap_file
        self.debug = debug
        self.encrypted_attempts = defaultdict(list)
        self.plaintext_queries = []
        self.fallback_events = []
        self.time_window = 5.0
        self.packet_stats = {
            'total': 0,
            'tcp_443': 0,
            'tcp_853': 0,
            'udp_53': 0,
            'udp_853': 0,
            'udp_784': 0,
            'udp_8853': 0,
            'tls_packets': 0,
            'dns_packets': 0,
            'quic_packets': 0,
            'doh_attempts': 0,
            'dot_attempts': 0,
            'doq_attempts': 0,
            'plaintext_queries': 0
        }
        
        # Load DoH server lists from files
        self.doh_providers = self.load_list_from_file(doh_domains_file, [])
        
        self.doh_ipv4 = self.load_list_from_file(doh_ipv4_file, [])
        
        self.doh_ipv6 = self.load_list_from_file(doh_ipv6_file, [])
        
        # Combine all IPs for easy checking
        self.doh_ips = set(self.doh_ipv4 + self.doh_ipv6)
        
        # DoT typically uses same IPs as DoH
        self.dot_ips = self.doh_ips
        
        print(f"Loaded {len(self.doh_providers)} DoH domains")
        print(f"Loaded {len(self.doh_ipv4)} IPv4 addresses")
        print(f"Loaded {len(self.doh_ipv6)} IPv6 addresses")
        
        if self.debug:
            print(f"Sample DoH domains: {list(self.doh_providers)[:5]}")
            print(f"Sample DoH IPv4s: {list(self.doh_ipv4)[:5]}")
            print(f"Sample DoH IPv6s: {list(self.doh_ipv6)[:5]}")
    
    def load_list_from_file(self, filename, default_list):
        """Load a list from file, use default if file not found"""
        if filename and os.path.exists(filename):
            try:
                with open(filename, 'r') as f:
                    items = []
                    for line in f:
                        line = line.strip()
                        # Skip empty lines and comments
                        if line and not line.startswith('#'):
                            # Handle various formats (some files might have additional info)
                            # Take the first field if space/tab separated
                            item = line.split()[0] if ' ' in line or '\t' in line else line
                            items.append(item.lower())
                    
                    print(f"Loaded {len(items)} entries from {filename}")
                    return items
            except Exception as e:
                print(f"Warning: Error reading {filename}: {e}")
                return default_list
        else:
            if filename:
                print(f"Warning: File {filename} not found, using defaults")
            return default_list
    
    def debug_print(self, message):
        """Print debug messages if debug mode is enabled"""
        if self.debug:
            print(f"[DEBUG] {message}")
    
    def is_doh_traffic(self, packet):
        """Enhanced DoH detection - outbound only, SNI-based"""
        try:
            # Must have TCP and TLS layers
            if not (hasattr(packet, 'tcp') and hasattr(packet, 'tls')):
                return False
                
            # Only check outbound traffic (destination port 443)
            dst_port = getattr(packet.tcp, 'dstport', None)
            if dst_port != '443':
                return False
            
            # Extract SNI from TLS handshake
            sni = None
            try:
                if hasattr(packet.tls, 'handshake_extensions_server_name'):
                    sni = str(packet.tls.handshake_extensions_server_name).lower()
                elif hasattr(packet.tls, 'handshake_extension_server_name'):
                    sni = str(packet.tls.handshake_extension_server_name).lower()
            except:
                pass
            
            # Primary detection: SNI must match known DoH providers
            if sni:
                for provider in self.doh_providers:
                    if provider.lower() in sni or sni in provider.lower():
                        self.debug_print(f"DoH detected by SNI: {sni}")
                        return True
            
            # Secondary detection: HTTP/2 with DoH paths (for already established connections)
            if hasattr(packet, 'http2'):
                try:
                    # Check various HTTP/2 header fields for DoH paths
                    for field in ['headers_path', 'header_path', 'path']:
                        if hasattr(packet.http2, field):
                            path = str(getattr(packet.http2, field))
                            if 'dns-query' in path or '/dns' in path:
                                # Additional verification: check if this is to a known DoH provider IP
                                dst_ip = None
                                if hasattr(packet, 'ip'):
                                    dst_ip = getattr(packet.ip, 'dst', None)
                                elif hasattr(packet, 'ipv6'):
                                    dst_ip = getattr(packet.ipv6, 'dst', None)
                                
                                # Only count if it's to a known DoH IP
                                if dst_ip and dst_ip in self.doh_ips:
                                    self.debug_print(f"DoH detected by HTTP/2 path to known server: {path} -> {dst_ip}")
                                    return True
                except:
                    pass
            
            # If we reach here, it's not DoH traffic we can identify
            return False
                        
        except Exception as e:
            self.debug_print(f"Error in DoH detection: {e}")
            return False
    
    def is_dot_traffic(self, packet):
        """Enhanced DoT detection"""
        try:
            # Must be TCP on port 853
            if not ('TCP' in packet and hasattr(packet, 'tcp')):
                return False
            
            dst_port = getattr(packet.tcp, 'dstport', None)
            
            if dst_port == '853':
                # Additional check: verify it's to/from a known DNS server
                if hasattr(packet, 'ip'):
                    dst_ip = getattr(packet.ip, 'dst', None)
                    
                self.debug_print(f"TCP port 853 traffic to server: {dst_ip}")
                return True
                
        except Exception as e:
            self.debug_print(f"Error in DoT detection: {e}")
            
        return False
    
    def is_doq_traffic(self, packet):
        """Detect DNS-over-QUIC (DoQ) traffic"""
        try:
            # Must be UDP on DoQ ports (853, 784, 8853)
            if not (hasattr(packet, 'udp')):
                return False
            
            dst_port = getattr(packet.udp, 'dstport', None)
            src_port = getattr(packet.udp, 'srcport', None)
            
            # Check for DoQ ports
            doq_ports = ['853', '784', '8853']
            if dst_port not in doq_ports:
                return False
            
            # Get IP addresses
            dst_ip = None
            src_ip = None
            
            # Check for QUIC protocol indicators
            if not hasattr(packet, 'quic'):
                return False
            
            if hasattr(packet, 'ip'):
                dst_ip = getattr(packet.ip, 'dst', None)
                src_ip = getattr(packet.ip, 'src', None)
            elif hasattr(packet, 'ipv6'):
                dst_ip = getattr(packet.ipv6, 'dst', None)
                src_ip = getattr(packet.ipv6, 'src', None)
            
            self.debug_print(f"DoQ detected on port {dst_port or src_port} to known server: {dst_ip or src_ip}")
            return True
                    
        except Exception as e:
            self.debug_print(f"Error in DoQ detection: {e}")
            
        return False
    
    def is_plaintext_dns(self, packet):
        """Enhanced plaintext DNS detection"""
        try:
            # Check if it's DNS
            if 'DNS' in packet:
                # Check if it's on standard DNS port
                if hasattr(packet, 'udp'):
                    dst_port = getattr(packet.udp, 'dstport', None)
                    src_port = getattr(packet.udp, 'srcport', None)
                    
                    if dst_port == '53' or src_port == '53':
                        self.debug_print("Plaintext DNS detected")
                        return True
                        
        except Exception as e:
            self.debug_print(f"Error in plaintext DNS detection: {e}")
            
        return False
    
    def extract_dns_query(self, packet):
        """Extract DNS query name"""
        try:
            if hasattr(packet, 'dns'):
                # Try different ways to get query name
                for attr in ['qry_name', 'qname', 'query_name']:
                    if hasattr(packet.dns, attr):
                        query = str(getattr(packet.dns, attr))
                        # Remove trailing dot if present
                        return query.rstrip('.').lower()
        except:
            pass
        return None
    
    def detect_connection_failure(self, packet):
        """Detect various connection failure indicators"""
        try:
            # TCP RST
            if hasattr(packet, 'tcp'):
                if hasattr(packet.tcp, 'flags_reset') and packet.tcp.flags_reset == '1':
                    self.debug_print("TCP RST detected")
                    return True
                    
                # TCP FIN
                if hasattr(packet.tcp, 'flags_fin') and packet.tcp.flags_fin == '1':
                    self.debug_print("TCP FIN detected")
                    return True
            
            # TLS alerts
            if hasattr(packet, 'tls'):
                if hasattr(packet.tls, 'alert_message'):
                    self.debug_print(f"TLS alert detected: {packet.tls.alert_message}")
                    return True
            
            # ICMP errors
            if 'ICMP' in packet:
                self.debug_print("ICMP error detected")
                return True
                
        except:
            pass
            
        return False
    
    def analyze_packet(self, packet):
        """Analyze individual packet"""
        try:
            self.packet_stats['total'] += 1
            
            # Get basic info
            timestamp = float(packet.sniff_timestamp)
            src_ip = None
            dst_ip = None
            
            # Check both IPv4 and IPv6
            if hasattr(packet, 'ip'):
                src_ip = getattr(packet.ip, 'src', None)
                dst_ip = getattr(packet.ip, 'dst', None)
            elif hasattr(packet, 'ipv6'):
                src_ip = getattr(packet.ipv6, 'src', None)
                dst_ip = getattr(packet.ipv6, 'dst', None)
            
            # Count packet types
            if hasattr(packet, 'tcp'):
                if getattr(packet.tcp, 'dstport', None) == '443':
                    self.packet_stats['tcp_443'] += 1
                elif getattr(packet.tcp, 'dstport', None) == '853':
                    self.packet_stats['tcp_853'] += 1
                    
            if hasattr(packet, 'udp'):
                dst_port = getattr(packet.udp, 'dstport', None)
                if dst_port == '53':
                    self.packet_stats['udp_53'] += 1
                elif dst_port == '853':
                    self.packet_stats['udp_853'] += 1
                elif dst_port == '784':
                    self.packet_stats['udp_784'] += 1
                elif dst_port == '8853':
                    self.packet_stats['udp_8853'] += 1
            
            if 'TLS' in packet:
                self.packet_stats['tls_packets'] += 1
                
            if 'DNS' in packet:
                self.packet_stats['dns_packets'] += 1
                
            if hasattr(packet, 'quic'):
                self.packet_stats['quic_packets'] += 1
            
            # Check for DoH
            if self.is_doh_traffic(packet):
                failed = self.detect_connection_failure(packet)
                
                # Get destination for DoH
                server = dst_ip
                if hasattr(packet, 'tls'):
                    for attr in ['handshake_extensions_server_name', 'handshake_extension_server_name']:
                        if hasattr(packet.tls, attr):
                            server = str(getattr(packet.tls, attr))
                            break
                
                self.packet_stats['doh_attempts'] += 1
                self.encrypted_attempts[src_ip].append({
                    'timestamp': timestamp,
                    'type': 'DoH',
                    'server': server,
                    'dst_ip': dst_ip,
                    'failed': failed
                })
                
            # Check for DoT
            elif self.is_dot_traffic(packet):
                failed = self.detect_connection_failure(packet)
                
                self.packet_stats['dot_attempts'] += 1
                self.encrypted_attempts[src_ip].append({
                    'timestamp': timestamp,
                    'type': 'DoT',
                    'server': dst_ip,
                    'dst_ip': dst_ip,
                    'failed': failed
                })
            
            # Check for DoQ
            elif self.is_doq_traffic(packet):
                # DoQ failure detection is different (no TCP RST/FIN)
                # We might detect ICMP errors or timeouts
                failed = False
                if 'ICMP' in packet or 'ICMPv6' in packet:
                    failed = True
                    self.debug_print("DoQ failure detected via ICMP")
                
                self.packet_stats['doq_attempts'] += 1
                self.encrypted_attempts[src_ip].append({
                    'timestamp': timestamp,
                    'type': 'DoQ',
                    'server': dst_ip,
                    'dst_ip': dst_ip,
                    'failed': failed
                })
                
            # Check for plaintext DNS
            elif self.is_plaintext_dns(packet):
                query_name = self.extract_dns_query(packet)
                if query_name and src_ip:  # Only process queries, not responses
                    self.packet_stats['plaintext_queries'] += 1
                    self.plaintext_queries.append({
                        'timestamp': timestamp,
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'query': query_name
                    })
                    
        except Exception as e:
            self.debug_print(f"Error analyzing packet: {e}")
    
    def correlate_fallback_events(self):
        """Correlate failures with fallbacks"""
        self.debug_print(f"Correlating {len(self.plaintext_queries)} plaintext queries with encrypted attempts")
        
        seen_combinations = set()

        for plaintext in self.plaintext_queries:
            src_ip = plaintext['src_ip']
            query = plaintext['query']
            plaintext_time = plaintext['timestamp']
            
            # Create unique key for this plaintext query
            query_key = f"{src_ip}_{query}_{plaintext_time}"
            
            # Look for encrypted attempts from same source
            if src_ip in self.encrypted_attempts:
                best_match = None
                best_time_diff = float('inf')
                
                for encrypted in self.encrypted_attempts[src_ip]:
                    # Must be before plaintext query
                    if encrypted['timestamp'] >= plaintext_time:
                        continue
                    
                    time_diff = plaintext_time - encrypted['timestamp']
                    
                    # Within time window
                    if time_diff <= self.time_window:
                        # Create unique key for this correlation
                        correlation_key = f"{src_ip}_{encrypted['type']}_{encrypted['server']}_{query}_{int(plaintext_time)}"
                        
                        if correlation_key not in seen_combinations:
                            # Prefer failed attempts or closer time
                            if encrypted.get('failed', False) or time_diff < best_time_diff:
                                best_match = (encrypted, time_diff, correlation_key)
                                best_time_diff = time_diff
                
                # Add the best match if found
                if best_match:
                    encrypted, time_diff, correlation_key = best_match
                    seen_combinations.add(correlation_key)
                    
                    self.fallback_events.append({
                        'timestamp': datetime.fromtimestamp(plaintext_time).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                        'src_ip': src_ip,
                        'encrypted_type': encrypted['type'],
                        'encrypted_server': encrypted['server'],
                        'encrypted_time': datetime.fromtimestamp(encrypted['timestamp']).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                        'plaintext_query': query,
                        'plaintext_server': plaintext['dst_ip'],
                        'time_to_fallback': f"{time_diff:.3f}s",
                        'likely_failure': encrypted.get('failed', False)
                    })
        
        self.debug_print(f"Found {len(self.fallback_events)} unique fallback events")
    
    def analyze_pcap(self):
        """Main analysis function"""
        print(f"Analyzing {self.pcap_file}...")
        
        try:
            # First pass without filter to see all packets
            if self.debug:
                print("Running in debug mode - analyzing all packets")
                cap = pyshark.FileCapture(self.pcap_file)
            else:
                # Use broader filter
                cap = pyshark.FileCapture(
                    self.pcap_file,
                    display_filter='tcp.port==443 or tcp.port==853 or udp.port==53 or udp.port==853 or udp.port==784 or udp.port==8853 or dns or quic'
                )
            
            packet_count = 0
            for packet in cap:
                self.analyze_packet(packet)
                packet_count += 1
                
                if packet_count % 100 == 0:
                    print(f"Processed {packet_count} packets...")
            
            cap.close()
            
            # Print statistics
            print(f"\nPacket Statistics:")
            print(f"Filtered packets analyzed: {self.packet_stats['total']} (DNS-relevant traffic only)")
            print(f"TCP port 443 packets: {self.packet_stats['tcp_443']}")
            print(f"TCP port 853 packets: {self.packet_stats['tcp_853']}")
            print(f"UDP port 53 packets: {self.packet_stats['udp_53']}")
            print(f"UDP port 853 packets: {self.packet_stats['udp_853']}")
            print(f"UDP port 784 packets: {self.packet_stats['udp_784']}")
            print(f"UDP port 8853 packets: {self.packet_stats['udp_8853']}")
            print(f"TLS packets: {self.packet_stats['tls_packets']}")
            print(f"QUIC packets: {self.packet_stats['quic_packets']}")
            print(f"DNS packets: {self.packet_stats['dns_packets']}")
            
            print(f"\nDNS Traffic Summary:")
            print(f"DoH attempts: {self.packet_stats['doh_attempts']}")
            print(f"DoT attempts: {self.packet_stats['dot_attempts']}")
            print(f"DoQ attempts: {self.packet_stats['doq_attempts']}")
            print(f"Total encrypted DNS: {self.packet_stats['doh_attempts'] + self.packet_stats['dot_attempts'] + self.packet_stats['doq_attempts']}")
            print(f"Plaintext DNS queries: {self.packet_stats['plaintext_queries']}")
            
            print(f"\nDetection Results:")
            print(f"Encrypted DNS attempts found: {sum(len(attempts) for attempts in self.encrypted_attempts.values())}")
            print(f"  - DoH: {self.packet_stats['doh_attempts']}")
            print(f"  - DoT: {self.packet_stats['dot_attempts']}")
            print(f"  - DoQ: {self.packet_stats['doq_attempts']}")
            print(f"Plaintext DNS queries found: {len(self.plaintext_queries)}")
            
            # Show sample of what was found
            if self.debug and self.encrypted_attempts:
                print("\nSample encrypted attempts:")
                for ip, attempts in list(self.encrypted_attempts.items())[:2]:
                    for attempt in attempts[:2]:
                        print(f"  {ip} -> {attempt['type']} to {attempt['server']}")
            
            # Correlate events
            self.correlate_fallback_events()
            print(f"Fallback events detected: {len(self.fallback_events)}")
            
        except Exception as e:
            print(f"Error analyzing pcap: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)
    
    def save_results(self, output_format='json', output_file=None):
        """Save analysis results"""
        if not output_file:
            base_name = os.path.splitext(self.pcap_file)[0]
            output_file = f"{base_name}_fallback_analysis"
        
        if output_format == 'json':
            output_file += '.json'
            with open(output_file, 'w') as f:
                json.dump({
                    'analysis_timestamp': datetime.now().isoformat(),
                    'pcap_file': self.pcap_file,
                    'packet_statistics': self.packet_stats,
                    'total_fallback_events': len(self.fallback_events),
                    'doh_servers_loaded': {
                        'domains': len(self.doh_providers),
                        'ipv4': len(self.doh_ipv4),
                        'ipv6': len(self.doh_ipv6)
                    },
                    'fallback_events': self.fallback_events
                }, f, indent=2)
                
        elif output_format == 'csv':
            output_file += '.csv'
            with open(output_file, 'w', newline='') as f:
                if self.fallback_events:
                    writer = csv.DictWriter(f, fieldnames=self.fallback_events[0].keys())
                    writer.writeheader()
                    writer.writerows(self.fallback_events)
                else:
                    writer = csv.writer(f)
                    writer.writerow(['No fallback events detected'])
        
        print(f"Results saved to: {output_file}")
        return output_file

def main():
    parser = argparse.ArgumentParser(description='DNS Fallback Detector with Custom DoH Lists')
    parser.add_argument('pcap_file', help='Path to .pcapng file to analyze')
    parser.add_argument('--doh-domains', help='File containing DoH domain names (doh-domains_overall.txt)')
    parser.add_argument('--doh-ipv4', help='File containing DoH IPv4 addresses (doh-ipv4.txt)')
    parser.add_argument('--doh-ipv6', help='File containing DoH IPv6 addresses (doh-ipv6.txt)')
    parser.add_argument('--format', choices=['json', 'csv'], default='json', 
                       help='Output format (default: json)')
    parser.add_argument('--output', help='Output file name (without extension)')
    parser.add_argument('--time-window', type=float, default=5.0,
                       help='Time window in seconds to correlate fallback events (default: 5.0)')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.pcap_file):
        print(f"Error: File '{args.pcap_file}' not found")
        sys.exit(1)
    
    # Check for DoH list files
    if args.doh_domains and not os.path.exists(args.doh_domains):
        print(f"Warning: DoH domains file '{args.doh_domains}' not found")
    if args.doh_ipv4 and not os.path.exists(args.doh_ipv4):
        print(f"Warning: DoH IPv4 file '{args.doh_ipv4}' not found")
    if args.doh_ipv6 and not os.path.exists(args.doh_ipv6):
        print(f"Warning: DoH IPv6 file '{args.doh_ipv6}' not found")
    
    detector = DNSFallbackDetectorWithLists(
        args.pcap_file, 
        debug=args.debug,
        doh_domains_file=args.doh_domains,
        doh_ipv4_file=args.doh_ipv4,
        doh_ipv6_file=args.doh_ipv6
    )
    detector.time_window = args.time_window
    
    # Run analysis
    detector.analyze_pcap()
    
    # Save results
    detector.save_results(output_format=args.format, output_file=args.output)
    
    # Print summary
    if detector.fallback_events:
        print("\nFallback Events Summary:")
        print("-" * 80)
        for event in detector.fallback_events[:5]:
            print(f"Time: {event['timestamp']}")
            print(f"Source: {event['src_ip']}")
            print(f"Encrypted {event['encrypted_type']} to {event['encrypted_server']}")
            print(f"Fallback to plaintext DNS: {event['plaintext_query']} -> {event['plaintext_server']}")
            print(f"Time to fallback: {event['time_to_fallback']}")
            print(f"Likely failure: {event['likely_failure']}")
            print("-" * 80)
        
        if len(detector.fallback_events) > 5:
            print(f"... and {len(detector.fallback_events) - 5} more events")

if __name__ == "__main__":
    main()
