#!/usr/bin/env python3
"""
Real DNS Traffic Generator
Generates actual DNS network traffic (DoH/DoT/plaintext) for testing fallback detection
"""

import socket
import ssl
import time
import random
import requests
import json
import base64
import struct
import argparse
import sys
from datetime import datetime
import dns.message
import dns.query
import dns.rdatatype

class RealDNSTrafficGenerator:
    def __init__(self, doh_domains_file=None, doh_ipv4_file=None):
        self.doh_servers = self.load_doh_servers(doh_domains_file, doh_ipv4_file)
        self.test_domains = [
            "example.com", "google.com", "cloudflare.com", "github.com",
            "wikipedia.org", "stackoverflow.com", "reddit.com", "amazon.com"
        ]
        self.failure_rate = 0.3
        self.force_failures = False
        
    def load_doh_servers(self, domains_file, ipv4_file):
        """Load DoH server information"""
        servers = {
            'doh': [
                {'name': 'Cloudflare', 'url': 'https://cloudflare-dns.com/dns-query'},
                {'name': 'Google', 'url': 'https://dns.google/dns-query'},
                {'name': 'Quad9', 'url': 'https://dns.quad9.net/dns-query'}
            ],
            'dot': [
                {'name': 'Cloudflare', 'ip': '1.1.1.1', 'hostname': 'cloudflare-dns.com'},
                {'name': 'Google', 'ip': '8.8.8.8', 'hostname': 'dns.google'},
                {'name': 'Quad9', 'ip': '9.9.9.9', 'hostname': 'dns.quad9.net'}
            ],
            'plaintext': [
                {'name': 'Google', 'ip': '8.8.8.8'},
                {'name': 'Cloudflare', 'ip': '1.1.1.1'},
                {'name': 'OpenDNS', 'ip': '208.67.222.222'}
            ]
        }
        
        # Load custom servers if files provided
        try:
            if domains_file:
                with open(domains_file, 'r') as f:
                    custom_domains = [line.strip() for line in f if line.strip()]
                    for domain in custom_domains[:3]:  # Use first 3
                        servers['doh'].append({
                            'name': domain,
                            'url': f'https://{domain}/dns-query'
                        })
            
            if ipv4_file:
                with open(ipv4_file, 'r') as f:
                    custom_ips = [line.strip() for line in f if line.strip()]
                    for ip in custom_ips[:3]:  # Use first 3
                        servers['dot'].append({
                            'name': f'Server-{ip}',
                            'ip': ip,
                            'hostname': 'dns.example'
                        })
        except Exception as e:
            print(f"Warning loading custom servers: {e}")
            
        return servers
    
    def create_dns_query_message(self, domain):
        """Create a DNS query using dnspython"""
        query = dns.message.make_query(domain, dns.rdatatype.A)
        return query
    
    def real_doh_query(self, domain, server_info):
        """Perform real DNS-over-HTTPS query"""
        try:
            # Create DNS query
            query = self.create_dns_query_message(domain)
            
            # Convert to wire format
            wire_query = query.to_wire()
            
            # DoH headers
            headers = {
                'Accept': 'application/dns-message',
                'Content-Type': 'application/dns-message',
                'Content-Length': str(len(wire_query))
            }
            
            # Simulate failure if needed
            if self.force_failures or (self.failure_rate > 0 and random.random() < self.failure_rate):
                print(f"[DoH] Simulating failure for {domain} to {server_info['name']}")
                # Make a request to a non-existent endpoint to generate real failed traffic
                try:
                    response = requests.post(
                        server_info['url'].replace('/dns-query', '/nonexistent'),
                        data=wire_query,
                        headers=headers,
                        timeout=2
                    )
                except:
                    pass
                raise Exception("Simulated DoH failure")
            
            # Make real DoH request
            response = requests.post(
                server_info['url'],
                data=wire_query,
                headers=headers,
                timeout=5
            )
            
            if response.status_code == 200:
                print(f"[DoH] Successfully queried {domain} via {server_info['name']} ({server_info['url']})")
                return True
            else:
                print(f"[DoH] Failed with status {response.status_code}")
                raise Exception(f"DoH query failed with status {response.status_code}")
                
        except Exception as e:
            print(f"[DoH] Failed: {e}")
            raise
    
    def real_dot_query(self, domain, server_info):
        """Perform real DNS-over-TLS query"""
        try:
            # Create DNS query
            query = self.create_dns_query_message(domain)
            wire_query = query.to_wire()
            
            # Add TCP length prefix
            tcp_query = struct.pack('!H', len(wire_query)) + wire_query
            
            # Simulate failure if needed
            if self.force_failures or (self.failure_rate > 0 and random.random() < self.failure_rate):
                print(f"[DoT] Simulating failure for {domain} to {server_info['name']}")
                # Try to connect to wrong port to generate failed traffic
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    sock.connect((server_info['ip'], 854))  # Wrong port
                    sock.close()
                except:
                    pass
                raise Exception("Simulated DoT failure")
            
            # Create TCP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            # Wrap socket with TLS
            context = ssl.create_default_context()
            context.check_hostname = True
            
            # Connect and wrap with TLS
            sock.connect((server_info['ip'], 853))
            ssock = context.wrap_socket(sock, server_hostname=server_info['hostname'])
            
            # Send query
            ssock.sendall(tcp_query)
            
            # Receive response (just length for verification)
            response_length_data = ssock.recv(2)
            if len(response_length_data) == 2:
                print(f"[DoT] Successfully queried {domain} via {server_info['name']} ({server_info['ip']}:853)")
                ssock.close()
                return True
            else:
                raise Exception("Invalid DoT response")
                
        except Exception as e:
            print(f"[DoT] Failed: {e}")
            raise
        finally:
            try:
                ssock.close()
            except:
                pass
            try:
                sock.close()
            except:
                pass
    
    def real_doq_query(self, domain, server_info):
        """Perform real DNS-over-QUIC query (simplified)"""
        try:
            # For now, we'll simulate DoQ with UDP packets to port 853
            # Real DoQ implementation would require a QUIC library
            
            # Simulate failure if needed
            if self.force_failures or (self.failure_rate > 0 and random.random() < self.failure_rate):
                print(f"[DoQ] Simulating failure for {domain} to {server_info['name']}")
                # Send to wrong port to generate failed traffic
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(1)
                try:
                    # Use port 854 (wrong port) to simulate failure
                    sock.sendto(b'failed_doq_attempt', (server_info['ip'], 854))
                except:
                    pass
                finally:
                    sock.close()
                raise Exception("Simulated DoQ failure")
            
            # Create DNS query
            query = self.create_dns_query_message(domain)
            wire_query = query.to_wire()
            
            # For testing, send a UDP packet to DoQ port
            # This will be detected by the detector
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            
            # DoQ typically uses port 853 (sometimes 784 for AdGuard)
            doq_port = 853
            if 'adguard' in server_info.get('name', '').lower():
                doq_port = 784
                
            sock.sendto(wire_query, (server_info['ip'], doq_port))
            print(f"[DoQ] Successfully sent query for {domain} via {server_info['name']} ({server_info['ip']}:{doq_port})")
            sock.close()
            return True
            
        except Exception as e:
            print(f"[DoQ] Failed: {e}")
            raise
    
    def real_plaintext_dns_query(self, domain, server_info):
        """Perform real plaintext DNS query"""
        try:
            print(f"[DNS] Plaintext query for {domain} to {server_info['name']} ({server_info['ip']}:53)")
            
            # Use dnspython for the query
            query = self.create_dns_query_message(domain)
            response = dns.query.udp(query, server_info['ip'], timeout=2)
            
            if response:
                print(f"[DNS] Plaintext query successful")
                return True
            else:
                raise Exception("No response")
                
        except Exception as e:
            print(f"[DNS] Plaintext query failed: {e}")
            return False
    
    def perform_dns_resolution(self, domain):
        """Perform DNS resolution with potential fallback"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        print(f"\n[{timestamp}] Resolving {domain}")
        
        # Try DoH first
        try:
            server = random.choice(self.doh_servers['doh'])
            self.real_doh_query(domain, server)
            return 'doh'
        except Exception:
            pass
        
        # Try DoT
        try:
            server = random.choice(self.doh_servers['dot'])
            self.real_dot_query(domain, server)
            return 'dot'
        except Exception:
            pass
        
        # Try DoQ
        try:
            # Use same servers as DoT for DoQ
            server = random.choice(self.doh_servers['dot'])
            self.real_doq_query(domain, server)
            return 'doq'
        except Exception:
            pass
        
        # Fallback to plaintext
        print(f"[FALLBACK] Falling back to plaintext DNS for {domain}")
        time.sleep(0.1)  # Small delay before fallback
        
        server = random.choice(self.doh_servers['plaintext'])
        if self.real_plaintext_dns_query(domain, server):
            return 'plaintext'
        
        return 'failed'
    
    def run_traffic_generation(self, duration=60, queries_per_second=1):
        """Generate real DNS traffic"""
        print(f"Starting real DNS traffic generation for {duration} seconds")
        print(f"Failure rate: {self.failure_rate * 100}%")
        print(f"Protocols: DoH, DoT, DoQ → Plaintext DNS fallback")
        print("-" * 60)
        
        start_time = time.time()
        query_count = 0
        fallback_count = 0
        
        while time.time() - start_time < duration:
            domain = random.choice(self.test_domains)
            result = self.perform_dns_resolution(domain)
            
            query_count += 1
            if result == 'plaintext':
                fallback_count += 1
            
            # Wait before next query
            time.sleep(1.0 / queries_per_second)
        
        print("\n" + "=" * 60)
        print(f"Traffic generation completed")
        print(f"Total queries: {query_count}")
        print(f"Fallback events: {fallback_count}")
        print(f"Fallback rate: {(fallback_count/query_count)*100:.1f}%")

def main():
    parser = argparse.ArgumentParser(description='Real DNS Traffic Generator')
    parser.add_argument('--doh-domains', help='File containing DoH domain names')
    parser.add_argument('--doh-ipv4', help='File containing DoH IPv4 addresses')
    parser.add_argument('--duration', type=int, default=60, help='Generation duration in seconds')
    parser.add_argument('--qps', type=float, default=1.0, help='Queries per second')
    parser.add_argument('--failure-rate', type=float, default=0.3, help='Encrypted DNS failure rate (0.0-1.0)')
    parser.add_argument('--force-failures', action='store_true', help='Force all encrypted DNS to fail')
    
    args = parser.parse_args()
    
    # Check for dnspython
    try:
        import dns.message
    except ImportError:
        print("ERROR: dnspython is required for real DNS queries")
        print("Install it with: pip install dnspython")
        sys.exit(1)
    
    generator = RealDNSTrafficGenerator(
        doh_domains_file=args.doh_domains,
        doh_ipv4_file=args.doh_ipv4
    )
    
    generator.failure_rate = args.failure_rate
    generator.force_failures = args.force_failures
    
    try:
        generator.run_traffic_generation(duration=args.duration, queries_per_second=args.qps)
    except KeyboardInterrupt:
        print("\nTraffic generation interrupted by user")

if __name__ == "__main__":
    main()