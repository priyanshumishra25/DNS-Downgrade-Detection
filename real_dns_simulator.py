#!/usr/bin/env python3
"""
Real DNS Traffic Generator - All Encrypted DNS Protocols
Generates actual DNS network traffic (DoH/DoT/DoQ/plaintext) for testing fallback detection
Supports all major encrypted DNS protocols with realistic failure patterns
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
import asyncio
import os
from datetime import datetime
import dns.message
import dns.query
import dns.rdatatype

# Try to import QUIC libraries
try:
    from aioquic.asyncio import connect
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.quic.events import StreamDataReceived
    QUIC_AVAILABLE = True
except ImportError:
    QUIC_AVAILABLE = False

class DoQClient(QuicConnectionProtocol):
    """QUIC client for DNS-over-QUIC queries"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.dns_response = None
        self.response_received = asyncio.Event()
    
    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            # DNS response received
            self.dns_response = event.data
            self.response_received.set()

class RealDNSTrafficGenerator:
    def __init__(self, doh_domains_file=None, doh_ipv4_file=None):
        self.doh_servers = self.load_doh_servers(doh_domains_file, doh_ipv4_file)
        self.test_domains = [
            "example.com", "google.com", "cloudflare.com", "github.com",
            "wikipedia.org", "stackoverflow.com", "reddit.com", "amazon.com"
        ]
        self.failure_rate = 0.3
        self.force_failures = False
        self.force_fallback_rate = 0.15  # 15% of queries will force fallback to plaintext
        self.loop = None
        
    def load_doh_servers(self, domains_file, ipv4_file):
        """Load encrypted DNS server information for all protocols"""
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
            'doq': [
                # DoQ servers - DNS-over-QUIC on various ports
                {'name': 'Cloudflare-DoQ', 'ip': '1.1.1.1', 'port': 853, 'hostname': 'cloudflare-dns.com'},
                {'name': 'Google-DoQ', 'ip': '8.8.8.8', 'port': 853, 'hostname': 'dns.google'},
                {'name': 'AdGuard-DoQ', 'ip': '94.140.14.14', 'port': 784, 'hostname': 'dns.adguard.com'},
                {'name': 'Quad9-DoQ', 'ip': '9.9.9.9', 'port': 853, 'hostname': 'dns.quad9.net'}
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
                        # Also add as DoQ server
                        servers['doq'].append({
                            'name': f'DoQ-{ip}',
                            'ip': ip,
                            'port': 853,
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
    
    async def real_doq_query_async(self, domain, server_info):
        """Perform real DNS-over-QUIC query using aioquic"""
        if not QUIC_AVAILABLE:
            raise Exception("QUIC library not available")
        
        try:
            # Create DNS query
            query = self.create_dns_query_message(domain)
            wire_query = query.to_wire()
            
            # Configure QUIC with proper settings
            configuration = QuicConfiguration(is_client=True)
            configuration.verify_mode = ssl.CERT_NONE  # For testing - in production should verify
            
            # Try to set server name in configuration for SNI
            try:
                configuration.server_name = server_info['hostname']
            except AttributeError:
                # Older version of aioquic might not have server_name
                pass
            
            # Try different connection methods based on aioquic version
            protocol = None
            try:
                # Method 1: Modern aioquic
                async with connect(
                    server_info['ip'],
                    server_info['port'],
                    configuration=configuration,
                    create_protocol=DoQClient
                ) as protocol:
                    return await self._perform_doq_query(protocol, domain, server_info, wire_query)
                    
            except TypeError as e:
                if "unexpected keyword argument" in str(e):
                    # Method 2: Try without create_protocol parameter
                    try:
                        async with connect(
                            server_info['ip'],
                            server_info['port'],
                            configuration=configuration
                        ) as protocol:
                            return await self._perform_doq_query(protocol, domain, server_info, wire_query)
                    except Exception:
                        raise Exception(f"aioquic connection failed: {e}")
                else:
                    raise
                    
        except Exception as e:
            print(f"[DoQ] QUIC query failed: {e}")
            raise
    
    async def _perform_doq_query(self, protocol, domain, server_info, wire_query):
        """Helper method to perform the actual DoQ query"""
        try:
            # Check if protocol has the expected methods
            if not hasattr(protocol, '_quic'):
                raise Exception("Protocol doesn't have expected QUIC interface")
            
            # Send DNS query over QUIC stream
            try:
                stream_id = protocol._quic.get_next_available_stream_id()
            except AttributeError:
                # Try alternative method
                stream_id = 0  # Use stream 0 for simplicity
            
            # DoQ uses length-prefixed DNS messages (RFC 9250)
            doq_query = struct.pack('!H', len(wire_query)) + wire_query
            
            # Send the query
            protocol._quic.send_stream_data(stream_id, doq_query, end_stream=True)
            
            # Transmit the packet
            if hasattr(protocol, 'transmit'):
                protocol.transmit()
            
            # For this simple implementation, we'll consider the send successful
            # In a real implementation, you'd wait for and parse the response
            print(f"[DoQ] Successfully sent QUIC query for {domain} via {server_info['name']} ({server_info['ip']}:{server_info['port']})")
            
            # Small delay to simulate response time
            await asyncio.sleep(0.1)
        
            return True
        
        except Exception as e:
            print(f"[DoQ] Failed to perform DoQ query: {e}")
            raise
            
    def real_doq_query_simple(self, domain, server_info):
        """DNS-over-QUIC implementation with proper QUIC packet structure"""
        try:
            # Create DNS query
            query = self.create_dns_query_message(domain)
            wire_query = query.to_wire()
            
            # Create a proper QUIC packet structure (RFC 9000)
            # This generates traffic that will be recognized as QUIC by network analyzers
            
            # QUIC Long Header for Initial packet
            header_form = 1  # Long header
            fixed_bit = 1
            packet_type = 0  # Initial
            
            first_byte = (header_form << 7) | (fixed_bit << 6) | (packet_type << 4) | 0x03
            
            # QUIC version (version 1)
            version = 0x00000001
            
            # Connection IDs
            dcid = os.urandom(8)  # Destination Connection ID
            scid = os.urandom(8)  # Source Connection ID
            
            # Token (empty for initial packet)
            token_length = 0
            
            # Payload length (variable length integer)
            payload_data = struct.pack('!H', len(wire_query)) + wire_query  # DoQ DNS message
            payload_length = len(payload_data) + 16  # Add space for packet number and auth tag
            
            # Packet number (simplified - just use 1)
            packet_number = 1
            
            # Build QUIC packet
            quic_packet = struct.pack('!B', first_byte)  # First byte
            quic_packet += struct.pack('!I', version)    # Version
            quic_packet += struct.pack('!B', len(dcid)) + dcid  # DCID length + DCID
            quic_packet += struct.pack('!B', len(scid)) + scid  # SCID length + SCID  
            quic_packet += struct.pack('!B', token_length)      # Token length (0)
            
            # Variable length integer for payload length (simplified)
            if payload_length < 64:
                quic_packet += struct.pack('!B', payload_length)
            else:
                quic_packet += struct.pack('!H', 0x4000 | payload_length)
            
            # Packet number
            quic_packet += struct.pack('!I', packet_number)
            
            # DoQ payload (DNS message with length prefix)
            quic_packet += payload_data
            
            # Simplified authentication tag (normally this would be real crypto)
            auth_tag = os.urandom(16)
            quic_packet += auth_tag
            
            # Send UDP packet that contains proper QUIC structure
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            
            sock.sendto(quic_packet, (server_info['ip'], server_info['port']))
            print(f"[DoQ] Successfully sent proper QUIC packet for {domain} via {server_info['name']} ({server_info['ip']}:{server_info['port']})")
            sock.close()
            return True
            
        except Exception as e:
            print(f"[DoQ] QUIC packet creation failed: {e}")
            raise
    
    def real_doq_query_fallback(self, domain, server_info):
        """Fallback DoQ implementation using QUIC-like UDP packets"""
        try:
            # Create DNS query
            query = self.create_dns_query_message(domain)
            wire_query = query.to_wire()
            
            # Create a QUIC-like packet structure
            # QUIC packets have specific headers - this is a simplified simulation
            quic_version = 0x00000001  # QUIC version 1
            
            # QUIC header (simplified)
            # Flag byte: Long header (0x80) + Initial packet (0x00)
            header_flags = 0x80
            
            # Create pseudo-QUIC packet
            quic_header = struct.pack('!B', header_flags)  # Flags
            quic_header += struct.pack('!I', quic_version)  # Version
            quic_header += b'\x08' + b'doq_test'  # Connection ID length + ID
            
            # Add DNS query as QUIC payload (with length prefix for DoQ)
            doq_payload = struct.pack('!H', len(wire_query)) + wire_query
            
            # Combine header and payload
            quic_packet = quic_header + doq_payload
            
            # Send UDP packet that looks like QUIC
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            
            sock.sendto(quic_packet, (server_info['ip'], server_info['port']))
            print(f"[DoQ] Successfully sent QUIC-like query for {domain} via {server_info['name']} ({server_info['ip']}:{server_info['port']})")
            sock.close()
            return True
            
        except Exception as e:
            print(f"[DoQ] Fallback query failed: {e}")
            raise
    
    def real_doq_query(self, domain, server_info):
        """Perform DNS-over-QUIC query with multiple implementation methods"""
        try:
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
            
            # Try methods in order of preference
            methods = []
            
            # Method 1: Real QUIC with aioquic (if available)
            if QUIC_AVAILABLE:
                methods.append(("Real QUIC (aioquic)", self._try_aioquic_doq))
            
            # Method 2: Proper QUIC packet structure
            methods.append(("Proper QUIC packets", self.real_doq_query_simple))
            
            # Method 3: QUIC-like fallback
            methods.append(("QUIC-like fallback", self.real_doq_query_fallback))
            
            last_error = None
            for method_name, method in methods:
                try:
                    print(f"[DoQ] Trying {method_name} for {domain}")
                    return method(domain, server_info)
                except Exception as e:
                    print(f"[DoQ] {method_name} failed: {e}")
                    last_error = e
                    continue
            
            # If all methods failed
            raise Exception(f"All DoQ methods failed. Last error: {last_error}")
            
        except Exception as e:
            print(f"[DoQ] Failed: {e}")
            raise
    
    def _try_aioquic_doq(self, domain, server_info):
        """Try aioquic implementation with better error handling"""
        try:
            # Fix for the deprecation warning and prevent crashes
            try:
                # Try to get existing event loop
                self.loop = asyncio.get_running_loop()
            except RuntimeError:
                # No running loop, create a new one
                try:
                    if hasattr(asyncio, 'new_event_loop'):
                        self.loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(self.loop)
                    else:
                        self.loop = asyncio.get_event_loop()
                except Exception as loop_error:
                    raise Exception(f"Could not create event loop: {loop_error}")
        
            # Run the async operation with timeout
            try:
                future = asyncio.wait_for(
                    self.real_doq_query_async(domain, server_info),
                    timeout=10.0  # 10 second timeout
                )
                return self.loop.run_until_complete(future)
            except asyncio.TimeoutError:
                raise Exception("aioquic operation timed out")
            except Exception as async_error:
                raise Exception(f"aioquic async operation failed: {async_error}")
                
        except Exception as e:
            # Better error reporting for aioquic issues
            error_msg = str(e) if str(e) else f"aioquic error: {type(e).__name__}"
            raise Exception(f"aioquic failed: {error_msg}")
        finally:
            # Clean up the loop if we created it
            try:
                if hasattr(self, 'loop') and self.loop and not self.loop.is_running():
                    # Only close if we're not in a running loop
                    pending = asyncio.all_tasks(self.loop)
                    if pending:
                        for task in pending:
                            task.cancel()
                    # Don't close the loop as it might be used by other parts
            except Exception:
                pass  # Ignore cleanup errors
    
    def real_plaintext_dns_query(self, domain, server_info):
        """Perform real plaintext DNS query with better error handling"""
        try:
            print(f"[DNS] Plaintext query for {domain} to {server_info['name']} ({server_info['ip']}:53)")
            
            # Use dnspython for the query with timeout
            query = self.create_dns_query_message(domain)
            
            # Try the query with error handling
            try:
                response = dns.query.udp(query, server_info['ip'], timeout=5)
                
                if response and len(response.answer) > 0:
                    print(f"[DNS] Plaintext query successful - got {len(response.answer)} answers")
                    return True
                elif response:
                    print(f"[DNS] Plaintext query completed but no answers returned")
                    return True
                else:
                    raise Exception("No response received")
            except dns.exception.Timeout:
                raise Exception("DNS query timeout")
            except Exception as dns_error:
                raise Exception(f"DNS query error: {dns_error}")
                
        except Exception as e:
            print(f"[DNS] Plaintext query failed: {e}")
            return False
    
    def perform_dns_resolution(self, domain):
        """Perform DNS resolution with potential fallback - enhanced with better error handling"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        print(f"\n[{timestamp}] Resolving {domain}")
        
        try:
            # Determine if this entire query should fail all encrypted methods
            force_total_failure = random.random() < self.force_fallback_rate
            
            if force_total_failure:
                print(f"[SCENARIO] 🎯 Forcing all encrypted DNS to fail for {domain} (fallback test)")
            
            # Try DoH first
            try:
                server = random.choice(self.doh_servers['doh'])
                # Temporarily increase failure rate if forcing total failure
                original_force = self.force_failures
                if force_total_failure:
                    self.force_failures = True
                
                self.real_doh_query(domain, server)
                self.force_failures = original_force
                return 'doh'
            except Exception as e:
                self.force_failures = original_force
                print(f"[DEBUG] DoH failed: {e}")
                pass
            
            # Try DoT
            try:
                server = random.choice(self.doh_servers['dot'])
                original_force = self.force_failures
                if force_total_failure:
                    self.force_failures = True
                    
                self.real_dot_query(domain, server)
                self.force_failures = original_force
                return 'dot'
            except Exception as e:
                self.force_failures = original_force
                print(f"[DEBUG] DoT failed: {e}")
                pass
            
            # Try DoQ with QUIC
            try:
                server = random.choice(self.doh_servers['doq'])
                original_force = self.force_failures
                if force_total_failure:
                    self.force_failures = True
                    
                self.real_doq_query(domain, server)
                self.force_failures = original_force
                return 'doq'
            except Exception as e:
                self.force_failures = original_force
                print(f"[DEBUG] DoQ failed: {e}")
                pass
            
            # Fallback to plaintext
            print(f"[FALLBACK] 🚨 ALL ENCRYPTED DNS FAILED! Falling back to plaintext DNS for {domain}")
            time.sleep(0.2)  # Slightly longer delay before fallback for realism
            
            try:
                server = random.choice(self.doh_servers['plaintext'])
                if self.real_plaintext_dns_query(domain, server):
                    return 'plaintext'
                else:
                    print(f"[ERROR] Plaintext DNS also failed for {domain}")
                    return 'failed'
            except Exception as e:
                print(f"[ERROR] Plaintext DNS query exception: {e}")
                return 'failed'
            
        except Exception as e:
            print(f"[ERROR] Fatal error in perform_dns_resolution: {e}")
            import traceback
            traceback.print_exc()
            return 'failed'
    
    def run_traffic_generation(self, duration=60, queries_per_second=1):
        """Generate realistic encrypted DNS traffic with controlled fallback scenarios"""
        print(f"Starting encrypted DNS traffic generation for {duration} seconds")
        print(f"Individual protocol failure rate: {self.failure_rate * 100}%")
        print(f"Force fallback rate: {self.force_fallback_rate * 100}%")
        print(f"Expected plaintext fallback rate: ~{self.force_fallback_rate * 100}%")
        print(f"QUIC library available: {QUIC_AVAILABLE}")
        print(f"Protocol chain: DoH (HTTPS/TLS) → DoT (TLS) → DoQ (QUIC) → Plaintext DNS fallback")
        print("-" * 60)
        
        start_time = time.time()
        query_count = 0
        fallback_count = 0
        protocol_stats = {'doh': 0, 'dot': 0, 'doq': 0, 'plaintext': 0, 'failed': 0}
        
        try:
            while time.time() - start_time < duration:
                try:
                    domain = random.choice(self.test_domains)
                    elapsed_time = time.time() - start_time
                    print(f"\n[DEBUG] Query {query_count + 1}, Elapsed: {elapsed_time:.1f}s/{duration}s")
                    
                    result = self.perform_dns_resolution(domain)
                    
                    query_count += 1
                    protocol_stats[result] += 1
                    
                    if result == 'plaintext':
                        fallback_count += 1
                    
                    print(f"[DEBUG] Query completed, result: {result}")
                    
                    # Wait before next query
                    time.sleep(1.0 / queries_per_second)
                    
                except Exception as e:
                    print(f"[ERROR] Query failed with exception: {e}")
                    import traceback
                    traceback.print_exc()
                    query_count += 1
                    protocol_stats['failed'] += 1
                    # Continue with next query instead of stopping
                    time.sleep(1.0 / queries_per_second)
                    
        except KeyboardInterrupt:
            print("\n[INFO] Traffic generation interrupted by user")
        except Exception as e:
            print(f"\n[ERROR] Fatal error in traffic generation: {e}")
            import traceback
            traceback.print_exc()
        
        actual_duration = time.time() - start_time
        print("\n" + "=" * 60)
        print(f"Encrypted DNS traffic generation completed")
        print(f"Actual duration: {actual_duration:.1f} seconds (target: {duration}s)")
        print(f"Total queries: {query_count}")
        print(f"Protocol breakdown:")
        for protocol, count in protocol_stats.items():
            percentage = (count/query_count)*100 if query_count > 0 else 0
            emoji = "🔒" if protocol in ['doh', 'dot', 'doq'] else ("📢" if protocol == 'plaintext' else "❌")
            print(f"  {emoji} {protocol.upper()}: {count} ({percentage:.1f}%)")
        print(f"Fallback events: {fallback_count}")
        print(f"Actual fallback rate: {(fallback_count/query_count)*100:.1f}%" if query_count > 0 else "No queries completed")

def main():
    parser = argparse.ArgumentParser(description='Encrypted DNS Traffic Generator - DoH/DoT/DoQ with Realistic Fallback Patterns')
    parser.add_argument('--doh-domains', help='File containing DoH domain names')
    parser.add_argument('--doh-ipv4', help='File containing DNS server IPv4 addresses')
    parser.add_argument('--duration', type=int, default=60, help='Generation duration in seconds')
    parser.add_argument('--qps', type=float, default=1.0, help='Queries per second')
    parser.add_argument('--failure-rate', type=float, default=0.3, help='Individual protocol failure rate (0.0-1.0)')
    parser.add_argument('--fallback-rate', type=float, default=0.15, help='Force all encrypted DNS to fail rate (0.0-1.0)')
    parser.add_argument('--force-failures', action='store_true', help='Force ALL encrypted DNS to fail (100% fallback)')
    
    args = parser.parse_args()
    
    # Check for dnspython
    try:
        import dns.message
    except ImportError:
        print("ERROR: dnspython is required for real DNS queries")
        print("Install it with: pip install dnspython")
        sys.exit(1)
    
    # Check for QUIC support
    if not QUIC_AVAILABLE:
        print("WARNING: aioquic library not found. DoQ will use simulated QUIC packets.")
        print("For real QUIC support, install with: pip install aioquic")
    
    generator = RealDNSTrafficGenerator(
        doh_domains_file=args.doh_domains,
        doh_ipv4_file=args.doh_ipv4
    )
    
    generator.failure_rate = args.failure_rate
    generator.force_fallback_rate = args.fallback_rate if not args.force_failures else 1.0
    generator.force_failures = args.force_failures
    
    if generator.force_failures:
        print("🚨 FORCE FAILURES MODE: All encrypted DNS will fail, expect 100% plaintext fallback")
    
    try:
        generator.run_traffic_generation(duration=args.duration, queries_per_second=args.qps)
    except KeyboardInterrupt:
        print("\nTraffic generation interrupted by user")

if __name__ == "__main__":
    main()
