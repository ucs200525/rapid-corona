"""
Traffic Simulator - Generate synthetic traffic for testing
Simulates normal traffic and various DDoS attack patterns
"""

import random
import time
import socket
import struct
from typing import Dict, List
from dataclasses import dataclass
from enum import Enum

import logging
logger = logging.getLogger(__name__)


class AttackType(Enum):
    """Types of DDoS attacks"""
    UDP_FLOOD = "udp_flood"
    SYN_FLOOD = "syn_flood"
    HTTP_FLOOD = "http_flood"
    ICMP_FLOOD = "icmp_flood"
    DNS_AMPLIFICATION = "dns_amplification"
    MIXED = "mixed"


@dataclass
class TrafficPattern:
    """Traffic generation pattern"""
    packets_per_second: int
    duration: float  # seconds
    source_ips: List[str]  # Empty list = random IPs
    dest_ip: str
    dest_ports: List[int]
    protocol: str  # 'tcp', 'udp', 'icmp'
    packet_size: int  # bytes


class TrafficSimulator:
    """Simulate network traffic for testing"""
    
    def __init__(self):
        self.running = False
        self.stats = {
            'packets_generated': 0,
            'bytes_generated': 0,
            'start_time': 0,
        }
    
    def generate_random_ip(self) -> str:
        """Generate a random IP address"""
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    
    def generate_normal_traffic(self, pps: int, duration: float, dest_ip: str = "10.0.0.1") -> Dict:
        """
        Generate normal traffic pattern
        
        Args:
            pps: Packets per second
            duration: Duration in seconds
            dest_ip: Destination IP
            
        Returns:
            Traffic statistics
        """
        logger.info(f"Generating normal traffic: {pps} pps for {duration}s")
        
        self.running = True
        self.stats['start_time'] = time.time()
        total_packets = int(pps * duration)
        
        # Normal traffic characteristics:
        # - 85% TCP (HTTP/HTTPS, etc.)
        # - 10% UDP (DNS, etc.)
        # - 5% ICMP
        # - Diverse source IPs
        # - Common destination ports
        
        tcp_packets = int(total_packets * 0.85)
        udp_packets = int(total_packets * 0.10)
        icmp_packets = total_packets - tcp_packets - udp_packets
        
        dest_ports_tcp = [80, 443, 8080, 22, 3306, 5432]
        dest_ports_udp = [53, 123, 161]
        
        packets_sent = 0
        bytes_sent = 0
        
        interval = 1.0 / pps if pps > 0 else 0
        
        for i in range(total_packets):
            if not self.running:
                break
            
            src_ip = self.generate_random_ip()
            
            if i < tcp_packets:
                # TCP packet
                port = random.choice(dest_ports_tcp)
                size = random.randint(64, 1500)
                protocol = 'tcp'
            elif i < tcp_packets + udp_packets:
                # UDP packet
                port = random.choice(dest_ports_udp)
                size = random.randint(64, 512)
                protocol = 'udp'
            else:
                # ICMP packet
                port = 0
                size = 64
                protocol = 'icmp'
            
            # Simulate packet (just log metadata, not actually sending)
            packets_sent += 1
            bytes_sent += size
            
            # Rate limiting
            if interval > 0:
                time.sleep(interval)
        
        self.stats['packets_generated'] = packets_sent
        self.stats['bytes_generated'] = bytes_sent
        self.running = False
        
        logger.info(f"Normal traffic complete: {packets_sent} packets, {bytes_sent} bytes")
        return self.stats.copy()
    
    def generate_attack_traffic(self, attack_type: AttackType, pps: int, duration: float, 
                               dest_ip: str = "10.0.0.1") -> Dict:
        """
        Generate attack traffic pattern
        
        Args:
            attack_type: Type of attack
            pps: Packets per second
            duration: Duration in seconds
            dest_ip: Target IP
            
        Returns:
            Traffic statistics
        """
        logger.info(f"Generating {attack_type.value} attack: {pps} pps for {duration}s")
        
        self.running = True
        self.stats['start_time'] = time.time()
        total_packets = int(pps * duration)
        
        if attack_type == AttackType.UDP_FLOOD:
            return self._generate_udp_flood(total_packets, pps, dest_ip)
        elif attack_type == AttackType.SYN_FLOOD:
            return self._generate_syn_flood(total_packets, pps, dest_ip)
        elif attack_type == AttackType.ICMP_FLOOD:
            return self._generate_icmp_flood(total_packets, pps, dest_ip)
        elif attack_type == AttackType.HTTP_FLOOD:
            return self._generate_http_flood(total_packets, pps, dest_ip)
        elif attack_type == AttackType.MIXED:
            return self._generate_mixed_attack(total_packets, pps, dest_ip)
        else:
            logger.warning(f"Unknown attack type: {attack_type}")
            return self.stats.copy()
    
    def _generate_udp_flood(self, total_packets: int, pps: int, dest_ip: str) -> Dict:
        """Generate UDP flood attack"""
        packets_sent = 0
        bytes_sent = 0
        interval = 1.0 / pps if pps > 0 else 0
        
        # UDP flood characteristics:
        # - Random or spoofed source IPs
        # - Random destination ports
        # - Large packet sizes
        
        # Simulate botnet with limited IP pool (1000-10000 IPs)
        botnet_size = min(10000, max(1000, pps // 100))
        botnet_ips = [self.generate_random_ip() for _ in range(botnet_size)]
        
        for i in range(total_packets):
            if not self.running:
                break
            
            src_ip = random.choice(botnet_ips)
            dest_port = random.randint(1024, 65535)
            size = random.randint(512, 1400)  # Large packets
            
            packets_sent += 1
            bytes_sent += size
            
            if interval > 0:
                time.sleep(interval)
        
        self.stats['packets_generated'] = packets_sent
        self.stats['bytes_generated'] = bytes_sent
        self.running = False
        
        logger.info(f"UDP flood complete: {packets_sent} packets from {botnet_size} IPs")
        return self.stats.copy()
    
    def _generate_syn_flood(self, total_packets: int, pps: int, dest_ip: str) -> Dict:
        """Generate SYN flood attack"""
        packets_sent = 0
        bytes_sent = 0
        interval = 1.0 / pps if pps > 0 else 0
        
        # SYN flood characteristics:
        # - TCP SYN packets only
        # - Randomized source IPs (spoofed)
        # - Targeting specific ports
        
        target_ports = [80, 443, 22, 8080]
        botnet_size = min(50000, max(5000, pps // 50))
        
        for i in range(total_packets):
            if not self.running:
                break
            
            src_ip = self.generate_random_ip()  # Spoofed
            dest_port = random.choice(target_ports)
            size = 64  # SYN packets are small
            
            packets_sent += 1
            bytes_sent += size
            
            if interval > 0:
                time.sleep(interval)
        
        self.stats['packets_generated'] = packets_sent
        self.stats['bytes_generated'] = bytes_sent
        self.running = False
        
        logger.info(f"SYN flood complete: {packets_sent} SYN packets")
        return self.stats.copy()
    
    def _generate_icmp_flood(self, total_packets: int, pps: int, dest_ip: str) -> Dict:
        """Generate ICMP flood attack"""
        packets_sent = 0
        bytes_sent = 0
        interval = 1.0 / pps if pps > 0 else 0
        
        # ICMP flood (ping flood)
        botnet_ips = [self.generate_random_ip() for _ in range(1000)]
        
        for i in range(total_packets):
            if not self.running:
                break
            
            src_ip = random.choice(botnet_ips)
            size = 64  # Standard ICMP packet
            
            packets_sent += 1
            bytes_sent += size
            
            if interval > 0:
                time.sleep(interval)
        
        self.stats['packets_generated'] = packets_sent
        self.stats['bytes_generated'] = bytes_sent
        self.running = False
        
        logger.info(f"ICMP flood complete: {packets_sent} packets")
        return self.stats.copy()
    
    def _generate_http_flood(self, total_packets: int, pps: int, dest_ip: str) -> Dict:
        """Generate HTTP flood (Layer 7) attack"""
        packets_sent = 0
        bytes_sent = 0
        interval = 1.0 / pps if pps > 0 else 0
        
        # HTTP flood - legitimate-looking HTTP requests
        user_agents = [
            "Mozilla/5.0", "Chrome/91.0", "Safari/537.36", "Edge/91.0"
        ]
        
        botnet_size = min(5000, max(500, pps // 100))
        botnet_ips = [self.generate_random_ip() for _ in range(botnet_size)]
        
        for i in range(total_packets):
            if not self.running:
                break
            
            src_ip = random.choice(botnet_ips)
            size = random.randint(200, 800)  # HTTP request size
            
            packets_sent += 1
            bytes_sent += size
            
            if interval > 0:
                time.sleep(interval)
        
        self.stats['packets_generated'] = packets_sent
        self.stats['bytes_generated'] = bytes_sent
        self.running = False
        
        logger.info(f"HTTP flood complete: {packets_sent} requests")
        return self.stats.copy()
    
    def _generate_mixed_attack(self, total_packets: int, pps: int, dest_ip: str) -> Dict:
        """Generate mixed multi-vector attack"""
        # Mix of UDP flood (50%), SYN flood (30%), ICMP flood (20%)
        udp_packets = int(total_packets * 0.5)
        syn_packets = int(total_packets * 0.3)
        icmp_packets = total_packets - udp_packets - syn_packets
        
        self._generate_udp_flood(udp_packets, int(pps * 0.5), dest_ip)
        self._generate_syn_flood(syn_packets, int(pps * 0.3), dest_ip)
        self._generate_icmp_flood(icmp_packets, int(pps * 0.2), dest_ip)
        
        logger.info(f"Mixed attack complete")
        return self.stats.copy()
    
    def stop(self):
        """Stop traffic generation"""
        self.running = False
        logger.info("Traffic generation stopped")
