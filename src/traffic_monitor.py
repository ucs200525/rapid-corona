"""
Traffic Monitor - User-space controller for eBPF/XDP programs
Loads XDP programs and reads statistics from eBPF maps
"""

import platform
import logging
import struct
import socket
import time
from typing import Dict, List, Tuple, Optional

# Platform-specific imports
PLATFORM = platform.system().lower()

if PLATFORM == 'linux':
    try:
        from bcc import BPF
        BCC_AVAILABLE = True
    except ImportError:
        BCC_AVAILABLE = False
        logging.warning("BCC not available. Install with: sudo apt-get install python3-bpfcc")
else:  # Windows
    # Microsoft eBPF bindings (placeholder - will need actual implementation)
    BCC_AVAILABLE = False
    logging.warning("Microsoft eBPF support not yet implemented")

logger = logging.getLogger(__name__)


class TrafficMonitor:
    """Monitor traffic using eBPF/XDP programs"""
    
    def __init__(self, interface: str, xdp_mode: str = 'native'):
        """
        Initialize traffic monitor
        
        Args:
            interface: Network interface name (e.g., 'eth0', 'Ethernet')
            xdp_mode: XDP mode - 'native', 'generic', or 'offload'
        """
        self.interface = interface
        self.xdp_mode = xdp_mode
        self.bpf = None
        self.loaded = False
        
        if not BCC_AVAILABLE:
            raise RuntimeError("BCC/eBPF not available on this system")
    
    def load_xdp_program(self, program_path: str) -> bool:
        """
        Load XDP program onto the network interface
        
        Args:
            program_path: Path to compiled BPF object file
            
        Returns:
            True if loaded successfully
        """
        try:
            # Load the BPF program
            with open(program_path, 'rb') as f:
                self.bpf = BPF(text="", obj=f.read())
            
            # Get the XDP function
            fn = self.bpf.load_func("xdp_ddos_filter", BPF.XDP)
            
            # Attach to interface
            flags = 0
            if self.xdp_mode == 'generic':
                flags = 2  # XDP_FLAGS_SKB_MODE
            elif self.xdp_mode == 'native':
                flags = 1  # XDP_FLAGS_DRV_MODE
            elif self.xdp_mode == 'offload':
                flags = 4  # XDP_FLAGS_HW_MODE
            
            self.bpf.attach_xdp(self.interface, fn, flags)
            self.loaded = True
            
            logger.info(f"XDP program loaded on {self.interface} (mode: {self.xdp_mode})")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load XDP program: {e}")
            return False
    
    def unload_xdp_program(self):
        """Unload XDP program from interface"""
        if self.bpf and self.loaded:
            try:
                self.bpf.remove_xdp(self.interface)
                logger.info(f"XDP program unloaded from {self.interface}")
            except Exception as e:
                logger.error(f"Failed to unload XDP program: {e}")
            finally:
                self.loaded = False
    
    def get_statistics(self) -> Dict:
        """
        Read overall statistics from eBPF maps
        
        Returns:
            Dictionary with aggregated statistics
        """
        if not self.loaded:
            return {}
        
        try:
            stats_map = self.bpf.get_table("stats_map")
            
            # Aggregate per-CPU stats
            total_stats = {
                'total_packets': 0,
                'total_bytes': 0,
                'dropped_packets': 0,
                'dropped_bytes': 0,
                'passed_packets': 0,
                'passed_bytes': 0,
                'tcp_packets': 0,
                'udp_packets': 0,
                'icmp_packets': 0,
                'other_packets': 0,
            }
            
            # BCC automatically aggregates per-CPU maps
            key = 0
            stats = stats_map[key]
            
            for field in total_stats.keys():
                total_stats[field] = getattr(stats, field, 0)
            
            return total_stats
            
        except Exception as e:
            logger.error(f"Failed to read statistics: {e}")
            return {}
    
    def get_ip_statistics(self, limit: int = 100) -> List[Dict]:
        """
        Get per-IP statistics
        
        Args:
            limit: Maximum number of IPs to return
            
        Returns:
            List of dictionaries with IP statistics
        """
        if not self.loaded:
            return []
        
        try:
            ip_map = self.bpf.get_table("ip_tracking_map")
            ip_stats = []
            
            count = 0
            for key, value in ip_map.items():
                if count >= limit:
                    break
                
                ip_addr = socket.inet_ntoa(struct.pack('I', key.value))
                
                ip_stats.append({
                    'ip': ip_addr,
                    'packets': value.packets,
                    'bytes': value.bytes,
                    'flow_count': value.flow_count,
                    'syn_count': value.syn_count,
                    'udp_count': value.udp_count,
                    'last_seen': value.last_seen,
                })
                
                count += 1
            
            # Sort by packet count (descending)
            ip_stats.sort(key=lambda x: x['packets'], reverse=True)
            return ip_stats
            
        except Exception as e:
            logger.error(f"Failed to read IP statistics: {e}")
            return []
    
    def get_flow_statistics(self, limit: int = 100) -> List[Dict]:
        """
        Get flow statistics
        
        Args:
            limit: Maximum number of flows to return
            
        Returns:
            List of dictionaries with flow statistics
        """
        if not self.loaded:
            return []
        
        try:
            flow_map = self.bpf.get_table("flow_map")
            flows = []
            
            count = 0
            for key, value in flow_map.items():
                if count >= limit:
                    break
                
                src_ip = socket.inet_ntoa(struct.pack('I', key.src_ip))
                dst_ip = socket.inet_ntoa(struct.pack('I', key.dst_ip))
                
                flows.append({
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': key.src_port,
                    'dst_port': key.dst_port,
                    'protocol': key.protocol,
                    'packets': value.packets,
                    'bytes': value.bytes,
                    'last_seen': value.last_seen,
                })
                
                count += 1
            
            # Sort by packet count (descending)
            flows.sort(key=lambda x: x['packets'], reverse=True)
            return flows
            
        except Exception as e:
            logger.error(f"Failed to read flow statistics: {e}")
            return []
    
    def add_to_blacklist(self, ip_address: str) -> bool:
        """
        Add IP to blacklist
        
        Args:
            ip_address: IP address to block (dotted decimal)
            
        Returns:
            True if added successfully
        """
        if not self.loaded:
            return False
        
        try:
            blacklist_map = self.bpf.get_table("blacklist_map")
            ip_int = struct.unpack('I', socket.inet_aton(ip_address))[0]
            timestamp = int(time.time() * 1_000_000_000)  # nanoseconds
            
            blacklist_map[blacklist_map.Key(ip_int)] = blacklist_map.Leaf(timestamp)
            logger.info(f"Added {ip_address} to blacklist")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add {ip_address} to blacklist: {e}")
            return False
    
    def remove_from_blacklist(self, ip_address: str) -> bool:
        """
        Remove IP from blacklist
        
        Args:
            ip_address: IP address to unblock
            
        Returns:
            True if removed successfully
        """
        if not self.loaded:
            return False
        
        try:
            blacklist_map = self.bpf.get_table("blacklist_map")
            ip_int = struct.unpack('I', socket.inet_aton(ip_address))[0]
            
            del blacklist_map[blacklist_map.Key(ip_int)]
            logger.info(f"Removed {ip_address} from blacklist")
            return True
            
        except Exception as e:
            logger.error(f"Failed to remove {ip_address} from blacklist: {e}")
            return False
    
    def get_blacklist(self) -> List[str]:
        """
        Get current blacklist
        
        Returns:
            List of blacklisted IP addresses
        """
        if not self.loaded:
            return []
        
        try:
            blacklist_map = self.bpf.get_table("blacklist_map")
            blacklist = []
            
            for key in blacklist_map.keys():
                ip_addr = socket.inet_ntoa(struct.pack('I', key.value))
                blacklist.append(ip_addr)
            
            return blacklist
            
        except Exception as e:
            logger.error(f"Failed to read blacklist: {e}")
            return []
    
    def update_config(self, rate_limit_pps: int = 0, blacklist_enabled: bool = True) -> bool:
        """
        Update configuration
        
        Args:
            rate_limit_pps: Per-IP rate limit (0 = disabled)
            blacklist_enabled: Enable blacklist filtering
            
        Returns:
            True if updated successfully
        """
        if not self.loaded:
            return False
        
        try:
            config_map = self.bpf.get_table("config_map")
            
            config = config_map.Leaf()
            config.rate_limit_pps = rate_limit_pps
            config.rate_limit_enabled = 1 if rate_limit_pps > 0 else 0
            config.blacklist_enabled = 1 if blacklist_enabled else 0
            config.signature_enabled = 0  # Future feature
            
            config_map[config_map.Key(0)] = config
            logger.info(f"Updated config: rate_limit={rate_limit_pps}, blacklist={blacklist_enabled}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update config: {e}")
            return False
