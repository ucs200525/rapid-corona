"""
Metrics Collector - Collect and aggregate metrics for monitoring
"""

import time
import psutil
from typing import Dict
from dataclasses import dataclass, asdict


@dataclass
class SystemMetrics:
    """System performance metrics"""
    cpu_percent: float
    memory_percent: float
    memory_mb: float
    timestamp: float


class MetricsCollector:
    """Collect system and traffic metrics"""
    
    def __init__(self):
        self.start_time = time.time()
        self.metrics_history = []
    
    def collect_system_metrics(self) -> SystemMetrics:
        """Collect current system metrics"""
        memory = psutil.virtual_memory()
        
        metrics = SystemMetrics(
            cpu_percent=psutil.cpu_percent(interval=0.1),
            memory_percent=memory.percent,
            memory_mb=memory.used / (1024 * 1024),
            timestamp=time.time()
        )
        
        self.metrics_history.append(metrics)
        
        # Keep only last 1000 entries
        if len(self.metrics_history) > 1000:
            self.metrics_history = self.metrics_history[-1000:]
        
        return metrics
    
    def get_uptime(self) -> float:
        """Get system uptime in seconds"""
        return time.time() - self.start_time
    
    def format_metrics_prometheus(self, traffic_stats: Dict, system_metrics: SystemMetrics) -> str:
        """
        Format metrics in Prometheus exposition format
        
        Args:
            traffic_stats: Traffic statistics
            system_metrics: System metrics
            
        Returns:
            Prometheus-formatted metrics string
        """
        lines = []
        
        # Traffic metrics
        lines.append(f"# HELP ddos_total_packets Total packets processed")
        lines.append(f"# TYPE ddos_total_packets counter")
        lines.append(f"ddos_total_packets {traffic_stats.get('total_packets', 0)}")
        
        lines.append(f"# HELP ddos_total_bytes Total bytes processed")
        lines.append(f"# TYPE ddos_total_bytes counter")
        lines.append(f"ddos_total_bytes {traffic_stats.get('total_bytes', 0)}")
        
        lines.append(f"# HELP ddos_dropped_packets Packets dropped")
        lines.append(f"# TYPE ddos_dropped_packets counter")
        lines.append(f"ddos_dropped_packets {traffic_stats.get('dropped_packets', 0)}")
        
        lines.append(f"# HELP ddos_tcp_packets TCP packets")
        lines.append(f"# TYPE ddos_tcp_packets counter")
        lines.append(f"ddos_tcp_packets {traffic_stats.get('tcp_packets', 0)}")
        
        lines.append(f"# HELP ddos_udp_packets UDP packets")
        lines.append(f"# TYPE ddos_udp_packets counter")
        lines.append(f"ddos_udp_packets {traffic_stats.get('udp_packets', 0)}")
        
        # System metrics
        lines.append(f"# HELP ddos_cpu_percent CPU usage percentage")
        lines.append(f"# TYPE ddos_cpu_percent gauge")
        lines.append(f"ddos_cpu_percent {system_metrics.cpu_percent}")
        
        lines.append(f"# HELP ddos_memory_percent Memory usage percentage")
        lines.append(f"# TYPE ddos_memory_percent gauge")
        lines.append(f"ddos_memory_percent {system_metrics.memory_percent}")
        
        lines.append(f"# HELP ddos_uptime_seconds System uptime in seconds")
        lines.append(f"# TYPE ddos_uptime_seconds counter")
        lines.append(f"ddos_uptime_seconds {self.get_uptime()}")
        
        return '\n'.join(lines)
    
    def get_summary(self) -> Dict:
        """Get summary of recent metrics"""
        if not self.metrics_history:
            return {}
        
        recent = self.metrics_history[-60:]  # Last 60 samples
        
        avg_cpu = sum(m.cpu_percent for m in recent) / len(recent)
        avg_memory = sum(m.memory_percent for m in recent) / len(recent)
        
        return {
            'avg_cpu_percent': avg_cpu,
            'avg_memory_percent': avg_memory,
            'current_memory_mb': recent[-1].memory_mb,
            'uptime_seconds': self.get_uptime(),
        }
