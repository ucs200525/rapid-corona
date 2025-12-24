"""
Main Application - DDoS Mitigation System
Orchestrates all components for real-time DDoS detection and mitigation
"""

import argparse
import logging
import signal
import sys
import time
import threading
from pathlib import Path

# Setup logging first
import coloredlogs

from config import (
    NETWORK_INTERFACE, EBPF_PROGRAM_PATH, XDP_MODE,
    MonitoringConfig, TimeWindows, PLATFORM
)

from src.traffic_monitor import TrafficMonitor, BCC_AVAILABLE
from src.anomaly_detector import AnomalyDetector
from src.traffic_profiler import TrafficProfiler
from src.alert_system import AlertSystem
from src.metrics_collector import MetricsCollector

# Setup logging
logging.basicConfig(
    level=getattr(logging, MonitoringConfig.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(MonitoringConfig.LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)

coloredlogs.install(
    level=MonitoringConfig.LOG_LEVEL,
    fmt='%(asctime)s %(name)s[%(process)d] %(levelname)s %(message)s'
)

logger = logging.getLogger(__name__)


class DDoSMitigationSystem:
    """Main application class"""
    
    def __init__(self, interface: str, xdp_mode: str = 'native'):
        self.interface = interface
        self.xdp_mode = xdp_mode
        self.running = False
        
        # Initialize components
        self.traffic_monitor = None
        self.anomaly_detector = AnomalyDetector()
        self.traffic_profiler = TrafficProfiler()
        self.alert_system = AlertSystem()
        self.metrics_collector = MetricsCollector()
        
        # Signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        logger.info("Shutdown signal received, stopping...")
        self.stop()
        sys.exit(0)
    
    def start(self):
        """Start the DDoS mitigation system"""
        logger.info("=" * 70)
        logger.info("DDoS Mitigation System - Phase 1: Baseline Anomaly Detection")
        logger.info("=" * 70)
        logger.info(f"Platform: {PLATFORM}")
        logger.info(f"Interface: {self.interface}")
        logger.info(f"XDP Mode: {self.xdp_mode}")
        logger.info("=" * 70)
        
        # Check for eBPF support
        if not BCC_AVAILABLE:
            logger.error("BCC/eBPF not available!")
            logger.error("Please install: sudo apt-get install python3-bpfcc (Linux)")
            logger.error("Or: Install Microsoft eBPF runtime (Windows)")
            return False
        
        # Initialize traffic monitor
        try:
            self.traffic_monitor = TrafficMonitor(self.interface, self.xdp_mode)
            
            # Check if eBPF program exists
            if not Path(EBPF_PROGRAM_PATH).exists():
                logger.error(f"eBPF program not found: {EBPF_PROGRAM_PATH}")
                logger.error("Please compile: cd src/ebpf && make")
                return False
            
            # Load XDP program
            if not self.traffic_monitor.load_xdp_program(EBPF_PROGRAM_PATH):
                logger.error("Failed to load XDP program")
                return False
            
            logger.info("✓ XDP program loaded successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize traffic monitor: {e}")
            return False
        
        # Start monitoring loop
        self.running = True
        self._monitoring_loop()
        
        return True
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        logger.info("Starting monitoring loop...")
        logger.info(f"Learning period: {TimeWindows.BASELINE_WINDOW}s")
        
        iteration = 0
        
        while self.running:
            try:
                iteration += 1
                
                # Read statistics from eBPF
                stats = self.traffic_monitor.get_statistics()
                ip_stats = self.traffic_monitor.get_ip_statistics(limit=1000)
                
                # Calculate current rates
                current_time = time.time()
                if iteration > 1:
                    time_delta = TimeWindows.STATISTICS_UPDATE
                    
                    prev_packets = getattr(self, '_prev_total_packets', 0)
                    prev_bytes = getattr(self, '_prev_total_bytes', 0)
                    
                    current_pps = (stats.get('total_packets', 0) - prev_packets) / time_delta
                    current_bps = (stats.get('total_bytes', 0) - prev_bytes) / time_delta
                else:
                    current_pps = 0
                    current_bps = 0
                
                # Store for get_status() API
                self._current_pps = current_pps
                self._current_bps = current_bps
                self._prev_total_packets = stats.get('total_packets', 0)
                self._prev_total_bytes = stats.get('total_bytes', 0)
                
                # Update baseline and profile
                self.anomaly_detector.update_baseline(stats)
                self.traffic_profiler.update_profile(stats, current_pps, current_bps)
                
                # Detect anomalies
                anomaly_result = self.anomaly_detector.detect_anomaly(stats, ip_stats)
                
                # Handle detected anomalies
                if anomaly_result.is_anomaly:
                    if self.anomaly_detector.should_alert('ddos_attack'):
                        self.alert_system.send_alert(
                            alert_type='ddos_attack',
                            severity='high' if anomaly_result.score >= 75 else 'medium',
                            message=f"DDoS attack detected (score: {anomaly_result.score:.1f})",
                            details={
                                'reasons': anomaly_result.reasons,
                                'metrics': anomaly_result.metrics,
                                'current_pps': current_pps,
                                'baseline_pps': self.anomaly_detector.baseline.mean_pps,
                            }
                        )
                        
                        # Add top attackers to blacklist
                        if ip_stats:
                            top_ips = sorted(ip_stats, key=lambda x: x['packets'], reverse=True)[:5]
                            for ip_stat in top_ips:
                                if ip_stat['packets'] > 10000:  # Threshold for blacklisting
                                    self.traffic_monitor.add_to_blacklist(ip_stat['ip'])
                                    logger.warning(f"Blacklisted: {ip_stat['ip']} ({ip_stat['packets']} packets)")
                
                # Collect system metrics
                system_metrics = self.metrics_collector.collect_system_metrics()
                
                # Log status (every 10 iterations)
                if iteration % 10 == 0:
                    logger.info(f"Status: {current_pps:.0f} pps | "
                               f"Baseline: {self.anomaly_detector.baseline.mean_pps:.0f} pps | "
                               f"IPs: {len(ip_stats)} | "
                               f"Drop rate: {stats.get('dropped_packets', 0)} | "
                               f"CPU: {system_metrics.cpu_percent:.1f}%")
                
                # Sleep until next update
                time.sleep(TimeWindows.STATISTICS_UPDATE)
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}", exc_info=True)
                time.sleep(1)
        
        logger.info("Monitoring loop stopped")
    
    def stop(self):
        """Stop the system and cleanup"""
        logger.info("Stopping DDoS mitigation system...")
        self.running = False
        
        if self.traffic_monitor:
            self.traffic_monitor.unload_xdp_program()
        
        # Save profile
        if self.traffic_profiler:
            self.traffic_profiler.save_profile()
        
        logger.info("System stopped")
    
    def get_status(self) -> dict:
        """Get current system status"""
        stats = self.traffic_monitor.get_statistics() if self.traffic_monitor else {}
        baseline = self.anomaly_detector.get_baseline_info()
        profile = self.traffic_profiler.get_profile()
        blacklist = self.traffic_monitor.get_blacklist() if self.traffic_monitor else []
        ip_stats = self.traffic_monitor.get_ip_statistics(limit=20) if self.traffic_monitor else []
        
        # Calculate current rates for real-time display
        current_pps = getattr(self, '_current_pps', 0)
        current_bps = getattr(self, '_current_bps', 0)
        
        return {
            'running': self.running,
            'interface': self.interface,
            'statistics': stats,
            'baseline': baseline,
            'profile': profile.__dict__ if profile else {},
            'blacklist': blacklist,
            'recent_alerts': self.alert_system.get_recent_alerts(10),
            'ip_stats': ip_stats[:10],  # Top 10 IPs
            'current_pps': current_pps,
            'current_bps': current_bps,
        }


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='DDoS Mitigation System - Phase 1',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run on Linux with native XDP
  sudo python main.py --interface eth0
  
  # Run with generic XDP (works on all interfaces)
  sudo python main.py --interface eth0 --mode generic
  
  # Run on Windows
  python main.py --interface "Ethernet"
        """
    )
    
    parser.add_argument(
        '--interface', '-i',
        default=NETWORK_INTERFACE,
        help=f'Network interface to monitor (default: {NETWORK_INTERFACE})'
    )
    
    parser.add_argument(
        '--mode', '-m',
        choices=['native', 'generic', 'offload'],
        default=XDP_MODE,
        help=f'XDP mode (default: {XDP_MODE})'
    )
    
    parser.add_argument(
        '--debug', '-d',
        action='store_true',
        help='Enable debug logging'
    )
    
    parser.add_argument(
        '--dashboard',
        action='store_true',
        help='Enable web dashboard (default port: 5000)'
    )
    
    parser.add_argument(
        '--port', '-p',
        type=int,
        default=5000,
        help='Dashboard port (default: 5000)'
    )
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.setLevel(logging.DEBUG)
    
    # Check for root/admin privileges
    if PLATFORM == 'linux':
        import os
        if os.geteuid() != 0:
            logger.error("This program must be run with sudo/root privileges on Linux")
            logger.error("Try: sudo python main.py --interface eth0")
            sys.exit(1)
    
    # Start system
    system = DDoSMitigationSystem(args.interface, args.mode)
    
    # Start dashboard in background thread if enabled
    if args.dashboard:
        from src.dashboard import run_dashboard
        dashboard_thread = threading.Thread(
            target=run_dashboard,
            args=(system, '0.0.0.0', args.port),
            daemon=True
        )
        dashboard_thread.start()
        logger.info(f"Dashboard started at http://localhost:{args.port}")
    
    try:
        success = system.start()
        if not success:
            sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        system.stop()
        sys.exit(1)


if __name__ == '__main__':
    main()
