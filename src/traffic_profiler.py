"""
Traffic Profiler - Learn and maintain traffic baseline profiles
"""

import json
import time
from pathlib import Path
from typing import Dict
from dataclasses import dataclass, asdict

from config import ProfilingConfig

import logging
logger = logging.getLogger(__name__)


@dataclass
class TrafficProfile:
    """Traffic profile for baseline behavior"""
    avg_pps: float = 0.0
    peak_pps: float = 0.0
    avg_bps: float = 0.0
    peak_bps: float = 0.0
    tcp_ratio: float = 0.85
    udp_ratio: float = 0.10
    icmp_ratio: float = 0.05
    unique_ips_per_minute: float = 0.0
    learning_samples: int = 0
    last_updated: float = 0.0
    is_learned: bool = False


class TrafficProfiler:
    """Profile and learn normal traffic patterns"""
    
    def __init__(self, profile_file: str = None):
        self.profile_file = profile_file or ProfilingConfig.PROFILE_FILE
        self.profile = TrafficProfile()
        self.learning_start = time.time()
        self.samples = []
        
        # Try to load existing profile
        self.load_profile()
    
    def update_profile(self, stats: Dict, current_pps: float, current_bps: float):
        """
        Update profile with new traffic data
        
        Args:
            stats: Traffic statistics
            current_pps: Current packets per second
            current_bps: Current bytes per second
        """
        # During learning period, accumulate samples
        if not self.profile.is_learned:
            if time.time() - self.learning_start < ProfilingConfig.LEARNING_PERIOD:
                self.samples.append({
                    'pps': current_pps,
                    'bps': current_bps,
                    'stats': stats,
                    'timestamp': time.time()
                })
                logger.debug(f"Learning: collected {len(self.samples)} samples")
            else:
                # Learning period complete, compute profile
                self._compute_profile()
        else:
            # Profile is learned, do adaptive updates
            self._adaptive_update(current_pps, current_bps, stats)
    
    def _compute_profile(self):
        """Compute profile from collected samples"""
        if not self.samples:
            logger.warning("No samples collected during learning period")
            return
        
        pps_values = [s['pps'] for s in self.samples]
        bps_values = [s['bps'] for s in self.samples]
        
        self.profile.avg_pps = sum(pps_values) / len(pps_values)
        self.profile.peak_pps = max(pps_values)
        self.profile.avg_bps = sum(bps_values) / len(bps_values)
        self.profile.peak_bps = max(bps_values)
        
        # Protocol ratios (from last sample)
        last_stats = self.samples[-1]['stats']
        total_packets = (last_stats.get('tcp_packets', 0) + 
                        last_stats.get('udp_packets', 0) + 
                        last_stats.get('icmp_packets', 0))
        
        if total_packets > 0:
            self.profile.tcp_ratio = last_stats.get('tcp_packets', 0) / total_packets
            self.profile.udp_ratio = last_stats.get('udp_packets', 0) / total_packets
            self.profile.icmp_ratio = last_stats.get('icmp_packets', 0) / total_packets
        
        self.profile.learning_samples = len(self.samples)
        self.profile.last_updated = time.time()
        self.profile.is_learned = True
        
        logger.info(f"Profile learned: avg_pps={self.profile.avg_pps:.0f}, "
                   f"peak_pps={self.profile.peak_pps:.0f}, samples={len(self.samples)}")
        
        # Save profile
        self.save_profile()
    
    def _adaptive_update(self, current_pps: float, current_bps: float, stats: Dict):
        """
        Adaptively update profile with new data (exponential moving average)
        
        Args:
            current_pps: Current packets per second
            current_bps: Current bytes per second
            stats: Traffic statistics
        """
        alpha = 0.05  # Smoothing factor
        
        # Update averages with exponential moving average
        self.profile.avg_pps = (1 - alpha) * self.profile.avg_pps + alpha * current_pps
        self.profile.avg_bps = (1 - alpha) * self.profile.avg_bps + alpha * current_bps
        
        # Update peaks if exceeded
        if current_pps > self.profile.peak_pps:
            self.profile.peak_pps = current_pps
        
        if current_bps > self.profile.peak_bps:
            self.profile.peak_bps = current_bps
        
        self.profile.last_updated = time.time()
    
    def get_profile(self) -> TrafficProfile:
        """Get current profile"""
        return self.profile
    
    def save_profile(self):
        """Save profile to disk"""
        try:
            Path(self.profile_file).parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.profile_file, 'w') as f:
                json.dump(asdict(self.profile), f, indent=2)
            
            logger.info(f"Profile saved to {self.profile_file}")
        except Exception as e:
            logger.error(f"Failed to save profile: {e}")
    
    def load_profile(self):
        """Load profile from disk"""
        try:
            if Path(self.profile_file).exists():
                with open(self.profile_file, 'r') as f:
                    data = json.load(f)
                
                self.profile = TrafficProfile(**data)
                logger.info(f"Profile loaded from {self.profile_file}")
                
                # Don't restart learning if profile exists
                if self.profile.is_learned:
                    logger.info("Using existing learned profile")
        except Exception as e:
            logger.warning(f"Failed to load profile: {e}, starting fresh")
    
    def reset_learning(self):
        """Reset and restart learning period"""
        self.profile = TrafficProfile()
        self.learning_start = time.time()
        self.samples.clear()
        logger.info("Profile learning reset")
