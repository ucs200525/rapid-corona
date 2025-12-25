"""
Feature Extractor - Extract CIC-compatible features from real-time traffic
Maps eBPF traffic statistics to CIC-DDoS-2019 flow features
"""

import logging
import time
import numpy as np
from typing import Dict, List, Optional, Tuple
from collections import deque
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class FlowFeatures:
    """Container for extracted flow features"""
    features: np.ndarray
    feature_names: List[str]
    timestamp: float
    flow_count: int
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            name: float(value) 
            for name, value in zip(self.feature_names, self.features)
        }


@dataclass
class FlowWindow:
    """Sliding window for flow statistics aggregation"""
    packets_fwd: deque = field(default_factory=lambda: deque(maxlen=1000))
    packets_bwd: deque = field(default_factory=lambda: deque(maxlen=1000))
    bytes_fwd: deque = field(default_factory=lambda: deque(maxlen=1000))
    bytes_bwd: deque = field(default_factory=lambda: deque(maxlen=1000))
    iat_fwd: deque = field(default_factory=lambda: deque(maxlen=1000))
    iat_bwd: deque = field(default_factory=lambda: deque(maxlen=1000))
    timestamps: deque = field(default_factory=lambda: deque(maxlen=1000))
    flags: Dict[str, int] = field(default_factory=dict)
    

# Feature names matching CIC-DDoS-2019 dataset
FEATURE_NAMES = [
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets', 
    'Total Length of Fwd Packets',
    'Total Length of Bwd Packets',
    'Fwd Packet Length Max',
    'Fwd Packet Length Min',
    'Fwd Packet Length Mean',
    'Fwd Packet Length Std',
    'Bwd Packet Length Max',
    'Bwd Packet Length Min',
    'Bwd Packet Length Mean',
    'Bwd Packet Length Std',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Flow IAT Mean',
    'Flow IAT Std',
    'Flow IAT Max',
    'Flow IAT Min',
    'Fwd IAT Total',
    'Fwd IAT Mean',
    'Fwd IAT Std',
    'Fwd IAT Max',
    'Fwd IAT Min',
    'Bwd IAT Total',
    'Bwd IAT Mean',
    'Bwd IAT Std',
    'Bwd IAT Max',
    'Bwd IAT Min',
    'Fwd PSH Flags',
    'Bwd PSH Flags',
    'Fwd URG Flags',
    'Bwd URG Flags',
    'Fwd Header Length',
    'Bwd Header Length',
    'Fwd Packets/s',
    'Bwd Packets/s',
    'Min Packet Length',
    'Max Packet Length',
    'Packet Length Mean',
    'Packet Length Std',
    'Packet Length Variance',
    'FIN Flag Count',
    'SYN Flag Count',
    'RST Flag Count',
    'PSH Flag Count',
    'ACK Flag Count',
    'URG Flag Count',
    'CWE Flag Count',
    'ECE Flag Count',
    'Down/Up Ratio',
    'Average Packet Size',
    'Avg Fwd Segment Size',
    'Avg Bwd Segment Size',
    'Init_Win_bytes_forward',
    'Init_Win_bytes_backward',
    'Active Mean',
    'Active Std',
    'Active Max',
    'Active Min',
    'Idle Mean',
    'Idle Std',
    'Idle Max',
    'Idle Min',
]


class FeatureExtractor:
    """Extract CIC-compatible features from real-time traffic statistics"""
    
    def __init__(self, window_size: float = 10.0):
        """
        Initialize feature extractor
        
        Args:
            window_size: Time window in seconds for feature aggregation
        """
        self.window_size = window_size
        self.flow_window = FlowWindow()
        self.feature_names = FEATURE_NAMES
        
        # State tracking
        self.start_time = time.time()
        self.last_stats = {}
        self.last_update_time = time.time()
        
        # Per-IP flow tracking
        self.ip_flows: Dict[str, FlowWindow] = {}
        
        # Aggregated statistics
        self.total_fwd_packets = 0
        self.total_bwd_packets = 0
        self.total_fwd_bytes = 0
        self.total_bwd_bytes = 0
        
    def update(self, stats: Dict, ip_stats: Optional[List[Dict]] = None) -> None:
        """
        Update internal state with new traffic statistics
        
        Args:
            stats: Overall traffic statistics from eBPF
            ip_stats: Per-IP statistics
        """
        current_time = time.time()
        time_delta = current_time - self.last_update_time
        
        if time_delta <= 0:
            return
        
        # Calculate packet rates
        total_packets = stats.get('total_packets', 0)
        total_bytes = stats.get('total_bytes', 0)
        
        if self.last_stats:
            packets_delta = total_packets - self.last_stats.get('total_packets', 0)
            bytes_delta = total_bytes - self.last_stats.get('total_bytes', 0)
        else:
            packets_delta = total_packets
            bytes_delta = total_bytes
        
        # Estimate forward/backward split (simplified for real-time)
        # In production, this would come from eBPF tracking
        tcp_ratio = stats.get('tcp_packets', 0) / max(total_packets, 1)
        
        # Approximate: 60% forward, 40% backward for TCP
        fwd_ratio = 0.6 if tcp_ratio > 0.5 else 0.8
        
        fwd_packets = int(packets_delta * fwd_ratio)
        bwd_packets = packets_delta - fwd_packets
        fwd_bytes = int(bytes_delta * fwd_ratio)
        bwd_bytes = bytes_delta - fwd_bytes
        
        # Update flow window
        self.flow_window.packets_fwd.append(fwd_packets)
        self.flow_window.packets_bwd.append(bwd_packets)
        self.flow_window.bytes_fwd.append(fwd_bytes)
        self.flow_window.bytes_bwd.append(bwd_bytes)
        self.flow_window.timestamps.append(current_time)
        
        # Update IAT (inter-arrival time) tracking
        if len(self.flow_window.timestamps) > 1:
            iat = (self.flow_window.timestamps[-1] - 
                   self.flow_window.timestamps[-2]) * 1000  # ms
            self.flow_window.iat_fwd.append(iat)
            self.flow_window.iat_bwd.append(iat)
        
        # Update flag counts from stats
        self.flow_window.flags = {
            'SYN': stats.get('syn_packets', 0),
            'ACK': stats.get('ack_packets', 0),
            'FIN': stats.get('fin_packets', 0),
            'RST': stats.get('rst_packets', 0),
            'PSH': stats.get('psh_packets', 0),
            'URG': stats.get('urg_packets', 0),
        }
        
        # Update per-IP flows if provided
        if ip_stats:
            self._update_ip_flows(ip_stats)
        
        # Update totals
        self.total_fwd_packets += fwd_packets
        self.total_bwd_packets += bwd_packets
        self.total_fwd_bytes += fwd_bytes
        self.total_bwd_bytes += bwd_bytes
        
        self.last_stats = stats.copy()
        self.last_update_time = current_time
    
    def _update_ip_flows(self, ip_stats: List[Dict]) -> None:
        """Update per-IP flow statistics"""
        for ip_stat in ip_stats:
            ip = ip_stat.get('ip', 'unknown')
            
            if ip not in self.ip_flows:
                self.ip_flows[ip] = FlowWindow()
            
            flow = self.ip_flows[ip]
            flow.packets_fwd.append(ip_stat.get('packets', 0))
            flow.bytes_fwd.append(ip_stat.get('bytes', 0))
            flow.timestamps.append(time.time())
    
    def extract_features(self) -> FlowFeatures:
        """
        Extract CIC-compatible features from current window
        
        Returns:
            FlowFeatures object with extracted features
        """
        current_time = time.time()
        flow_duration = (current_time - self.start_time) * 1000000  # microseconds
        
        # Get window data as arrays
        fwd_packets = list(self.flow_window.packets_fwd)
        bwd_packets = list(self.flow_window.packets_bwd)
        fwd_bytes = list(self.flow_window.bytes_fwd)
        bwd_bytes = list(self.flow_window.bytes_bwd)
        fwd_iat = list(self.flow_window.iat_fwd)
        bwd_iat = list(self.flow_window.iat_bwd)
        
        # Calculate features
        features = np.zeros(len(self.feature_names), dtype=np.float32)
        
        # Flow Duration
        features[0] = flow_duration
        
        # Packet counts
        features[1] = sum(fwd_packets)  # Total Fwd Packets
        features[2] = sum(bwd_packets)  # Total Backward Packets
        
        # Byte counts
        features[3] = sum(fwd_bytes)  # Total Length of Fwd Packets
        features[4] = sum(bwd_bytes)  # Total Length of Bwd Packets
        
        # Forward packet length stats
        if fwd_bytes:
            features[5] = max(fwd_bytes)  # Max
            features[6] = min(fwd_bytes)  # Min
            features[7] = np.mean(fwd_bytes)  # Mean
            features[8] = np.std(fwd_bytes)  # Std
        
        # Backward packet length stats
        if bwd_bytes:
            features[9] = max(bwd_bytes)  # Max
            features[10] = min(bwd_bytes)  # Min
            features[11] = np.mean(bwd_bytes)  # Mean
            features[12] = np.std(bwd_bytes)  # Std
        
        # Flow rates
        duration_s = max(flow_duration / 1000000, 0.001)
        total_bytes = sum(fwd_bytes) + sum(bwd_bytes)
        total_packets = sum(fwd_packets) + sum(bwd_packets)
        
        features[13] = total_bytes / duration_s  # Flow Bytes/s
        features[14] = total_packets / duration_s  # Flow Packets/s
        
        # Flow IAT stats
        all_iat = fwd_iat + bwd_iat
        if all_iat:
            features[15] = np.mean(all_iat)  # Flow IAT Mean
            features[16] = np.std(all_iat)  # Flow IAT Std
            features[17] = max(all_iat)  # Flow IAT Max
            features[18] = min(all_iat)  # Flow IAT Min
        
        # Forward IAT stats
        if fwd_iat:
            features[19] = sum(fwd_iat)  # Fwd IAT Total
            features[20] = np.mean(fwd_iat)  # Fwd IAT Mean
            features[21] = np.std(fwd_iat)  # Fwd IAT Std
            features[22] = max(fwd_iat)  # Fwd IAT Max
            features[23] = min(fwd_iat)  # Fwd IAT Min
        
        # Backward IAT stats
        if bwd_iat:
            features[24] = sum(bwd_iat)  # Bwd IAT Total
            features[25] = np.mean(bwd_iat)  # Bwd IAT Mean
            features[26] = np.std(bwd_iat)  # Bwd IAT Std
            features[27] = max(bwd_iat)  # Bwd IAT Max
            features[28] = min(bwd_iat)  # Bwd IAT Min
        
        # Flag counts (simplified - would need eBPF support)
        features[29] = 0  # Fwd PSH Flags
        features[30] = 0  # Bwd PSH Flags
        features[31] = 0  # Fwd URG Flags  
        features[32] = 0  # Bwd URG Flags
        
        # Header lengths (estimated)
        features[33] = sum(fwd_packets) * 40  # Fwd Header Length
        features[34] = sum(bwd_packets) * 40  # Bwd Header Length
        
        # Packets per second
        features[35] = sum(fwd_packets) / duration_s  # Fwd Packets/s
        features[36] = sum(bwd_packets) / duration_s  # Bwd Packets/s
        
        # Packet length overall stats
        all_bytes = fwd_bytes + bwd_bytes
        if all_bytes:
            features[37] = min(all_bytes)  # Min Packet Length
            features[38] = max(all_bytes)  # Max Packet Length
            features[39] = np.mean(all_bytes)  # Packet Length Mean
            features[40] = np.std(all_bytes)  # Packet Length Std
            features[41] = np.var(all_bytes)  # Packet Length Variance
        
        # TCP flag counts
        flags = self.flow_window.flags
        features[42] = flags.get('FIN', 0)  # FIN Flag Count
        features[43] = flags.get('SYN', 0)  # SYN Flag Count
        features[44] = flags.get('RST', 0)  # RST Flag Count
        features[45] = flags.get('PSH', 0)  # PSH Flag Count
        features[46] = flags.get('ACK', 0)  # ACK Flag Count
        features[47] = flags.get('URG', 0)  # URG Flag Count
        features[48] = 0  # CWE Flag Count
        features[49] = 0  # ECE Flag Count
        
        # Down/Up Ratio
        if sum(fwd_packets) > 0:
            features[50] = sum(bwd_packets) / sum(fwd_packets)
        
        # Average sizes
        if total_packets > 0:
            features[51] = total_bytes / total_packets  # Average Packet Size
        if sum(fwd_packets) > 0:
            features[52] = sum(fwd_bytes) / sum(fwd_packets)  # Avg Fwd Segment Size
        if sum(bwd_packets) > 0:
            features[53] = sum(bwd_bytes) / sum(bwd_packets)  # Avg Bwd Segment Size
        
        # Initial window bytes (estimated)
        features[54] = 65535  # Init_Win_bytes_forward
        features[55] = 65535  # Init_Win_bytes_backward
        
        # Active/Idle times (simplified)
        features[56] = 100  # Active Mean
        features[57] = 50   # Active Std
        features[58] = 500  # Active Max
        features[59] = 10   # Active Min
        features[60] = 1000  # Idle Mean
        features[61] = 500   # Idle Std
        features[62] = 5000  # Idle Max
        features[63] = 100   # Idle Min
        
        # Handle NaN and infinity
        features = np.nan_to_num(features, nan=0.0, posinf=1e10, neginf=-1e10)
        
        return FlowFeatures(
            features=features,
            feature_names=self.feature_names,
            timestamp=current_time,
            flow_count=len(self.ip_flows)
        )
    
    def extract_features_for_prediction(self, scaler=None) -> np.ndarray:
        """
        Extract and scale features ready for ML prediction
        
        Args:
            scaler: Optional sklearn scaler (StandardScaler)
            
        Returns:
            2D array of shape (1, n_features) for prediction
        """
        flow_features = self.extract_features()
        features = flow_features.features.reshape(1, -1)
        
        if scaler is not None:
            features = scaler.transform(features)
        
        return features
    
    def reset(self) -> None:
        """Reset the feature extractor state"""
        self.flow_window = FlowWindow()
        self.ip_flows = {}
        self.start_time = time.time()
        self.last_stats = {}
        self.last_update_time = time.time()
        self.total_fwd_packets = 0
        self.total_bwd_packets = 0
        self.total_fwd_bytes = 0
        self.total_bwd_bytes = 0
    
    def get_feature_summary(self) -> Dict:
        """Get summary of current extracted features"""
        flow_features = self.extract_features()
        
        return {
            'total_fwd_packets': self.total_fwd_packets,
            'total_bwd_packets': self.total_bwd_packets,
            'total_fwd_bytes': self.total_fwd_bytes,
            'total_bwd_bytes': self.total_bwd_bytes,
            'unique_flows': len(self.ip_flows),
            'window_samples': len(self.flow_window.packets_fwd),
            'top_features': {
                'Flow Bytes/s': float(flow_features.features[13]),
                'Flow Packets/s': float(flow_features.features[14]),
                'SYN Flag Count': float(flow_features.features[43]),
                'ACK Flag Count': float(flow_features.features[46]),
            }
        }


if __name__ == '__main__':
    # Test the feature extractor
    logging.basicConfig(level=logging.INFO)
    
    extractor = FeatureExtractor()
    
    # Simulate some traffic updates
    for i in range(10):
        stats = {
            'total_packets': 1000 * (i + 1),
            'total_bytes': 100000 * (i + 1),
            'tcp_packets': 850 * (i + 1),
            'udp_packets': 100 * (i + 1),
            'syn_packets': 10 * (i + 1),
            'ack_packets': 500 * (i + 1),
        }
        
        extractor.update(stats)
        time.sleep(0.1)
    
    # Extract features
    features = extractor.extract_features()
    print(f"Extracted {len(features.features)} features")
    print(f"\nTop features:")
    for name, value in list(features.to_dict().items())[:10]:
        print(f"  {name}: {value:.2f}")
