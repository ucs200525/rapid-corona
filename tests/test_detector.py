"""
Test Anomaly Detector - Unit tests for anomaly detection module
"""

import pytest
import time
from src.anomaly_detector import AnomalyDetector, TrafficBaseline, AnomalyScore


class TestAnomalyDetector:
    """Test cases for anomaly detector"""
    
    def test_initialization(self):
        """Test detector initialization"""
        detector = AnomalyDetector()
        assert detector.baseline.mean_pps == 0.0
        assert len(detector.history) == 0
    
    def test_baseline_update(self):
        """Test baseline updates"""
        detector = AnomalyDetector()
        
        # Simulate normal traffic
        for i in range(20):
            stats = {
                'total_packets': 10000 * (i + 1),
                'total_bytes': 1000000 * (i + 1),
                'tcp_packets': 8500,
                'udp_packets': 1000,
                'icmp_packets': 500,
            }
            detector.update_baseline(stats)
            time.sleep(0.01)  # Small delay
        
        # Baseline should be learned
        assert detector.baseline.samples >= 10
        assert detector.baseline.mean_pps > 0
    
    def test_high_packet_rate_detection(self):
        """Test detection of high packet rate"""
        detector = AnomalyDetector()
        
        # Establish baseline with low rate
        base_packets = 0
        for i in range(15):
            base_packets += 1000
            stats = {
                'total_packets': base_packets,
                'total_bytes': base_packets * 100,
                'tcp_packets': 850,
                'udp_packets': 100,
                'icmp_packets': 50,
            }
            detector.update_baseline(stats)
            time.sleep(0.01)
        
        # Inject high packet rate (attack)
        attack_stats = {
            'total_packets': base_packets + 1000000,  # Massive spike
            'total_bytes': (base_packets + 1000000) * 100,
            'tcp_packets': 850000,
            'udp_packets': 100000,
            'icmp_packets': 50000,
        }
        
        result = detector.detect_anomaly(attack_stats, [])
        
        assert result.is_anomaly == True
        assert result.score > 50
        assert any('high packet rate' in reason.lower() for reason in result.reasons)
    
    def test_protocol_anomaly_detection(self):
        """Test protocol distribution anomaly detection"""
        detector = AnomalyDetector()
        
        # Establish TCP-heavy baseline
        base_packets = 0
        for i in range(15):
            base_packets += 1000
            stats = {
                'total_packets': base_packets,
                'total_bytes': base_packets * 100,
                'tcp_packets': int(base_packets * 0.85),
                'udp_packets': int(base_packets * 0.10),
                'icmp_packets': int(base_packets * 0.05),
            }
            detector.update_baseline(stats)
            time.sleep(0.01)
        
        # UDP flood
        udp_flood_stats = {
            'total_packets': base_packets + 10000,
            'total_bytes': (base_packets + 10000) * 100,
            'tcp_packets': int(base_packets * 0.85) + 1000,
            'udp_packets': int(base_packets * 0.10) + 9000,  # 90% UDP now
            'icmp_packets': int(base_packets * 0.05),
        }
        
        result = detector.detect_anomaly(udp_flood_stats, [])
        
        assert any('udp' in reason.lower() for reason in result.reasons)
    
    def test_entropy_detection(self):
        """Test IP entropy detection"""
        detector = AnomalyDetector()
        
        # Low entropy (concentrated sources - botnet)
        low_entropy_ips = [
            {'ip': '192.168.1.1', 'packets': 10000},
            {'ip': '192.168.1.2', 'packets': 9000},
            {'ip': '192.168.1.3', 'packets': 8000},
        ]
        
        entropy = detector._calculate_ip_entropy(low_entropy_ips)
        assert entropy < 5.0  # Low entropy
        
        # High entropy (diverse sources - normal or flash crowd)
        high_entropy_ips = [
            {'ip': f'192.168.{i}.{j}', 'packets': 100}
            for i in range(10) for j in range(10)
        ]
        
        entropy = detector._calculate_ip_entropy(high_entropy_ips)
        assert entropy > 5.0  # Higher entropy
    
    def test_alert_cooldown(self):
        """Test alert cooldown mechanism"""
        detector = AnomalyDetector()
        
        # First alert should go through
        assert detector.should_alert('test_alert') == True
        
        # Immediate second alert should be blocked
        assert detector.should_alert('test_alert') == False
        
        # Different alert type should go through
        assert detector.should_alert('other_alert') == True


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
