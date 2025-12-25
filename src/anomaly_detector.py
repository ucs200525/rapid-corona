"""
Anomaly Detector - Statistical and ML-based anomaly detection for DDoS attacks
Phase 2: Enhanced with ML classification using CIC-DDoS-2019 trained models
"""

import logging
import time
import math
from typing import Dict, List, Tuple, Optional
from collections import deque
from dataclasses import dataclass, field
import numpy as np

from config import DetectionThresholds, TimeWindows

logger = logging.getLogger(__name__)

# ML imports (optional - gracefully degrade if not available)
ML_AVAILABLE = False
try:
    from src.ml.ml_classifier import DDoSClassifier, PredictionResult
    from src.ml.feature_extractor import FeatureExtractor
    ML_AVAILABLE = True
except ImportError:
    logger.debug("ML module not available, using statistical detection only")


@dataclass
class TrafficBaseline:
    """Baseline traffic statistics"""
    mean_pps: float = 0.0
    std_pps: float = 0.0
    mean_bps: float = 0.0
    std_bps: float = 0.0
    mean_tcp_ratio: float = 0.0
    mean_udp_ratio: float = 0.0
    mean_icmp_ratio: float = 0.0
    samples: int = 0
    last_updated: float = 0.0


@dataclass
class AnomalyScore:
    """Anomaly detection result with ML enhancement"""
    is_anomaly: bool
    score: float
    reasons: List[str]
    metrics: Dict[str, float]
    # Phase 2: ML-based fields
    ml_prediction: Optional[bool] = None
    ml_confidence: float = 0.0
    attack_type: str = "UNKNOWN"
    detection_source: str = "statistical"  # 'statistical', 'ml', or 'hybrid'


class AnomalyDetector:
    """Detect traffic anomalies using statistical methods"""
    
    def __init__(self):
        self.baseline = TrafficBaseline()
        self.history = deque(maxlen=int(TimeWindows.BASELINE_WINDOW / TimeWindows.STATISTICS_UPDATE))
        self.last_stats = {}
        self.last_check_time = time.time()
        self.alert_cooldown: Dict[str, float] = {}
    
    def update_baseline(self, stats: Dict):
        """
        Update baseline statistics with new data
        
        Args:
            stats: Current traffic statistics
        """
        total_packets = stats.get('total_packets', 0)
        total_bytes = stats.get('total_bytes', 0)
        
        # Calculate current rates
        current_time = time.time()
        time_delta = current_time - self.last_check_time
        
        if time_delta == 0:
            return
        
        # Calculate packets/bytes per second
        if self.last_stats:
            pps = (total_packets - self.last_stats.get('total_packets', 0)) / time_delta
            bps = (total_bytes - self.last_stats.get('total_bytes', 0)) / time_delta
        else:
            pps = total_packets / time_delta
            bps = total_bytes / time_delta
        
        # Calculate protocol ratios
        tcp_packets = stats.get('tcp_packets', 0)
        udp_packets = stats.get('udp_packets', 0)
        icmp_packets = stats.get('icmp_packets', 0)
        
        total_proto = tcp_packets + udp_packets + icmp_packets
        if total_proto > 0:
            tcp_ratio = tcp_packets / total_proto
            udp_ratio = udp_packets / total_proto
            icmp_ratio = icmp_packets / total_proto
        else:
            tcp_ratio = udp_ratio = icmp_ratio = 0
        
        # Add to history
        self.history.append({
            'pps': pps,
            'bps': bps,
            'tcp_ratio': tcp_ratio,
            'udp_ratio': udp_ratio,
            'icmp_ratio': icmp_ratio,
            'timestamp': current_time,
        })
        
        # Update baseline with running statistics
        if len(self.history) >= 10:  # Need minimum samples
            pps_values = [h['pps'] for h in self.history]
            bps_values = [h['bps'] for h in self.history]
            tcp_ratios = [h['tcp_ratio'] for h in self.history]
            udp_ratios = [h['udp_ratio'] for h in self.history]
            icmp_ratios = [h['icmp_ratio'] for h in self.history]
            
            self.baseline.mean_pps = np.mean(pps_values)
            self.baseline.std_pps = np.std(pps_values)
            self.baseline.mean_bps = np.mean(bps_values)
            self.baseline.std_bps = np.std(bps_values)
            self.baseline.mean_tcp_ratio = np.mean(tcp_ratios)
            self.baseline.mean_udp_ratio = np.mean(udp_ratios)
            self.baseline.mean_icmp_ratio = np.mean(icmp_ratios)
            self.baseline.samples = len(self.history)
            self.baseline.last_updated = current_time
        
        self.last_stats = stats
        self.last_check_time = current_time
    
    def detect_anomaly(self, stats: Dict, ip_stats: List[Dict]) -> AnomalyScore:
        """
        Detect anomalies in current traffic
        
        Args:
            stats: Overall traffic statistics
            ip_stats: Per-IP statistics
            
        Returns:
            AnomalyScore object with detection results
        """
        reasons = []
        metrics = {}
        score = 0.0
        
        # Calculate current metrics
        current_time = time.time()
        time_delta = current_time - self.last_check_time
        
        if time_delta == 0 or not self.last_stats:
            return AnomalyScore(False, 0.0, [], {})
        
        total_packets = stats.get('total_packets', 0)
        total_bytes = stats.get('total_bytes', 0)
        
        pps = (total_packets - self.last_stats.get('total_packets', 0)) / time_delta
        bps = (total_bytes - self.last_stats.get('total_bytes', 0)) / time_delta
        
        metrics['pps'] = pps
        metrics['bps'] = bps
        
        # 1. Check absolute thresholds
        if pps > DetectionThresholds.ATTACK_PPS_THRESHOLD:
            score += 50
            reasons.append(f"Very high packet rate: {pps:.0f} pps (threshold: {DetectionThresholds.ATTACK_PPS_THRESHOLD})")
        elif pps > DetectionThresholds.ALERT_PPS_THRESHOLD:
            score += 25
            reasons.append(f"High packet rate: {pps:.0f} pps (threshold: {DetectionThresholds.ALERT_PPS_THRESHOLD})")
        
        # 2. Statistical deviation detection
        if self.baseline.samples >= 10:
            if self.baseline.std_pps > 0:
                pps_sigma = (pps - self.baseline.mean_pps) / self.baseline.std_pps
                metrics['pps_sigma'] = pps_sigma
                
                if abs(pps_sigma) > DetectionThresholds.SIGMA_MULTIPLIER:
                    score += 30
                    reasons.append(f"Packet rate deviation: {pps_sigma:.1f} sigma from baseline")
        
        # 3. Rate of change detection
        if len(self.history) >= 2:
            recent_pps = [h['pps'] for h in list(self.history)[-10:]]
            if len(recent_pps) >= 2 and recent_pps[-2] > 0:
                change_rate = pps / recent_pps[-2]
                metrics['change_rate'] = change_rate
                
                if change_rate > DetectionThresholds.MAX_CHANGE_RATE:
                    score += 20
                    reasons.append(f"Rapid traffic increase: {change_rate:.1f}x")
        
        # 4. Protocol distribution anomaly
        tcp_packets = stats.get('tcp_packets', 0)
        udp_packets = stats.get('udp_packets', 0)
        icmp_packets = stats.get('icmp_packets', 0)
        
        total_proto = tcp_packets + udp_packets + icmp_packets
        if total_proto > 0:
            tcp_ratio = tcp_packets / total_proto
            udp_ratio = udp_packets / total_proto
            icmp_ratio = icmp_packets / total_proto
            
            metrics['tcp_ratio'] = tcp_ratio
            metrics['udp_ratio'] = udp_ratio
            metrics['icmp_ratio'] = icmp_ratio
            
            # Check for unusual protocol distributions
            if abs(tcp_ratio - DetectionThresholds.NORMAL_TCP_RATIO) > DetectionThresholds.PROTOCOL_DEVIATION_THRESHOLD:
                score += 15
                reasons.append(f"Abnormal TCP ratio: {tcp_ratio:.2f} (expected: {DetectionThresholds.NORMAL_TCP_RATIO:.2f})")
            
            if udp_ratio > DetectionThresholds.NORMAL_UDP_RATIO + DetectionThresholds.PROTOCOL_DEVIATION_THRESHOLD:
                score += 15
                reasons.append(f"High UDP ratio: {udp_ratio:.2f} (normal: {DetectionThresholds.NORMAL_UDP_RATIO:.2f}) - possible UDP flood")
            
            if icmp_ratio > DetectionThresholds.NORMAL_ICMP_RATIO + DetectionThresholds.PROTOCOL_DEVIATION_THRESHOLD:
                score += 15
                reasons.append(f"High ICMP ratio: {icmp_ratio:.2f} (normal: {DetectionThresholds.NORMAL_ICMP_RATIO:.2f}) - possible ICMP flood")
        
        # 5. Source IP entropy (diversity)
        if ip_stats:
            entropy = self._calculate_ip_entropy(ip_stats)
            metrics['ip_entropy'] = entropy
            
            if entropy < DetectionThresholds.MIN_ENTROPY:
                score += 20
                reasons.append(f"Low source IP entropy: {entropy:.2f} (threshold: {DetectionThresholds.MIN_ENTROPY}) - concentrated sources")
            
            # Check for individual heavy hitters
            top_ips = sorted(ip_stats, key=lambda x: x['packets'], reverse=True)[:10]
            if top_ips:
                total_ip_packets = sum(ip['packets'] for ip in ip_stats)
                top_ratio = sum(ip['packets'] for ip in top_ips) / total_ip_packets if total_ip_packets > 0 else 0
                metrics['top10_ratio'] = top_ratio
                
                if top_ratio > 0.8:  # Top 10 IPs account for >80% traffic
                    score += 10
                    reasons.append(f"Traffic concentrated in few IPs: top 10 = {top_ratio*100:.1f}%")
        
        # 6. SYN flood detection
        syn_heavy_ips = [ip for ip in ip_stats if ip.get('syn_count', 0) > 500]
        if syn_heavy_ips:
            score += 25
            reasons.append(f"Detected {len(syn_heavy_ips)} IPs with excessive SYN packets - possible SYN flood")
        
        # Determine if this is an anomaly
        is_anomaly = score >= 50  # 50+ points indicates likely attack
        
        return AnomalyScore(
            is_anomaly=is_anomaly,
            score=score,
            reasons=reasons,
            metrics=metrics
        )
    
    def _calculate_ip_entropy(self, ip_stats: List[Dict]) -> float:
        """
        Calculate Shannon entropy of source IP distribution
        Lower entropy = more concentrated sources (botnet characteristic)
        Higher entropy = more diverse sources (normal or flash crowd)
        
        Args:
            ip_stats: Per-IP statistics
            
        Returns:
            Entropy value
        """
        if not ip_stats:
            return 0.0
        
        total_packets = sum(ip['packets'] for ip in ip_stats)
        if total_packets == 0:
            return 0.0
        
        entropy = 0.0
        for ip in ip_stats:
            p = ip['packets'] / total_packets
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    
    def should_alert(self, alert_type: str) -> bool:
        """
        Check if alert should be sent (respecting cooldown)
        
        Args:
            alert_type: Type of alert
            
        Returns:
            True if alert should be sent
        """
        current_time = time.time()
        last_alert = self.alert_cooldown.get(alert_type, 0)
        
        if current_time - last_alert >= TimeWindows.ALERT_COOLDOWN:
            self.alert_cooldown[alert_type] = current_time
            return True
        
        return False
    
    def get_baseline_info(self) -> Dict:
        """Get current baseline information"""
        return {
            'mean_pps': self.baseline.mean_pps,
            'std_pps': self.baseline.std_pps,
            'mean_bps': self.baseline.mean_bps,
            'tcp_ratio': self.baseline.mean_tcp_ratio,
            'udp_ratio': self.baseline.mean_udp_ratio,
            'icmp_ratio': self.baseline.mean_icmp_ratio,
            'samples': self.baseline.samples,
            'last_updated': self.baseline.last_updated,
        }


class MLEnhancedAnomalyDetector(AnomalyDetector):
    """
    ML-Enhanced Anomaly Detector - Phase 2
    Combines statistical detection with ML classification for improved accuracy
    """
    
    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize ML-enhanced detector
        
        Args:
            model_path: Path to trained ML model (optional)
        """
        super().__init__()
        
        self.ml_enabled = False
        self.classifier = None
        self.feature_extractor = None
        self.ml_predictions_count = 0
        self.ml_attacks_detected = 0
        
        if ML_AVAILABLE:
            self.feature_extractor = FeatureExtractor()
            
            if model_path:
                self.load_model(model_path)
    
    def load_model(self, model_path: str) -> bool:
        """
        Load trained ML model
        
        Args:
            model_path: Path to model file
            
        Returns:
            True if successful
        """
        if not ML_AVAILABLE:
            logger.warning("ML module not available")
            return False
        
        try:
            self.classifier = DDoSClassifier()
            if self.classifier.load(model_path):
                self.ml_enabled = True
                logger.info(f"ML model loaded: {model_path}")
                logger.info(f"Model accuracy: {self.classifier.metrics.accuracy:.4f}" 
                           if self.classifier.metrics else "")
                return True
            else:
                self.classifier = None
                return False
        except Exception as e:
            logger.error(f"Failed to load ML model: {e}")
            return False
    
    def update_features(self, stats: Dict, ip_stats: Optional[List[Dict]] = None) -> None:
        """Update feature extractor with new traffic data"""
        if self.feature_extractor:
            self.feature_extractor.update(stats, ip_stats)
    
    def detect_anomaly(self, stats: Dict, ip_stats: List[Dict]) -> AnomalyScore:
        """
        Hybrid anomaly detection using both statistical and ML methods
        
        Args:
            stats: Overall traffic statistics
            ip_stats: Per-IP statistics
            
        Returns:
            AnomalyScore with combined detection results
        """
        # Get statistical detection result
        stat_result = super().detect_anomaly(stats, ip_stats)
        
        # Update feature extractor
        self.update_features(stats, ip_stats)
        
        # If ML not available, return statistical result
        if not self.ml_enabled or not self.classifier:
            return stat_result
        
        # Get ML prediction
        try:
            features = self.feature_extractor.extract_features_for_prediction(
                scaler=self.classifier.scaler
            )
            ml_result = self.classifier.predict(features)
            self.ml_predictions_count += 1
            
            if ml_result.is_attack:
                self.ml_attacks_detected += 1
            
            # Combine statistical and ML detection
            return self._combine_results(stat_result, ml_result)
            
        except Exception as e:
            logger.debug(f"ML prediction failed: {e}")
            return stat_result
    
    def _combine_results(self, stat_result: AnomalyScore, 
                         ml_result: 'PredictionResult') -> AnomalyScore:
        """
        Combine statistical and ML detection results
        
        Strategy:
        - If both agree: high confidence
        - If ML detects attack but statistical doesn't: trust ML with moderate confidence
        - If statistical detects but ML doesn't: verify with lower threshold
        - Weight ML more heavily when confidence is high
        """
        combined_score = stat_result.score
        reasons = stat_result.reasons.copy()
        metrics = stat_result.metrics.copy()
        
        # Add ML metrics
        metrics['ml_confidence'] = ml_result.confidence
        metrics['ml_attack_prob'] = ml_result.attack_probability
        metrics['ml_inference_ms'] = ml_result.inference_time_ms
        
        # Determine detection source
        if ml_result.is_attack:
            combined_score += 30 * (ml_result.confidence / 100)
            reasons.append(f"ML detected {ml_result.attack_type} "
                          f"(confidence: {ml_result.confidence:.1f}%)")
        
        # Determine final verdict
        # High confidence ML detection takes precedence
        if ml_result.is_attack and ml_result.confidence >= 85:
            is_anomaly = True
            detection_source = 'ml'
        # Both agree
        elif stat_result.is_anomaly and ml_result.is_attack:
            is_anomaly = True
            detection_source = 'hybrid'
        # Statistical only with high score
        elif stat_result.is_anomaly and stat_result.score >= 70:
            is_anomaly = True
            detection_source = 'statistical'
        # ML only with moderate confidence
        elif ml_result.is_attack and ml_result.confidence >= 70:
            is_anomaly = True
            detection_source = 'ml'
        # Combined score check
        elif combined_score >= 60:
            is_anomaly = True
            detection_source = 'hybrid'
        else:
            is_anomaly = stat_result.is_anomaly
            detection_source = 'statistical'
        
        return AnomalyScore(
            is_anomaly=is_anomaly,
            score=min(combined_score, 100),
            reasons=reasons,
            metrics=metrics,
            ml_prediction=ml_result.is_attack,
            ml_confidence=ml_result.confidence,
            attack_type=ml_result.attack_type if ml_result.is_attack else 'BENIGN',
            detection_source=detection_source,
        )
    
    def get_ml_stats(self) -> Dict:
        """Get ML-specific statistics"""
        stats = {
            'ml_enabled': self.ml_enabled,
            'ml_available': ML_AVAILABLE,
            'total_ml_predictions': self.ml_predictions_count,
            'ml_attacks_detected': self.ml_attacks_detected,
        }
        
        if self.classifier:
            stats.update({
                'model_type': self.classifier.model_type,
                'training_date': self.classifier.training_date,
                'model_accuracy': self.classifier.metrics.accuracy if self.classifier.metrics else None,
                'avg_inference_ms': (
                    self.classifier.total_inference_time / max(self.classifier.total_predictions, 1)
                ),
            })
        
        if self.feature_extractor:
            stats['feature_summary'] = self.feature_extractor.get_feature_summary()
        
        return stats
    
    def get_feature_importance(self, top_n: int = 10) -> Dict[str, float]:
        """Get top feature importances from ML model"""
        if self.classifier:
            return self.classifier.get_feature_importance(top_n)
        return {}
