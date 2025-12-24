"""
Alert System - Generate and manage alerts for detected anomalies
"""

import logging
import json
from datetime import datetime
from typing import Dict, List
from pathlib import Path

from config import AlertConfig

logger = logging.getLogger(__name__)


class AlertSystem:
    """Manage alerts and notifications for detected anomalies"""
    
    def __init__(self):
        self.alert_file = AlertConfig.ALERT_FILE
        self.alert_history: List[Dict] = []
        
        # Ensure alert file directory exists
        Path(self.alert_file).parent.mkdir(parents=True, exist_ok=True)
    
    def send_alert(self, alert_type: str, severity: str, message: str, details: Dict = None):
        """
        Send an alert
        
        Args:
            alert_type: Type of alert (e.g., 'volumetric_attack', 'syn_flood')
            severity: Severity level ('low', 'medium', 'high', 'critical')
            message: Alert message
            details: Additional details dictionary
        """
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': alert_type,
            'severity': severity,
            'message': message,
            'details': details or {}
        }
        
        self.alert_history.append(alert)
        
        # Console output
        if AlertConfig.ALERT_TO_CONSOLE:
            severity_colors = {
                'low': '\033[94m',      # Blue
                'medium': '\033[93m',   # Yellow
                'high': '\033[91m',     # Red
                'critical': '\033[95m'  # Magenta
            }
            color = severity_colors.get(severity, '')
            reset = '\033[0m'
            
            print(f"\n{color}[ALERT] {severity.upper()}: {message}{reset}")
            if details:
                print(f"  Details: {json.dumps(details, indent=2)}")
        
        # File output
        if AlertConfig.ALERT_TO_FILE:
            try:
                with open(self.alert_file, 'a') as f:
                    f.write(json.dumps(alert) + '\n')
            except Exception as e:
                logger.error(f"Failed to write alert to file: {e}")
        
        logger.warning(f"Alert: {alert_type} - {message}")
    
    def get_recent_alerts(self, count: int = 10) -> List[Dict]:
        """Get recent alerts"""
        return self.alert_history[-count:]
    
    def clear_history(self):
        """Clear alert history"""
        self.alert_history.clear()
