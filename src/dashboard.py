"""
Web Dashboard - Real-time monitoring dashboard
"""

from flask import Flask, render_template, jsonify, send_from_directory
from flask_cors import CORS
import json
import time
from pathlib import Path

from config import MonitoringConfig

app = Flask(__name__)
CORS(app)

# Global reference to DDoS system (set by dashboard runner)
ddos_system = None


@app.route('/')
def index():
    """Dashboard home page"""
    return """
<!DOCTYPE html>
<html>
<head>
    <title>DDoS Mitigation Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #fff;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        header {
            text-align: center;
            margin-bottom: 30px;
        }
        
        h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        
        .status-badge {
            display: inline-block;
            padding: 8px 20px;
            background: rgba(255,255,255,0.2);
            border-radius: 20px;
            font-size: 0.9em;
            backdrop-filter: blur(10px);
        }
        
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .card {
            background: rgba(255,255,255,0.15);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37);
            border: 1px solid rgba(255,255,255,0.18);
        }
        
        .card h2 {
            font-size: 1.3em;
            margin-bottom: 15px;
            color: #ffd700;
        }
        
        .metric {
            display: flex;
            justify-content: space-between;
            padding: 10px 0;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        
        .metric:last-child {
            border-bottom: none;
        }
        
        .metric-value {
            font-weight: bold;
            font-size: 1.1em;
        }
        
        .alerts {
            grid-column: 1 / -1;
        }
        
        .alert-item {
            background: rgba(255,255,255,0.1);
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 10px;
            border-left: 4px solid;
        }
        
        .alert-high {
            border-left-color: #ff4757;
        }
        
        .alert-medium {
            border-left-color: #ffa502;
        }
        
        .alert-low {
            border-left-color: #1e90ff;
        }
        
        .alert-time {
            font-size: 0.85em;
            opacity: 0.7;
            margin-bottom: 5px;
        }
        
        .loading {
            text-align: center;
            padding: 40px;
            font-size: 1.2em;
        }
        
        .refresh-info {
            text-align: center;
            margin-top: 20px;
            opacity: 0.7;
            font-size: 0.9em;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        .status-active {
            animation: pulse 2s infinite;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ DDoS Mitigation System</h1>
            <div class="status-badge status-active">
                <span id="status">MONITORING</span>
            </div>
        </header>
        
        <div id="dashboard" class="dashboard">
            <div class="loading">Loading dashboard...</div>
        </div>
        
        <div class="refresh-info">
            Auto-refresh: <span id="refresh-timer">5</span>s
        </div>
    </div>
    
    <script>
        let refreshInterval = 5000; // 5 seconds
        let countdown = refreshInterval / 1000;
        
        async function fetchData() {
            try {
                const response = await fetch('/api/status');
                const data = await response.json();
                updateDashboard(data);
            } catch (error) {
                console.error('Error fetching data:', error);
            }
        }
        
        function formatNumber(num) {
            if (num >= 1000000) return (num / 1000000).toFixed(2) + 'M';
            if (num >= 1000) return (num / 1000).toFixed(2) + 'K';
            return num.toFixed(0);
        }
        
        function formatBytes(bytes) {
            if (bytes >= 1073741824) return (bytes / 1073741824).toFixed(2) + ' GB';
            if (bytes >= 1048576) return (bytes / 1048576).toFixed(2) + ' MB';
            if (bytes >= 1024) return (bytes / 1024).toFixed(2) + ' KB';
            return bytes + ' B';
        }
        
        function updateDashboard(data) {
            const stats = data.statistics || {};
            const baseline = data.baseline || {};
            const alerts = data.recent_alerts || [];
            const ipStats = data.ip_stats || [];
            const currentPps = data.current_pps || 0;
            
            const html = `
                <div class="card">
                    <h2>⚡ Real-time Status</h2>
                    <div class="metric">
                        <span>Interface</span>
                        <span class="metric-value">${data.interface || 'N/A'}</span>
                    </div>
                    <div class="metric">
                        <span>Current PPS</span>
                        <span class="metric-value" style="color: ${currentPps > 100 ? '#ff4757' : '#2ed573'}">${formatNumber(currentPps)}</span>
                    </div>
                    <div class="metric">
                        <span>Baseline PPS</span>
                        <span class="metric-value">${formatNumber(baseline.mean_pps || 0)}</span>
                    </div>
                    <div class="metric">
                        <span>Drop Rate</span>
                        <span class="metric-value" style="color: ${stats.dropped_packets > 0 ? '#ff4757' : '#2ed573'}">${formatNumber(stats.dropped_packets || 0)}</span>
                    </div>
                </div>
                
                <div class="card">
                    <h2>📊 Traffic Statistics</h2>
                    <div class="metric">
                        <span>Total Packets</span>
                        <span class="metric-value">${formatNumber(stats.total_packets || 0)}</span>
                    </div>
                    <div class="metric">
                        <span>Total Bytes</span>
                        <span class="metric-value">${formatBytes(stats.total_bytes || 0)}</span>
                    </div>
                    <div class="metric">
                        <span>Dropped Packets</span>
                        <span class="metric-value" style="color: ${stats.dropped_packets > 0 ? '#ff4757' : 'inherit'}">${formatNumber(stats.dropped_packets || 0)}</span>
                    </div>
                    <div class="metric">
                        <span>Passed Packets</span>
                        <span class="metric-value">${formatNumber(stats.passed_packets || 0)}</span>
                    </div>
                </div>
                
                <div class="card">
                    <h2>📈 Protocol Distribution</h2>
                    <div class="metric">
                        <span>TCP</span>
                        <span class="metric-value">${formatNumber(stats.tcp_packets || 0)}</span>
                    </div>
                    <div class="metric">
                        <span>UDP</span>
                        <span class="metric-value">${formatNumber(stats.udp_packets || 0)}</span>
                    </div>
                    <div class="metric">
                        <span>ICMP</span>
                        <span class="metric-value">${formatNumber(stats.icmp_packets || 0)}</span>
                    </div>
                    <div class="metric">
                        <span>Other</span>
                        <span class="metric-value">${formatNumber(stats.other_packets || 0)}</span>
                    </div>
                </div>
                
                <div class="card">
                    <h2>🎯 Baseline Profile</h2>
                    <div class="metric">
                        <span>Mean PPS</span>
                        <span class="metric-value">${formatNumber(baseline.mean_pps || 0)}</span>
                    </div>
                    <div class="metric">
                        <span>Std Dev PPS</span>
                        <span class="metric-value">${formatNumber(baseline.std_pps || 0)}</span>
                    </div>
                    <div class="metric">
                        <span>Samples</span>
                        <span class="metric-value">${baseline.samples || 0}</span>
                    </div>
                    <div class="metric">
                        <span>Status</span>
                        <span class="metric-value">${baseline.samples > 10 ? '✓ Learned' : '⏳ Learning'}</span>
                    </div>
                </div>
                
                <div class="card">
                    <h2>🔥 Top IPs (by packets)</h2>
                    ${ipStats.length > 0 ? 
                        ipStats.slice(0, 5).map(ip => `
                            <div class="metric">
                                <span>${ip.ip}</span>
                                <span class="metric-value">${formatNumber(ip.packets)} pkts</span>
                            </div>
                        `).join('') : 
                        '<div class="metric"><span>No IPs tracked yet</span></div>'
                    }
                </div>
                
                <div class="card">
                    <h2>🚫 Blacklist</h2>
                    <div class="metric">
                        <span>Blocked IPs</span>
                        <span class="metric-value" style="color: ${data.blacklist && data.blacklist.length > 0 ? '#ff4757' : 'inherit'}">${data.blacklist ? data.blacklist.length : 0}</span>
                    </div>
                    ${data.blacklist && data.blacklist.length > 0 ? 
                        data.blacklist.slice(0, 5).map(ip => `
                            <div class="metric">
                                <span>🚫 ${ip}</span>
                            </div>
                        `).join('') : 
                        '<div class="metric"><span>No blocked IPs</span></div>'
                    }
                </div>
                
                <div class="card">
                    <h2>🤖 ML Classification (Phase 2)</h2>
                    <div class="metric">
                        <span>ML Enabled</span>
                        <span class="metric-value" style="color: ${data.ml_enabled ? '#2ed573' : '#ffa502'}">${data.ml_enabled ? '✓ Active' : '○ Disabled'}</span>
                    </div>
                    ${data.ml_stats ? `
                        <div class="metric">
                            <span>Model Accuracy</span>
                            <span class="metric-value">${data.ml_stats.model_accuracy ? (data.ml_stats.model_accuracy * 100).toFixed(1) + '%' : 'N/A'}</span>
                        </div>
                        <div class="metric">
                            <span>Total Predictions</span>
                            <span class="metric-value">${formatNumber(data.ml_stats.total_ml_predictions || 0)}</span>
                        </div>
                        <div class="metric">
                            <span>Attacks Detected</span>
                            <span class="metric-value" style="color: ${data.ml_stats.ml_attacks_detected > 0 ? '#ff4757' : '#2ed573'}">${data.ml_stats.ml_attacks_detected || 0}</span>
                        </div>
                        <div class="metric">
                            <span>Avg Inference</span>
                            <span class="metric-value">${(data.ml_stats.avg_inference_ms || 0).toFixed(2)} ms</span>
                        </div>
                    ` : '<div class="metric"><span>Load ML model to enable</span></div>'}
                </div>
                
                ${data.feature_importance && Object.keys(data.feature_importance).length > 0 ? `
                <div class="card">
                    <h2>📊 Top Feature Importance</h2>
                    ${Object.entries(data.feature_importance).slice(0, 5).map(([name, value]) => `
                        <div class="metric">
                            <span>${name.length > 20 ? name.substring(0, 20) + '...' : name}</span>
                            <span class="metric-value">${(value * 100).toFixed(1)}%</span>
                        </div>
                    `).join('')}
                </div>
                ` : ''}
                
                <div class="card alerts">
                    <h2>🚨 Recent Alerts</h2>
                    ${alerts.length > 0 ? alerts.slice(-5).reverse().map(alert => `
                        <div class="alert-item alert-${alert.severity}">
                            <div class="alert-time">${new Date(alert.timestamp).toLocaleString()}</div>
                            <div><strong>${alert.severity.toUpperCase()}:</strong> ${alert.message}</div>
                        </div>
                    `).join('') : '<div class="metric"><span>No alerts</span></div>'}
                </div>
            `;
            
            document.getElementById('dashboard').innerHTML = html;
        }
        
        // Initial fetch
        fetchData();
        
        // Auto-refresh
        setInterval(fetchData, refreshInterval);
        
        // Countdown timer
        setInterval(() => {
            countdown--;
            if (countdown <= 0) countdown = refreshInterval / 1000;
            document.getElementById('refresh-timer').textContent = countdown;
        }, 1000);
    </script>
</body>
</html>
    """


@app.route('/api/status')
def api_status():
    """Get current system status"""
    if ddos_system:
        return jsonify(ddos_system.get_status())
    return jsonify({'error': 'System not initialized'}), 503


def run_dashboard(system, host='0.0.0.0', port=5000):
    """
    Run the dashboard server
    
    Args:
        system: DDoSMitigationSystem instance
        host: Host to bind to
        port: Port to listen on
    """
    global ddos_system
    ddos_system = system
    
    app.run(host=host, port=port, debug=False)


if __name__ == '__main__':
    print("Dashboard should be run via main.py with --dashboard flag")
    print("Or use: python -m src.dashboard")
