"""
Test Traffic Simulator - Unit tests for traffic simulation
"""

import pytest
from simulation.traffic_simulator import TrafficSimulator, AttackType


class TestTrafficSimulator:
    """Test cases for traffic simulator"""
    
    def test_initialization(self):
        """Test simulator initialization"""
        sim = TrafficSimulator()
        assert sim.running == False
        assert sim.stats['packets_generated'] == 0
    
    def test_random_ip_generation(self):
        """Test random IP generation"""
        sim = TrafficSimulator()
        
        ips = [sim.generate_random_ip() for _ in range(100)]
        
        # Should generate unique IPs
        assert len(set(ips)) > 50
        
        # IPs should be valid format
        for ip in ips:
            parts = ip.split('.')
            assert len(parts) == 4
            for part in parts:
                assert 0 <= int(part) <= 255
    
    def test_normal_traffic_generation(self):
        """Test normal traffic generation"""
        sim = TrafficSimulator()
        
        # Generate small amount of traffic
        stats = sim.generate_normal_traffic(pps=1000, duration=1.0)
        
        # Should generate approximately 1000 packets
        assert 900 <= stats['packets_generated'] <= 1100
        assert stats['bytes_generated'] > 0
    
    def test_udp_flood_generation(self):
        """Test UDP flood attack generation"""
        sim = TrafficSimulator()
        
        stats = sim.generate_attack_traffic(
            attack_type=AttackType.UDP_FLOOD,
            pps=5000,
            duration=0.5
        )
        
        # Should generate approximately 2500 packets
        assert 2000 <= stats['packets_generated'] <= 3000
    
    def test_syn_flood_generation(self):
        """Test SYN flood attack generation"""
        sim = TrafficSimulator()
        
        stats = sim.generate_attack_traffic(
            attack_type=AttackType.SYN_FLOOD,
            pps=5000,
            duration=0.5
        )
        
        assert stats['packets_generated'] > 0
    
    def test_simulator_stop(self):
        """Test stopping simulator"""
        sim = TrafficSimulator()
        
        # Start generation in background (would need threading for real test)
        sim.running = True
        sim.stop()
        
        assert sim.running == False


class TestAttackScenarios:
    """Test attack scenario definitions"""
    
    def test_scenario_import(self):
        """Test importing attack scenarios"""
        from simulation.attack_scenarios import ScenarioLibrary
        
        scenarios = ScenarioLibrary.get_all_scenarios()
        assert len(scenarios) > 0
    
    def test_scenario_by_scale(self):
        """Test filtering scenarios by scale"""
        from simulation.attack_scenarios import ScenarioLibrary
        
        small = ScenarioLibrary.get_scenarios_by_scale('small')
        large = ScenarioLibrary.get_scenarios_by_scale('large')
        
        assert len(small) > 0
        assert len(large) > 0
        
        # Small scenarios should have lower pps than large
        if small and large:
            assert small[0].intensity_pps < large[0].intensity_pps


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
