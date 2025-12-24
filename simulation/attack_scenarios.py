"""
Attack Scenarios - Pre-defined attack scenarios for benchmarking
"""

from dataclasses import dataclass
from typing import Dict, List
from enum import Enum

from .traffic_simulator import AttackType


@dataclass
class AttackScenario:
    """Attack scenario definition"""
    name: str
    description: str
    attack_type: AttackType
    intensity_pps: int  # Packets per second
    duration: float  # seconds
    mixed_with_normal: bool = False
    normal_traffic_pps: int = 0
    

class ScenarioLibrary:
    """Library of pre-defined attack scenarios"""
    
    # Small scale attacks (for testing)
    SMALL_UDP_FLOOD = AttackScenario(
        name="Small UDP Flood",
        description="Low-intensity UDP flood  (10k pps)",
        attack_type=AttackType.UDP_FLOOD,
        intensity_pps=10_000,
        duration=60
    )
    
    # Medium scale attacks
    MEDIUM_SYN_FLOOD = AttackScenario(
        name="Medium SYN Flood",
        description="Medium SYN flood attack (100k pps)",
        attack_type=AttackType.SYN_FLOOD,
        intensity_pps=100_000,
        duration=120
    )
    
    MEDIUM_MIXED = AttackScenario(
        name="Medium Mixed Attack",
        description="Mixed attack vectors (100k pps)",
        attack_type=AttackType.MIXED,
        intensity_pps=100_000,
        duration=120
    )
    
    # Large scale volumetric attacks
    LARGE_UDP_FLOOD = AttackScenario(
        name="Large UDP Flood",
        description="High-intensity UDP flood (1M pps)",
        attack_type=AttackType.UDP_FLOOD,
        intensity_pps=1_000_000,
        duration=180
    )
    
    LARGE_SYN_FLOOD = AttackScenario(
        name="Large SYN Flood",
        description="Massive SYN flood (1M pps)",
        attack_type=AttackType.SYN_FLOOD,
        intensity_pps=1_000_000,
        duration=180
    )
    
    # Hyper-volumetric (India IX scale testing)
    HYPER_VOLUMETRIC_UDP = AttackScenario(
        name="Hyper-Volumetric UDP",
        description="Extreme UDP flood (5M pps)",
        attack_type=AttackType.UDP_FLOOD,
        intensity_pps=5_000_000,
        duration=60
    )
    
    HYPER_VOLUMETRIC_MIXED = AttackScenario(
        name="Hyper-Volumetric Mixed",
        description="Extreme multi-vector attack (5M pps)",
        attack_type=AttackType.MIXED,
        intensity_pps=5_000_000,
        duration=60
    )
    
    # Flash crowd simulation (legitimate traffic surge)
    FLASH_CROWD = AttackScenario(
        name="Flash Crowd",
        description="Legitimate traffic surge (500k pps)",
        attack_type=AttackType.HTTP_FLOOD,  # But from diverse sources
        intensity_pps=500_000,
        duration=120,
        mixed_with_normal=False
    )
    
    # Mixed scenarios (attack + normal traffic)
    STEALTHY_ATTACK = AttackScenario(
        name="Stealthy Attack",
        description="Attack hidden in normal traffic",
        attack_type=AttackType.UDP_FLOOD,
        intensity_pps=200_000,
        duration=180,
        mixed_with_normal=True,
        normal_traffic_pps=50_000
    )
    
    @classmethod
    def get_all_scenarios(cls) -> List[AttackScenario]:
        """Get all defined scenarios"""
        return [
            cls.SMALL_UDP_FLOOD,
            cls.MEDIUM_SYN_FLOOD,
            cls.MEDIUM_MIXED,
            cls.LARGE_UDP_FLOOD,
            cls.LARGE_SYN_FLOOD,
            cls.HYPER_VOLUMETRIC_UDP,
            cls.HYPER_VOLUMETRIC_MIXED,
            cls.FLASH_CROWD,
            cls.STEALTHY_ATTACK,
        ]
    
    @classmethod
    def get_scenario_by_name(cls, name: str) -> AttackScenario:
        """Get scenario by name"""
        scenarios = {s.name: s for s in cls.get_all_scenarios()}
        return scenarios.get(name)
    
    @classmethod
    def get_scenarios_by_scale(cls, scale: str) -> List[AttackScenario]:
        """
        Get scenarios by scale
        
        Args:
            scale: 'small', 'medium', 'large', or 'hyper'
        """
        all_scenarios = cls.get_all_scenarios()
        
        scale_map = {
            'small': lambda s: s.intensity_pps < 50_000,
            'medium': lambda s: 50_000 <= s.intensity_pps < 500_000,
            'large': lambda s: 500_000 <= s.intensity_pps < 2_000_000,
            'hyper': lambda s: s.intensity_pps >= 2_000_000,
        }
        
        filter_fn = scale_map.get(scale)
        if filter_fn:
            return [s for s in all_scenarios if filter_fn(s)]
        
        return all_scenarios
