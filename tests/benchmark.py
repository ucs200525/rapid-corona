"""
Benchmark - Performance benchmarking for DDoS mitigation system
Tests detection latency and throughput at various packet rates
"""

import argparse
import time
import json
from pathlib import Path
from typing import Dict, List
import logging

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from simulation.traffic_simulator import TrafficSimulator, AttackType
from simulation.attack_scenarios import ScenarioLibrary

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BenchmarkRunner:
    """Run performance benchmarks"""
    
    def __init__(self):
        self.simulator = TrafficSimulator()
        self.results = []
    
    def benchmark_attack_scenario(self, scenario_name: str) -> Dict:
        """
        Benchmark a specific attack scenario
        
        Args:
            scenario_name: Name of the scenario to test
            
        Returns:
            Benchmark results dictionary
        """
        scenario = ScenarioLibrary.get_scenario_by_name(scenario_name)
        if not scenario:
            logger.error(f"Scenario not found: {scenario_name}")
            return {}
        
        logger.info("=" * 70)
        logger.info(f"Benchmarking: {scenario.name}")
        logger.info(f"Description: {scenario.description}")
        logger.info(f"Attack Type: {scenario.attack_type.value}")
        logger.info(f"Intensity: {scenario.intensity_pps:,} pps")
        logger.info(f"Duration: {scenario.duration}s")
        logger.info("=" * 70)
        
        # Start timing
        start_time = time.time()
        
        # Generate attack traffic
        stats = self.simulator.generate_attack_traffic(
            attack_type=scenario.attack_type,
            pps=scenario.intensity_pps,
            duration=scenario.duration
        )
        
        end_time = time.time()
        
        # Calculate metrics
        actual_duration = end_time - start_time
        actual_pps = stats['packets_generated'] / actual_duration if actual_duration > 0 else 0
        
        result = {
            'scenario_name': scenario.name,
            'attack_type': scenario.attack_type.value,
            'target_pps': scenario.intensity_pps,
            'actual_pps': actual_pps,
            'target_duration': scenario.duration,
            'actual_duration': actual_duration,
            'packets_generated': stats['packets_generated'],
            'bytes_generated': stats['bytes_generated'],
            'throughput_mbps': (stats['bytes_generated'] * 8 / actual_duration / 1_000_000) if actual_duration > 0 else 0,
        }
        
        logger.info(f"✓ Generated {stats['packets_generated']:,} packets in {actual_duration:.2f}s")
        logger.info(f"  Actual PPS: {actual_pps:,.0f}")
        logger.info(f"  Throughput: {result['throughput_mbps']:.2f} Mbps")
        logger.info("")
        
        self.results.append(result)
        return result
    
    def benchmark_by_scale(self, scale: str):
        """
        Benchmark all scenarios of a given scale
        
        Args:
            scale: 'small', 'medium', 'large', or 'hyper'
        """
        scenarios = ScenarioLibrary.get_scenarios_by_scale(scale)
        
        logger.info(f"Benchmarking {len(scenarios)} {scale} scenarios...")
        logger.info("")
        
        for scenario in scenarios:
            self.benchmark_attack_scenario(scenario.name)
    
    def benchmark_packets_per_second_sweep(self, rates: List[int], duration: float = 10.0):
        """
        Benchmark detection latency across different packet rates
        
        Args:
            rates: List of packet rates to test
            duration: Duration for each test
        """
        logger.info("=" * 70)
        logger.info("Packet Rate Sweep Benchmark")
        logger.info("=" * 70)
        
        for rate in rates:
            logger.info(f"Testing {rate:,} pps...")
            
            start_time = time.time()
            
            stats = self.simulator.generate_attack_traffic(
                attack_type=AttackType.UDP_FLOOD,
                pps=rate,
                duration=duration
            )
            
            end_time = time.time()
            actual_duration = end_time - start_time
            actual_pps = stats['packets_generated'] / actual_duration if actual_duration > 0 else 0
            
            result = {
                'test_type': 'pps_sweep',
                'target_pps': rate,
                'actual_pps': actual_pps,
                'duration': actual_duration,
                'packets': stats['packets_generated'],
            }
            
            logger.info(f"  Actual: {actual_pps:,.0f} pps ({actual_duration:.2f}s)")
            self.results.append(result)
        
        logger.info("")
    
    def save_results(self, output_file: str = "benchmark_results.json"):
        """Save benchmark results to file"""
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump({
                'timestamp': time.time(),
                'results': self.results
            }, f, indent=2)
        
        logger.info(f"Results saved to {output_path}")
    
    def print_summary(self):
        """Print benchmark summary"""
        if not self.results:
            logger.info("No benchmark results")
            return
        
        logger.info("=" * 70)
        logger.info("BENCHMARK SUMMARY")
        logger.info("=" * 70)
        
        for result in self.results:
            if 'scenario_name' in result:
                logger.info(f"Scenario: {result['scenario_name']}")
                logger.info(f"  Target: {result['target_pps']:,} pps")
                logger.info(f"  Actual: {result['actual_pps']:,.0f} pps")
                logger.info(f"  Packets: {result['packets_generated']:,}")
                logger.info(f"  Throughput: {result['throughput_mbps']:.2f} Mbps")
                logger.info("")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='DDoS Mitigation Benchmark')
    
    parser.add_argument(
        '--scenario', '-s',
        help='Run specific scenario by name'
    )
    
    parser.add_argument(
        '--scale',
        choices=['small', 'medium', 'large', 'hyper'],
        help='Run all scenarios of given scale'
    )
    
    parser.add_argument(
        '--rate',
        type=int,
        action='append',
        help='Test specific packet rate (can specify multiple times)'
    )
    
    parser.add_argument(
        '--output', '-o',
        default='benchmark_results.json',
        help='Output file for results'
    )
    
    parser.add_argument(
        '--list',
        action='store_true',
        help='List all available scenarios'
    )
    
    args = parser.parse_args()
    
    if args.list:
        scenarios = ScenarioLibrary.get_all_scenarios()
        logger.info("Available scenarios:")
        for scenario in scenarios:
            logger.info(f"  - {scenario.name}: {scenario.description} ({scenario.intensity_pps:,} pps)")
        return
    
    benchmark = BenchmarkRunner()
    
    if args.scenario:
        benchmark.benchmark_attack_scenario(args.scenario)
    elif args.scale:
        benchmark.benchmark_by_scale(args.scale)
    elif args.rate:
        benchmark.benchmark_packets_per_second_sweep(args.rate, duration=5.0)
    else:
        # Default: run medium scale scenarios
        logger.info("No specific test specified, running medium scale scenarios...")
        benchmark.benchmark_by_scale('medium')
    
    benchmark.print_summary()
    benchmark.save_results(args.output)


if __name__ == '__main__':
    main()
