import asyncio
import aiohttp
import re
import logging
import time
from urllib.parse import urlparse
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Set, Tuple, Optional, List
import asyncio

# Configuration parameters
TEST_TIMEOUT = 5  # Test timeout in seconds
MAX_CONCURRENT_TESTS = 20  # Maximum concurrent tests
CONNECTION_RETRIES = 1  # Connection retry count
MIN_VALID_DELAY = 1  # Minimum delay to consider a node valid (ms)
TEST_URL = "http://www.gstatic.com/generate_204"  # URL for testing

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class NodeTester:
    def __init__(self):
        """Initialize the node tester with required resources."""
        # Store test results
        self.test_results = {}
        # Store node identifiers for deduplication
        self.node_identifiers = set()
        # Thread pool for blocking operations
        self.executor = ThreadPoolExecutor(max_workers=10)

    async def resolve_hostname(self, hostname: str) -> Optional[str]:
        """Resolve hostname to IP address asynchronously."""
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                self.executor,
                socket.gethostbyname,
                hostname
            )
        except socket.gaierror:
            logging.warning(f"Failed to resolve hostname: {hostname}")
            return None

    def extract_node_info(self, config_line: str) -> Dict[str, str]:
        """Extract node information for deduplication and testing"""
        # Extract URL part (remove comments)
        url_part = config_line.split('#')[0].strip()
        
        # Parse different protocol configurations
        protocol_info = {}
        
        if url_part.startswith('vmess://'):
            # VMess protocol parsing
            protocol_info['protocol'] = 'vmess'
            # Simple extraction of hostname and port
            match = re.search(r'@([^:]+):(\d+)', url_part)
            if match:
                protocol_info['host'] = match.group(1)
                protocol_info['port'] = match.group(2)
                
        elif url_part.startswith('vless://'):
            # VLESS protocol parsing
            protocol_info['protocol'] = 'vless'
            match = re.search(r'@([^:]+):(\d+)', url_part)
            if match:
                protocol_info['host'] = match.group(1)
                protocol_info['port'] = match.group(2)
                
        elif url_part.startswith('ss://') or url_part.startswith('ssr://'):
            # Shadowsocks and ShadowsocksR protocol parsing
            protocol = 'ss' if url_part.startswith('ss://') else 'ssr'
            protocol_info['protocol'] = protocol
            match = re.search(r'@([^:]+):(\d+)', url_part)
            if match:
                protocol_info['host'] = match.group(1)
                protocol_info['port'] = match.group(2)
                
        elif url_part.startswith('trojan://'):
            # Trojan protocol parsing
            protocol_info['protocol'] = 'trojan'
            match = re.search(r'@([^:]+):(\d+)', url_part)
            if match:
                protocol_info['host'] = match.group(1)
                protocol_info['port'] = match.group(2)
                
        # Additional protocol parsing logic
        elif url_part.startswith('tuic://'):
            protocol_info['protocol'] = 'tuic'
            match = re.search(r'@([^:]+):(\d+)', url_part)
            if match:
                protocol_info['host'] = match.group(1)
                protocol_info['port'] = match.group(2)
        elif url_part.startswith('hysteria2://'):
            protocol_info['protocol'] = 'hysteria2'
            match = re.search(r'@([^:]+):(\d+)', url_part)
            if match:
                protocol_info['host'] = match.group(1)
                protocol_info['port'] = match.group(2)
                
        return protocol_info

    def get_node_identifier(self, config_line: str) -> Optional[str]:
        """Generate unique identifier for node deduplication"""
        info = self.extract_node_info(config_line)
        
        # If critical information cannot be extracted, use hash of the URL part
        if not info.get('host') or not info.get('port'):
            # Remove comments before calculating hash to avoid treating identical nodes as different
            url_part = config_line.split('#')[0].strip()
            return f"hash:{hash(url_part)}"
            
        # Use protocol, host, and port combination as unique identifier
        return f"{info['protocol']}:{info['host']}:{info['port']}"

    async def test_tcp_connectivity(self, host: str, port: int) -> Tuple[bool, float]:
        """Test TCP connection connectivity and latency with retry logic"""
        for attempt in range(CONNECTION_RETRIES):
            start_time = time.time()
            
            try:
                # Try to resolve hostname if it's not an IP address
                if not re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
                    ip = await self.resolve_hostname(host)
                    if not ip:
                        if attempt == CONNECTION_RETRIES - 1:
                            return False, 0
                        continue
                    host = ip
                
                # Test TCP connection asynchronously
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=TEST_TIMEOUT
                )
                
                # Calculate latency in milliseconds
                delay = (time.time() - start_time) * 1000
                
                # Close connection
                writer.close()
                await writer.wait_closed()
                
                # Ensure we have a valid delay measurement
                if delay >= MIN_VALID_DELAY:
                    return True, delay
                else:
                    return False, 0
                    
            except Exception as e:
                logging.debug(f"TCP connection test failed for {host}:{port} (attempt {attempt+1}/{CONNECTION_RETRIES}): {e}")
                if attempt == CONNECTION_RETRIES - 1:
                    return False, 0
        
        return False, 0

    async def deduplicate_configs(self, configs: Set[str]) -> Set[str]:
        """Deduplicate configurations"""
        deduplicated = set()
        self.node_identifiers.clear()
        
        for config in configs:
            identifier = self.get_node_identifier(config)
            if identifier and identifier not in self.node_identifiers:
                self.node_identifiers.add(identifier)
                deduplicated.add(config)
                
        logging.info(f"Deduplication completed: {len(configs)} -> {len(deduplicated)} configs")
        return deduplicated

    async def test_config_validity(self, config_line: str) -> Dict:
        """Test validity of a single configuration"""
        # Check if already tested
        if config_line in self.test_results:
            return self.test_results[config_line]
            
        result = {
            'config': config_line,
            'is_valid': False,
            'delay': 0,
            'status': 'Untested',
            'error': None
        }
        
        try:
            # Extract node information
            info = self.extract_node_info(config_line)
            
            if not info.get('host') or not info.get('port'):
                result['status'] = 'Unparseable'
                result['error'] = 'Unable to extract host and port from configuration'
                self.test_results[config_line] = result
                return result
                
            host = info['host']
            port = int(info['port'])
            
            # Test TCP connection
            is_valid, delay = await self.test_tcp_connectivity(host, port)
            
            result['is_valid'] = is_valid
            result['delay'] = delay
            result['status'] = 'Valid' if is_valid else 'Invalid'
            
        except Exception as e:
            logging.warning(f"Error testing config {config_line[:50]}...: {e}")
            result['status'] = 'Test Error'
            result['error'] = str(e)
            
        self.test_results[config_line] = result
        return result

    async def batch_test_configs(self, configs: Set[str]) -> Dict[str, Dict]:
        """Batch test configuration validity"""
        if not configs:
            logging.info("No configurations to test.")
            return {}
        
        logging.info(f"Starting batch test for {len(configs)} configs")
        
        # Reset test results for fresh test
        self.test_results.clear()
        
        # Use semaphore to limit concurrent tests
        sem = asyncio.Semaphore(MAX_CONCURRENT_TESTS)
        
        async def bounded_test(config):
            async with sem:
                return await self.test_config_validity(config)
                
        # Test all configurations concurrently
        tasks = [bounded_test(config) for config in configs]
        results = await asyncio.gather(*tasks)
        
        # Convert results to dictionary format
        test_results_dict = {result['config']: result for result in results}
        
        # Count results
        valid_count = sum(1 for result in results if result['is_valid'])
        
        logging.info(f"Batch test completed: {valid_count}/{len(configs)} configs are valid")
        
        return test_results_dict

    def get_valid_configs(self, test_results: Dict[str, Dict]) -> Set[str]:
        """Get valid configurations from test results with real delay"""
        return {config for config, result in test_results.items() if result['is_valid'] and result['delay'] >= MIN_VALID_DELAY}

    def sort_configs_by_delay(self, test_results: Dict[str, Dict]) -> list:
        """Sort configurations by delay (lowest first)"""
        valid_results = [(config, result['delay']) for config, result in test_results.items() if result['is_valid'] and result['delay'] >= MIN_VALID_DELAY]
        return sorted(valid_results, key=lambda x: x[1])

    async def process_configs(self, configs: Set[str]) -> Tuple[Set[str], Dict[str, Dict]]:
        """Process configurations: deduplicate and test validity"""
        # First deduplicate
        deduplicated = await self.deduplicate_configs(configs)
        
        # Then test validity
        test_results = await self.batch_test_configs(deduplicated)
        
        # Get valid configurations with real delay
        valid_configs = self.get_valid_configs(test_results)
        
        return valid_configs, test_results

# Export singleton for external use
tester = NodeTester()

# Helper functions for main program
async def deduplicate_and_test_configs(configs: Set[str]) -> Tuple[Set[str], Dict[str, Dict]]:
    """Helper function to deduplicate and test configurations"""
    return await tester.process_configs(configs)

async def deduplicate_configs_only(configs: Set[str]) -> Set[str]:
    """Helper function to only deduplicate configurations"""
    return await tester.deduplicate_configs(configs)

async def test_configs_only(configs: Set[str]) -> Dict[str, Dict]:
    """Helper function to only test configuration validity"""
    return await tester.batch_test_configs(configs)

# Example usage (if running this module directly for testing)
if __name__ == "__main__":
    # Sample configurations (replace with real ones in actual use)
    sample_configs = {
        # These are just examples, replace with real configurations in actual use
        'vmess://example_config_1',
        'vless://example_config_2',
        'ss://example_config_3',
    }
    
    async def main():
        valid, results = await deduplicate_and_test_configs(sample_configs)
        print(f"Valid configs count: {len(valid)}")
        # Print valid configs sorted by delay
        sorted_valid = tester.sort_configs_by_delay(results)
        for config, delay in sorted_valid:
            print(f"Valid config with delay {delay:.2f}ms: {config}")
        
    asyncio.run(main())