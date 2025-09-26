import asyncio
import aiohttp
import re
import logging
import time
from urllib.parse import urlparse
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Set, Tuple, Optional

# 配置参数
test_timeout = 5  # 测试超时时间（秒）
max_concurrent_tests = 20  # 最大并发测试数
connection_retries = 1  # 连接重试次数
test_url = "http://www.gstatic.com/generate_204"  # 用于测试的URL

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class NodeTester:
    def __init__(self):
        # 用于存储已测试的节点及其结果
        self.test_results = {}
        # 用于存储节点的唯一标识，用于去重
        self.node_identifiers = set()
        # 线程池用于执行一些阻塞操作
        self.executor = ThreadPoolExecutor(max_workers=10)

    async def resolve_hostname(self, hostname: str) -> Optional[str]:
        """解析主机名为IP地址"""
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
        """从配置行提取节点信息用于去重和测试"""
        # 提取URL部分（去掉注释部分）
        url_part = config_line.split('#')[0].strip()
        
        # 解析不同协议的配置
        protocol_info = {}
        
        if url_part.startswith('vmess://'):
            # Vmess协议解析逻辑
            protocol_info['protocol'] = 'vmess'
            # 简单的主机名和端口提取
            match = re.search(r'@([^:]+):(\d+)', url_part)
            if match:
                protocol_info['host'] = match.group(1)
                protocol_info['port'] = match.group(2)
                
        elif url_part.startswith('vless://'):
            # Vless协议解析逻辑
            protocol_info['protocol'] = 'vless'
            match = re.search(r'@([^:]+):(\d+)', url_part)
            if match:
                protocol_info['host'] = match.group(1)
                protocol_info['port'] = match.group(2)
                
        elif url_part.startswith('ss://') or url_part.startswith('ssr://'):
            # Shadowsocks和ShadowsocksR协议解析
            protocol = 'ss' if url_part.startswith('ss://') else 'ssr'
            protocol_info['protocol'] = protocol
            # 提取base64部分并解码以获取主机和端口
            match = re.search(r'@([^:]+):(\d+)', url_part)
            if match:
                protocol_info['host'] = match.group(1)
                protocol_info['port'] = match.group(2)
                
        elif url_part.startswith('trojan://'):
            # Trojan协议解析
            protocol_info['protocol'] = 'trojan'
            match = re.search(r'@([^:]+):(\d+)', url_part)
            if match:
                protocol_info['host'] = match.group(1)
                protocol_info['port'] = match.group(2)
                
        # 对于其他协议，可以添加相应的解析逻辑
        
        return protocol_info

    def get_node_identifier(self, config_line: str) -> Optional[str]:
        """生成节点的唯一标识符，用于去重"""
        info = self.extract_node_info(config_line)
        
        # 如果无法提取关键信息，则使用配置行本身的哈希值
        if not info.get('host') or not info.get('port'):
            # 去掉注释部分再计算哈希值，以避免相同节点因注释不同被视为不同节点
            url_part = config_line.split('#')[0].strip()
            return f"hash:{hash(url_part)}"
            
        # 使用协议、主机和端口组合作为唯一标识
        return f"{info['protocol']}:{info['host']}:{info['port']}"

    async def test_tcp_connectivity(self, host: str, port: int) -> Tuple[bool, float]:
        """测试TCP连接的连通性和延迟"""
        start_time = time.time()
        
        try:
            # 首先尝试解析主机名（如果是域名）
            if not re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
                ip = await self.resolve_hostname(host)
                if not ip:
                    return False, 0
                host = ip
            
            # 使用异步TCP连接测试
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=test_timeout
            )
            
            # 计算延迟
            delay = (time.time() - start_time) * 1000  # 转换为毫秒
            
            # 关闭连接
            writer.close()
            await writer.wait_closed()
            
            return True, delay
            
        except Exception as e:
            logging.debug(f"TCP connection test failed for {host}:{port}: {e}")
            return False, 0

    async def deduplicate_configs(self, configs: Set[str]) -> Set[str]:
        """对配置进行去重"""
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
        """测试单个配置的有效性"""
        # 检查是否已经测试过
        if config_line in self.test_results:
            return self.test_results[config_line]
            
        result = {
            'config': config_line,
            'is_valid': False,
            'delay': 0,
            'status': '未测试',
            'error': None
        }
        
        try:
            # 提取节点信息
            info = self.extract_node_info(config_line)
            
            if not info.get('host') or not info.get('port'):
                result['status'] = '无法解析'
                result['error'] = '无法从配置中提取主机和端口'
                self.test_results[config_line] = result
                return result
                
            host = info['host']
            port = int(info['port'])
            
            # 测试TCP连接
            is_valid, delay = await self.test_tcp_connectivity(host, port)
            
            result['is_valid'] = is_valid
            result['delay'] = delay
            result['status'] = '有效' if is_valid else '无效'
            
        except Exception as e:
            logging.warning(f"Error testing config {config_line[:50]}...: {e}")
            result['status'] = '测试错误'
            result['error'] = str(e)
            
        self.test_results[config_line] = result
        return result

    async def batch_test_configs(self, configs: Set[str]) -> Dict[str, Dict]:
        """批量测试配置的有效性"""
        logging.info(f"Starting batch test for {len(configs)} configs")
        
        # 使用信号量限制并发测试数
        sem = asyncio.Semaphore(max_concurrent_tests)
        
        async def bounded_test(config):
            async with sem:
                return await self.test_config_validity(config)
                
        # 并发测试所有配置
        tasks = [bounded_test(config) for config in configs]
        results = await asyncio.gather(*tasks)
        
        # 将结果转换为字典格式
        test_results_dict = {result['config']: result for result in results}
        
        # 统计结果
        valid_count = sum(1 for result in results if result['is_valid'])
        
        logging.info(f"Batch test completed: {valid_count}/{len(configs)} configs are valid")
        
        return test_results_dict

    def get_valid_configs(self, test_results: Dict[str, Dict]) -> Set[str]:
        """从测试结果中获取有效的配置"""
        return {config for config, result in test_results.items() if result['is_valid']}

    def sort_configs_by_delay(self, test_results: Dict[str, Dict]) -> list:
        """根据延迟对配置进行排序（延迟低的优先）"""
        valid_results = [(config, result['delay']) for config, result in test_results.items() if result['is_valid']]
        return sorted(valid_results, key=lambda x: x[1])

    async def process_configs(self, configs: Set[str]) -> Tuple[Set[str], Dict[str, Dict]]:
        """处理配置：去重并测试有效性"""
        # 首先去重
        deduplicated = await self.deduplicate_configs(configs)
        
        # 然后测试有效性
        test_results = await self.batch_test_configs(deduplicated)
        
        # 获取有效的配置
        valid_configs = self.get_valid_configs(test_results)
        
        return valid_configs, test_results

# 导出单例对象供外部使用
tester = NodeTester()

# 辅助函数供主程序调用
async def deduplicate_and_test_configs(configs: Set[str]) -> Tuple[Set[str], Dict[str, Dict]]:
    """对配置进行去重和测试有效性的辅助函数"""
    return await tester.process_configs(configs)

async def deduplicate_configs_only(configs: Set[str]) -> Set[str]:
    """仅对配置进行去重的辅助函数"""
    return await tester.deduplicate_configs(configs)

async def test_configs_only(configs: Set[str]) -> Dict[str, Dict]:
    """仅测试配置有效性的辅助函数"""
    return await tester.batch_test_configs(configs)

# 示例用法（如需要直接运行此模块进行测试）
if __name__ == "__main__":
    # 示例配置（实际使用时应替换为真实配置）
    sample_configs = {
        # 这里只是示例，实际使用时应替换为真实配置
        'vmess://example_config_1',
        'vless://example_config_2',
        'ss://example_config_3',
    }
    
    async def main():
        valid, results = await deduplicate_and_test_configs(sample_configs)
        print(f"Valid configs count: {len(valid)}")
        
    asyncio.run(main())