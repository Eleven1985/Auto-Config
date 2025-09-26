import asyncio
import aiohttp
import re
import logging
import time
import socket
import os
from logging.handlers import RotatingFileHandler
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Set, Tuple, Optional
import asyncio

# 优化的配置参数
TEST_TIMEOUT = 3  # 降低超时时间(秒)
MAX_CONCURRENT_TESTS = 50  # 增加并发测试数量
CONNECTION_RETRIES = 1  # 保持最小重试次数
MIN_VALID_DELAY = 1  # 保持最小有效延迟阈值(ms)

# 简化日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class NodeTester:
    def __init__(self):
        """初始化节点测试器"""
        self.test_results = {}
        self.node_identifiers = set()
        # 减少线程池工作线程数量
        self.executor = ThreadPoolExecutor(max_workers=5)

    async def resolve_hostname(self, hostname: str) -> Optional[str]:
        """异步解析主机名到IP地址"""
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                self.executor,
                socket.gethostbyname,
                hostname
            )
        except socket.gaierror:
            # 只记录关键错误
            return None

    def extract_node_info(self, config_line: str) -> Dict[str, str]:
        """提取节点信息用于去重和测试"""
        url_part = config_line.split('#')[0].strip()
        protocol_info = {}
        
        # 简化协议解析逻辑
        protocols = ['vmess', 'vless', 'ss', 'ssr', 'trojan', 'tuic', 'hysteria2']
        
        for proto in protocols:
            if url_part.startswith(f'{proto}://'):
                protocol_info['protocol'] = proto
                match = re.search(r'@([^:]+):(\d+)', url_part)
                if match:
                    protocol_info['host'] = match.group(1)
                    protocol_info['port'] = match.group(2)
                break
                
        return protocol_info

    def get_node_identifier(self, config_line: str) -> Optional[str]:
        """生成节点唯一标识符用于去重"""
        info = self.extract_node_info(config_line)
        
        if not info.get('host') or not info.get('port'):
            url_part = config_line.split('#')[0].strip()
            return f"hash:{hash(url_part)}"
            
        return f"{info['protocol']}:{info['host']}:{info['port']}"

    async def test_tcp_connectivity(self, host: str, port: int) -> Tuple[bool, float]:
        """简化的TCP连接测试"""
        for attempt in range(CONNECTION_RETRIES):
            start_time = time.time()
            
            try:
                # 简化主机名解析逻辑
                if not re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
                    ip = await self.resolve_hostname(host)
                    if not ip:
                        if attempt == CONNECTION_RETRIES - 1:
                            return False, 0
                        continue
                    host = ip
                
                # 测试TCP连接
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=TEST_TIMEOUT
                )
                
                # 计算延迟
                delay = (time.time() - start_time) * 1000
                
                # 关闭连接
                writer.close()
                await writer.wait_closed()
                
                return delay >= MIN_VALID_DELAY, delay
                
            except Exception:
                if attempt == CONNECTION_RETRIES - 1:
                    return False, 0
        
        return False, 0

    async def deduplicate_configs(self, configs: Set[str]) -> Set[str]:
        """配置去重"""
        deduplicated = set()
        self.node_identifiers.clear()
        
        for config in configs:
            identifier = self.get_node_identifier(config)
            if identifier and identifier not in self.node_identifiers:
                self.node_identifiers.add(identifier)
                deduplicated.add(config)
                
        return deduplicated

    async def test_config_validity(self, config_line: str) -> Dict:
        """简化的配置有效性测试"""
        # 检查是否已测试
        if config_line in self.test_results:
            return self.test_results[config_line]
            
        result = {
            'config': config_line,
            'is_valid': False,
            'delay': 0
        }
        
        try:
            # 提取节点信息
            info = self.extract_node_info(config_line)
            
            if not info.get('host') or not info.get('port'):
                self.test_results[config_line] = result
                return result
                
            host = info['host']
            port = int(info['port'])
            
            # 测试TCP连接
            is_valid, delay = await self.test_tcp_connectivity(host, port)
            
            result['is_valid'] = is_valid
            result['delay'] = delay
            
        except Exception:
            pass
            
        self.test_results[config_line] = result
        return result

    # 进一步优化配置参数
    TEST_TIMEOUT = 2  # 进一步降低超时时间(秒)
    MAX_CONCURRENT_TESTS = 100  # 进一步增加并发测试数量
    CONNECTION_RETRIES = 0  # 移除重试，加快测试速度
    MIN_VALID_DELAY = 5  # 稍微提高最小有效延迟阈值(ms)
    
    async def batch_test_configs(self, configs: Set[str]) -> Dict[str, Dict]:
        """批量测试配置有效性 - 优化版"""
        if not configs:
            return {}
        
        # 重置测试结果
        self.test_results.clear()
        
        # 大幅提高并发量
        sem = asyncio.Semaphore(MAX_CONCURRENT_TESTS)
        
        async def bounded_test(config):
            async with sem:
                try:
                    # 快速过滤无效格式配置
                    url_part = config.split('#')[0].strip()
                    if len(url_part) < 20:
                        return {"config": config, "is_valid": False, "delay": 0}
                    
                    # 提取节点信息
                    info = self.extract_node_info(config)
                    if not info.get('host') or not info.get('port'):
                        return {"config": config, "is_valid": False, "delay": 0}
                        
                    # 快速测试连接
                    host = info['host']
                    port = int(info['port'])
                    is_valid, delay = await self.test_tcp_connectivity(host, port)
                    
                    return {"config": config, "is_valid": is_valid, "delay": delay}
                except Exception:
                    return {"config": config, "is_valid": False, "delay": 0}
        
        # 并发测试所有配置
        tasks = [bounded_test(config) for config in configs]
        results = await asyncio.gather(*tasks)
        
        # 转换结果为字典格式
        test_results_dict = {result['config']: result for result in results}
        
        return test_results_dict
        
    # 进一步简化 test_tcp_connectivity 方法
    async def test_tcp_connectivity(self, host: str, port: int) -> Tuple[bool, float]:
        """简化的TCP连接测试"""
        start_time = time.time()
        
        try:
            # 简化主机名解析逻辑，减少DNS查询时间
            if not re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
                # 直接使用主机名而不解析IP，让操作系统处理DNS缓存
                pass
            
            # 测试TCP连接，使用更短的超时时间
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=TEST_TIMEOUT
            )
            
            # 计算延迟
            delay = (time.time() - start_time) * 1000
            
            # 关闭连接
            writer.close()
            await writer.wait_closed()
            
            return delay >= MIN_VALID_DELAY, delay
            
        except Exception:
            return False, 0

    def get_valid_configs(self, test_results: Dict[str, Dict]) -> Set[str]:
        """获取有效的配置"""
        return {config for config, result in test_results.items() if result['is_valid'] and result['delay'] >= MIN_VALID_DELAY}

    async def process_configs(self, configs: Set[str]) -> Set[str]:
        """简化的配置处理流程：去重和测试有效性"""
        # 首先去重
        deduplicated = await self.deduplicate_configs(configs)
        
        # 然后测试有效性
        test_results = await self.batch_test_configs(deduplicated)
        
        # 获取有效配置
        valid_configs = self.get_valid_configs(test_results)
        
        return valid_configs

# 导出单例供外部使用
tester = NodeTester()

# 简化的辅助函数
async def deduplicate_and_test_configs(configs: Set[str]) -> Set[str]:
    """辅助函数：去重并测试配置"""
    return await tester.process_configs(configs)

# 移除未使用的辅助函数

# 示例用法
if __name__ == "__main__":
    # 示例配置
    sample_configs = {
        'vmess://example_config_1',
        'vless://example_config_2',
        'ss://example_config_3',
    }
    
    async def main():
        valid = await deduplicate_and_test_configs(sample_configs)
        print(f"有效配置数量: {len(valid)}")
        
    asyncio.run(main())


# 创建logs目录
if not os.path.exists('logs'):
    os.makedirs('logs')

# Configure logging with file rotation
logger = logging.getLogger('node_tester')
logger.setLevel(logging.INFO)

# 创建格式化器
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s')

# 控制台处理器
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# 文件处理器 (带滚动功能)
file_handler = RotatingFileHandler(
    'logs/node_tester.log',
    maxBytes=5*1024*1024,  # 5MB
    backupCount=3,
    encoding='utf-8'
)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# 错误日志单独记录
error_handler = RotatingFileHandler(
    'logs/node_tester_error.log',
    maxBytes=5*1024*1024,
    backupCount=3,
    encoding='utf-8'
)
error_handler.setLevel(logging.ERROR)
error_handler.setFormatter(formatter)
logger.addHandler(error_handler)

# 重命名logging为logger以便后续使用
logging = logger