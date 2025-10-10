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

# 创建logs目录
if not os.path.exists('logs'):
    os.makedirs('logs')

# 配置日志
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

# 配置参数
TEST_TIMEOUT = 1.5  # 超时时间
MAX_CONCURRENT_TESTS = 150  # 并发测试数量
MIN_VALID_DELAY = 5  # 最小有效延迟阈值(ms)
GEOIP_TIMEOUT = 2.0  # IP地理位置查询超时时间
GEOIP_CACHE_SIZE = 500  # IP地理位置缓存大小

class NodeTester:
    def __init__(self):
        """初始化节点测试器"""
        self.node_identifiers = set()
        # 线程池工作线程数量
        self.executor = ThreadPoolExecutor(max_workers=5)
        # IP地理位置缓存
        self.geoip_cache = {}

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
        start_time = time.time()
        
        try:
            # 测试TCP连接，使用超时时间
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

    async def batch_test_configs(self, configs: Set[str]) -> Dict[str, Dict]:
        """批量测试配置有效性"""
        if not configs:
            return {}
        
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

    def get_valid_configs(self, test_results: Dict[str, Dict]) -> Set[str]:
        """获取有效的配置"""
        return {config for config, result in test_results.items() if result['is_valid'] and result['delay'] >= MIN_VALID_DELAY}

    async def process_configs(self, configs: Set[str]) -> Set[str]:
        """配置处理流程：去重和测试有效性"""
        # 首先去重
        deduplicated = await self.deduplicate_configs(configs)
        
        # 然后测试有效性
        test_results = await self.batch_test_configs(deduplicated)
        
        # 获取有效配置
        valid_configs = self.get_valid_configs(test_results)
        
        return valid_configs
    
    async def resolve_hostname(self, hostname: str) -> Optional[str]:
        """解析域名获取IP地址"""
        try:
            # 使用线程池执行DNS解析以避免阻塞事件循环
            loop = asyncio.get_event_loop()
            ip_address = await loop.run_in_executor(
                self.executor,
                lambda: socket.gethostbyname(hostname)
            )
            return ip_address
        except Exception:
            logging.warning(f"Failed to resolve hostname: {hostname}")
            return None

    async def get_country_by_ip(self, ip_address: str) -> Optional[str]:
        """通过IP地址查询国家信息"""
        # 检查缓存
        if ip_address in self.geoip_cache:
            return self.geoip_cache[ip_address]
        
        try:
            # 使用ip-api.com免费API查询IP地理位置
            import aiohttp
            url = f"http://ip-api.com/json/{ip_address}?fields=countryCode"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=GEOIP_TIMEOUT) as response:
                    if response.status == 200:
                        data = await response.json()
                        country_code = data.get('countryCode')
                        # 更新缓存并限制大小
                        if country_code:
                            if len(self.geoip_cache) >= GEOIP_CACHE_SIZE:
                                # 简单的LRU缓存移除策略
                                self.geoip_cache.pop(next(iter(self.geoip_cache)))
                            self.geoip_cache[ip_address] = country_code
                        return country_code
        except Exception as e:
            logging.warning(f"Failed to get country for IP {ip_address}: {e}")
            return None
    
    async def get_node_country(self, config_line: str) -> Optional[str]:
        """获取节点的国家信息"""
        info = self.extract_node_info(config_line)
        host = info.get('host')
        
        if not host:
            return None
        
        # 判断是否为IP地址
        try:
            # 尝试直接解析为IP地址
            socket.inet_aton(host)
            ip_address = host
        except socket.error:
            # 如果不是IP地址，则解析域名
            ip_address = await self.resolve_hostname(host)
            if not ip_address:
                return None
        
        # 查询IP所属国家
        country_code = await self.get_country_by_ip(ip_address)
        return country_code

# 导出单例供外部使用
tester = NodeTester()

# 简化的辅助函数
async def deduplicate_and_test_configs(configs: Set[str]) -> Set[str]:
    """辅助函数：去重并测试配置"""
    return await tester.process_configs(configs)

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