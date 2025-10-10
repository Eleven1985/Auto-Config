import asyncio
import time
import logging
import aiohttp
import os
import shutil
import re  # 添加缺失的re模块导入
import base64
import json

# 配置参数
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.join(base_dir, 'configs')
SUMMARY_DIR = os.path.join(OUTPUT_DIR, 'summary')
PROTOCOLS_DIR = os.path.join(OUTPUT_DIR, 'protocols')
COUNTRIES_DIR = os.path.join(OUTPUT_DIR, 'countries')
URLS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'urls.txt')

# IP测试API配置
IP_TEST_API = 'https://api.vore.top/api/IPdata'
IP_TEST_CONCURRENCY = 5  # IP测试的并发数
IP_TEST_TIMEOUT = 5      # IP测试的超时时间
USE_IP_TEST = True       # 是否使用IP测试功能

# 确保日志目录存在
os.makedirs(os.path.join(base_dir, 'logs'), exist_ok=True)

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(base_dir, 'logs/scrip.log')),
        logging.StreamHandler()
    ]
)

# 改进的协议模式配置 - 支持更多协议格式
PROTOCOL_PATTERNS = {
    'vmess': re.compile(r'vmess://[^\s,]+'),
    'vless': re.compile(r'vless://[^\s,]+'),
    'trojan': re.compile(r'trojan://[^\s,]+'),
    'shadowsocks': re.compile(r'ss://[^\s,]+'),
    'hysteria2': re.compile(r'hy2://[^\s,]+'),
    # 添加更多常见协议格式
    'ssr': re.compile(r'ssr://[^\s,]+'),  # ShadowsocksR
    'hysteria': re.compile(r'hysteria://[^\s,]+'),  # Hysteria 1.x
    'tuic': re.compile(r'tuic://[^\s,]+'),  # TUIC 协议
    'wireguard': re.compile(r'wireguard://[^\s,]+'),  # WireGuard
    'naiveproxy': re.compile(r'naive://[^\s,]+'),  # NaiveProxy
    'socks5': re.compile(r'socks5://[^\s,]+'),  # SOCKS5
    'http': re.compile(r'http://[^\s,]+')  # HTTP 代理
}

# 协议分类映射
PROTOCOL_CATEGORIES = {
    'vmess': 'Vmess',
    'vless': 'Vless',
    'trojan': 'Trojan',
    'shadowsocks': 'ShadowSocks',
    'hysteria2': 'Hysteria2',
    # 为新添加的协议添加映射
    'ssr': 'ShadowSocksR',
    'hysteria': 'Hysteria',
    'tuic': 'TUIC',
    'wireguard': 'WireGuard',
    'naiveproxy': 'NaiveProxy',
    'socks5': 'SOCKS5',
    'http': 'HTTP'
}

# 国家关键词配置
COUNTRY_KEYWORDS = {
    'United States': ['us', 'usa', 'america', 'united states'],
    'China': ['cn', 'china', 'beijing', 'shanghai'],
    'Japan': ['jp', 'japan', 'tokyo', 'osaka'],
    'Singapore': ['sg', 'singapore'],
    'Hong Kong': ['hk', 'hong kong'],
    'South Korea': ['kr', 'korea', 'south korea', 'seoul'],
    'Germany': ['de', 'germany'],
    'United Kingdom': ['uk', 'britain', 'united kingdom'],
    'France': ['fr', 'france'],
    'Canada': ['ca', 'canada'],
    'Australia': ['au', 'australia'],
    'Russia': ['ru', 'russia'],
    'Netherlands': ['nl', 'netherlands'],
    'Switzerland': ['ch', 'switzerland'],
    'Italy': ['it', 'italy']
}

# 国家代码映射表
COUNTRY_CODE_MAPPING = {
    'US': ('United States', '美国'),
    'CN': ('China', '中国'),
    'JP': ('Japan', '日本'),
    'SG': ('Singapore', '新加坡'),
    'HK': ('Hong Kong', '香港'),
    'KR': ('South Korea', '韩国'),
    'DE': ('Germany', '德国'),
    'GB': ('United Kingdom', '英国'),
    'FR': ('France', '法国'),
    'CA': ('Canada', '加拿大'),
    'AU': ('Australia', '澳大利亚'),
    'RU': ('Russia', '俄罗斯'),
    'NL': ('Netherlands', '荷兰'),
    'CH': ('Switzerland', '瑞士'),
    'IT': ('Italy', '意大利')
}

# 请求设置
CONCURRENT_REQUESTS = 10
TIMEOUT = 30

async def fetch_url(session, url, timeout=TIMEOUT):
    """异步获取URL内容"""
    try:
        async with session.get(url, timeout=timeout) as response:
            response.raise_for_status()
            text = await response.text()
            logging.info(f"Successfully fetched {url}")
            return url, text
    except Exception as e:
        logging.error(f"Failed to fetch {url}: {e}")
        return url, ""

async def test_ip_location(session, ip, timeout=IP_TEST_TIMEOUT):
    """异步测试IP地址的地理位置"""
    try:
        url = f"{IP_TEST_API}?ip={ip}"
        async with session.get(url, timeout=timeout) as response:
            if response.status == 200:
                data = await response.json()
                # 解析返回的JSON数据
                if isinstance(data, dict) and 'code' in data and data['code'] == 200 and 'data' in data:
                    country_code = data['data'].get('country_code', '')
                    return ip, country_code
        return ip, None
    except Exception as e:
        logging.error(f"Failed to test IP {ip}: {e}")
        return ip, None

def extract_ip_from_config(config):
    """从配置中提取IP地址"""
    try:
        # 处理不同协议的配置格式
        if config.startswith('vmess://'):
            # 解码vmess配置
            encoded = config[8:]
            # 确保base64解码正确处理
            missing_padding = len(encoded) % 4
            if missing_padding:
                encoded += '=' * (4 - missing_padding)
            decoded = base64.urlsafe_b64decode(encoded).decode('utf-8')
            vmess_data = json.loads(decoded)
            return vmess_data.get('add', '')
        elif config.startswith('vless://'):
            # 解析vless配置
            match = re.search(r'@([^:]+):', config)
            if match:
                return match.group(1)
        elif config.startswith('trojan://') or config.startswith('ss://'):
            # 解析trojan和ss配置
            match = re.search(r'@([^:]+):', config)
            if match:
                return match.group(1)
        elif config.startswith('ssr://'):
            # 解析ssr配置
            encoded = config[6:]
            missing_padding = len(encoded) % 4
            if missing_padding:
                encoded += '=' * (4 - missing_padding)
            decoded = base64.urlsafe_b64decode(encoded).decode('utf-8')
            match = re.search(r'([^:]+):', decoded)
            if match:
                return match.group(1)
        # 通用IP提取
        ip_pattern = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
        match = ip_pattern.search(config)
        if match:
            return match.group(0)
        return None
    except Exception as e:
        logging.error(f"Error extracting IP from config: {e}")
        return None

def find_matches(text, patterns):
    """在文本中查找匹配的协议配置"""
    matches = {}  # 确保即使没有匹配项也返回空字典
    
    for protocol, pattern in patterns.items():
        try:
            found = pattern.findall(text)
            if found:
                matches[protocol] = found
                logging.info(f"Found {len(found)} {protocol} configurations")
        except Exception as e:
            logging.error(f"Error matching {protocol} patterns: {e}")
    
    return matches

def save_to_file(directory, filename, items):
    """保存配置项到文件"""
    try:
        # 确保目录存在
        os.makedirs(directory, exist_ok=True)
        
        file_path = os.path.join(directory, f"{filename}.txt")
        file_content = []
        
        # 添加文件头信息
        file_content.append(f"# {filename} - {len(items)} items")
        file_content.append(f"# Generated at {time.strftime('%Y-%m-%d %H:%M:%S')}")
        file_content.append("")
        
        # 添加配置项
        file_content.extend(items)
        
        # 写入文件
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(file_content))
        
        logging.info(f"Successfully saved {len(items)} items to {file_path}")
        return True
    except Exception as e:
        logging.error(f"Failed to save items to {os.path.join(directory, filename)}.txt: {e}")
        return False

# 添加一个函数来复制文件，减少代码重复
def copy_file(source_dir, target_dir, filename):
    """复制文件从源目录到目标目录"""
    source_path = os.path.join(source_dir, f"{filename}.txt")
    target_path = os.path.join(target_dir, f"{filename}.txt")
    if os.path.exists(source_path):
        try:
            shutil.copy2(source_path, target_path)
            logging.info(f"Copied {filename} file to {target_dir}")
            return True
        except Exception as e:
            logging.error(f"Failed to copy {filename} file: {e}")
    return False

def remove_duplicate_configs(configs):
    """去除重复的节点配置"""
    original_count = len(configs)
    unique_configs = set(configs)
    removed_count = original_count - len(unique_configs)
    
    if removed_count > 0:
        logging.info(f"Removed {removed_count} duplicate configs")
    
    return unique_configs

def classify_by_country(config, country_keywords, country_code_mapping, ip_country_map=None):
    """根据关键词或IP测试结果对配置进行国家分类"""
    # 优先使用IP测试结果
    if ip_country_map:
        ip = extract_ip_from_config(config)
        if ip and ip in ip_country_map:
            country_code = ip_country_map[ip]
            if country_code in country_code_mapping:
                country_name, country_name_zh = country_code_mapping[country_code]
                config_with_country = f"# {country_name_zh}\n{config}"
                return country_name, config_with_country
                
    # 尝试从配置中提取节点名称
    name_part = config.split('#')
    node_name = name_part[1].strip() if len(name_part) > 1 else ""
    
    # 检查节点名称是否包含国家关键词
    matched_country = None
    for country, keywords in country_keywords.items():
        for keyword in keywords:
            if keyword.lower() in node_name.lower() or keyword.lower() in config.lower():
                matched_country = country
                break
        if matched_country:
            break
    
    if matched_country:
        # 获取中文国家名
        country_name_zh = None
        for code, (en_name, zh_name) in country_code_mapping.items():
            if en_name == matched_country:
                country_name_zh = zh_name
                break
        
        # 将中文国家名添加到配置中
        config_with_country = f"# {country_name_zh}\n{config}" if country_name_zh else config
        return matched_country, config_with_country
    
    return None, config

async def main():
    """Main entry point"""
    start_time = time.time()
    
    try:
        # 检查输入文件是否存在
        if not os.path.exists(URLS_FILE):
            logging.critical("URLs file not found.")
            return

        # 加载输入数据
        with open(URLS_FILE, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
        
        logging.info(f"Loaded {len(urls)} URLs.")

        # 并发获取URL内容
        sem = asyncio.Semaphore(CONCURRENT_REQUESTS)
        async def fetch_with_sem(session, url):
            async with sem:
                return await fetch_url(session, url)
        
        async with aiohttp.ClientSession() as session:
            fetched_pages = await asyncio.gather(*[fetch_with_sem(session, u) for u in urls])

        # 初始化结果结构
        country_names = [info[0] for info in COUNTRY_CODE_MAPPING.values()]
        final_configs_by_country = {cat: set() for cat in country_names}
        final_all_protocols = {cat: set() for cat in PROTOCOL_CATEGORIES.values()}
        all_configs = []  # 先收集所有配置，之后再进行去重

        logging.info("Processing pages for configs...")
        for url, text in fetched_pages:
            if not text:
                continue

            # 查找协议匹配
            page_protocol_matches = find_matches(text, PROTOCOL_PATTERNS)
            for protocol_cat, configs_found in page_protocol_matches.items():
                if protocol_cat in PROTOCOL_CATEGORIES:
                    all_configs.extend(configs_found)

        # 去除重复节点
        logging.info("Removing duplicate configs...")
        unique_configs = remove_duplicate_configs(all_configs)
        logging.info(f"Unique configs count: {len(unique_configs)}")
        all_valid_configs = unique_configs  # 直接使用去重后的配置
        logging.info(f"Total configs after deduplication: {len(all_valid_configs)}")

        # 按协议分类
        logging.info("Classifying configs by protocol...")
        for config in all_valid_configs:
            matched = False
            for protocol in PROTOCOL_PATTERNS.keys():
                if config.startswith(f"{protocol}://"):
                    if protocol in PROTOCOL_CATEGORIES:
                        category = PROTOCOL_CATEGORIES[protocol]
                        final_all_protocols[category].add(config)
                        matched = True
                    break
            
            # 记录未匹配的协议格式，用于调试
            if not matched:
                # 只记录前50个字符以避免日志过长
                logging.debug(f"Unmatched protocol format: {config[:50]}...")
        
        # 记录各协议分类的配置数量
        for category, items in final_all_protocols.items():
            logging.info(f"{category}: {len(items)} items")

        # 创建IP国家映射
        ip_country_map = {}
        if USE_IP_TEST and all_valid_configs:
            logging.info("Testing IP locations...")
            # 提取所有IP地址
            ip_list = []
            config_to_ip = {}
            
            for config in all_valid_configs:
                ip = extract_ip_from_config(config)
                if ip and ip not in ip_list:
                    ip_list.append(ip)
                    config_to_ip[ip] = config
            
            logging.info(f"Extracted {len(ip_list)} unique IPs for testing")
            
            # 并发测试IP
            ip_sem = asyncio.Semaphore(IP_TEST_CONCURRENCY)
            async def test_ip_with_sem(session, ip):
                async with ip_sem:
                    return await test_ip_location(session, ip)
            
            async with aiohttp.ClientSession() as session:
                ip_test_results = await asyncio.gather(*[test_ip_with_sem(session, ip) for ip in ip_list])
            
            # 构建IP到国家的映射
            for ip, country_code in ip_test_results:
                if country_code:
                    ip_country_map[ip] = country_code
            
            logging.info(f"Successfully tested {len(ip_country_map)} IP locations")

        # 使用基于IP测试或名称关键词的国家分类方法
        logging.info("Classifying nodes by IP test results and name keywords")
        for config in all_valid_configs:
            country, config_with_country = classify_by_country(config, COUNTRY_KEYWORDS, COUNTRY_CODE_MAPPING, ip_country_map)
            if country and country in final_configs_by_country:
                final_configs_by_country[country].add(config_with_country)

        # 准备输出目录
        directories = [OUTPUT_DIR, SUMMARY_DIR, PROTOCOLS_DIR, COUNTRIES_DIR]
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
            # 清理目录中的现有文件
            try:
                for filename in os.listdir(directory):
                    file_path = os.path.join(directory, filename)
                    if os.path.isfile(file_path):
                        os.unlink(file_path)
            except Exception as e:
                logging.error(f"Failed to clean directory {directory}: {e}")
        
        # 保存配置到相应目录
        # 保存汇总节点到 summary 目录
        if all_valid_configs:
            save_to_file(SUMMARY_DIR, "all_nodes", all_valid_configs)
        
        # 保存协议分类到 protocols 目录
        for category, items in final_all_protocols.items():
            if items:
                save_to_file(PROTOCOLS_DIR, category, items)
        
        # 保存国家分类到 countries 目录
        country_files_count = 0
        for category, items in final_configs_by_country.items():
            if items:
                save_to_file(COUNTRIES_DIR, category, items)
                country_files_count += 1
        
        # 同时创建根目录的快捷方式或引用
        # 复制汇总文件到根目录
        if all_valid_configs:
            copy_file(SUMMARY_DIR, OUTPUT_DIR, "all_nodes")
        
        # 复制协议分类文件到根目录
        for category in PROTOCOL_CATEGORIES.values():
            copy_file(PROTOCOLS_DIR, OUTPUT_DIR, category)
        
        # 复制国家分类文件到根目录
        for country in final_configs_by_country:
            copy_file(COUNTRIES_DIR, OUTPUT_DIR, country)
        
        # 统计生成的国家文件数量
        logging.info(f"Generated {country_files_count} country files")
        
        # 检查是否有生成的国家文件
        if country_files_count == 0:
            logging.warning("没有生成任何国家文件！请检查分类逻辑是否正常工作。")
            logging.info(f"Total configs: {len(all_valid_configs)}")
            if all_valid_configs:
                # 输出一些配置样例用于调试
                sample_config = next(iter(all_valid_configs))
                logging.info(f"Sample config: {sample_config[:100]}...")

        logging.info(f"--- Script Finished in {time.time() - start_time:.2f} seconds ---")
    except Exception as e:
        logging.error(f"An error occurred during script execution: {e}")
        import traceback
        logging.error(traceback.format_exc())

if __name__ == "__main__":
    asyncio.run(main())
