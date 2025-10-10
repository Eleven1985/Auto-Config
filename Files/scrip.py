import asyncio
import aiohttp
import json
import re
import logging
import os
import time
import base64
from urllib.parse import parse_qs, unquote
import asyncio
from logging.handlers import RotatingFileHandler
from bs4 import BeautifulSoup

# 配置参数 - 集中管理
URLS_FILE = 'Files/urls.txt'
OUTPUT_DIR = 'configs'
# 添加新的目录配置
SUMMARY_DIR = os.path.join(OUTPUT_DIR, 'summary')
PROTOCOLS_DIR = os.path.join(OUTPUT_DIR, 'protocols')
COUNTRIES_DIR = os.path.join(OUTPUT_DIR, 'countries')
REQUEST_TIMEOUT = 10  # 请求超时时间
CONCURRENT_REQUESTS = 15  # 并发请求数
MAX_CONFIG_LENGTH = 1500
MIN_PERCENT25_COUNT = 15
MAX_TEST_PER_CATEGORY = 200  # 每个分类测试的节点数
ENABLE_SAMPLING = True       # 启用采样测试
SAVE_WITHOUT_TESTING = False  # 是否直接保存不测试（最快但不保证有效性）

# 创建logs目录
if not os.path.exists('logs'):
    os.makedirs('logs')

# Configure logging with file rotation
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# 创建格式化器
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s')

# 控制台处理器
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# 文件处理器 (带滚动功能)
file_handler = RotatingFileHandler(
    'logs/scrip.log',
    maxBytes=5*1024*1024,  # 5MB
    backupCount=3,
    encoding='utf-8'
)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# 错误日志单独记录
error_handler = RotatingFileHandler(
    'logs/scrip_error.log',
    maxBytes=5*1024*1024,
    backupCount=3,
    encoding='utf-8'
)
error_handler.setLevel(logging.ERROR)
error_handler.setFormatter(formatter)
logger.addHandler(error_handler)

# 重命名logging为logger以便后续使用
logging = logger

# Define supported protocols
PROTOCOL_CATEGORIES = [
    "Vmess", "Vless", "Trojan", "ShadowSocks", "ShadowSocksR",
    "Tuic", "Hysteria2", "WireGuard"
]

# 直接在代码中定义国家关键词配置
COUNTRY_KEYWORDS = {
    "Argentina": ["Argentina", "AR"],
    "Australia": ["Australia", "AU"],
    "Austria": ["Austria", "AT"],
    "Belgium": ["Belgium", "BE"],
    "Brazil": ["Brazil", "BR"],
    "Bulgaria": ["Bulgaria", "BG"],
    "Canada": ["Canada", "CA"],
    "Croatia": ["Croatia", "HR"],
    "Czechia": ["Czechia", "CZ", "Czech"],
    "Denmark": ["Denmark", "DK"],
    "Finland": ["Finland", "FI"],
    "France": ["France", "FR"],
    "Germany": ["Germany", "DE", "German"],
    "Hungary": ["Hungary", "HU"],
    "India": ["India", "IN"],
    "Indonesia": ["Indonesia", "ID"],
    "Iran": ["Iran", "IR"],
    "Ireland": ["Ireland", "IE"],
    "Israel": ["Israel", "IL"],
    "Italy": ["Italy", "IT"],
    "Japan": ["Japan", "JP"],
    "Kazakhstan": ["Kazakhstan", "KZ"],
    "Lithuania": ["Lithuania", "LT"],
    "Luxembourg": ["Luxembourg", "LU"],
    "Malaysia": ["Malaysia", "MY"],
    "Moldova": ["Moldova", "MD"],
    "Montenegro": ["Montenegro", "ME"],
    "Netherlands": ["Netherlands", "NL", "Dutch"],
    "Norway": ["Norway", "NO"],
    "Paraguay": ["Paraguay", "PY"],
    "Poland": ["Poland", "PL"],
    "Portugal": ["Portugal", "PT"],
    "Romania": ["Romania", "RO"],
    "Russia": ["Russia", "RU"],
    "Samoa": ["Samoa", "WS"],
    "Singapore": ["Singapore", "SG"],
    "Slovenia": ["Slovenia", "SI"],
    "SouthKorea": ["South Korea", "KR", "Korea"],
    "Spain": ["Spain", "ES"],
    "Sweden": ["Sweden", "SE"],
    "Switzerland": ["Switzerland", "CH", "Swiss"],
    "Tajikistan": ["Tajikistan", "TJ"],
    "Thailand": ["Thailand", "TH"],
    "Turkey": ["Turkey", "TR"],
    "UAE": ["UAE", "United Arab Emirates", "AE"],
    "UK": ["UK", "United Kingdom", "GB"],
    "USA": ["USA", "United States", "US", "America"],
    "Vietnam": ["Vietnam", "VN"]
}

# 直接在代码中定义协议模式
PROTOCOL_PATTERNS = {
    "Vmess": [r"vmess://[A-Za-z0-9+/=]+"],
    "Vless": [r"vless://[A-Za-z0-9+/=?&.-]+"] ,
    "Trojan": [r"trojan://[A-Za-z0-9+/=?&.-]+"] ,
    "ShadowSocks": [r"ss://[A-Za-z0-9+/=?&.-]+"] ,
    "ShadowSocksR": [r"ssr://[A-Za-z0-9+/=?&.-]+"] ,
    "Tuic": [r"tuic://[A-Za-z0-9+/=?&.-]+"] ,
    "Hysteria2": [r"hysteria2://[A-Za-z0-9+/=?&.-]+"] ,
    "WireGuard": [r"wg://[A-Za-z0-9+/=?&.-]+"]
}

def decode_base64(data):
    """Safely decode base64 data"""
    try:
        data = data.replace('_', '/').replace('-', '+')
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        return base64.b64decode(data).decode('utf-8')
    except Exception:
        return None

def get_vmess_name(vmess_link):
    """Extract name from VMess link"""
    if not vmess_link.startswith("vmess://"):
        return None
    try:
        b64_part = vmess_link[8:]
        decoded_str = decode_base64(b64_part)
        if decoded_str:
            vmess_json = json.loads(decoded_str)
            return vmess_json.get('ps')
    except Exception as e:
        logging.warning(f"Failed to parse Vmess name from {vmess_link[:30]}...: {e}")
    return None

def get_ssr_name(ssr_link):
    """Extract name from SSR link"""
    if not ssr_link.startswith("ssr://"):
        return None
    try:
        b64_part = ssr_link[6:]
        decoded_str = decode_base64(b64_part)
        if not decoded_str:
            return None
        parts = decoded_str.split('/?')
        if len(parts) < 2:
            return None
        params_str = parts[1]
        params = parse_qs(params_str)
        if 'remarks' in params and params['remarks']:
            remarks_b64 = params['remarks'][0]
            return decode_base64(remarks_b64)
    except Exception as e:
        logging.warning(f"Failed to parse SSR name from {ssr_link[:30]}...: {e}")
    return None

def should_filter_config(config):
    """Filter out invalid or suspicious configs"""
    if 'i_love_' in config.lower():
        return True
    percent25_count = config.count('%25')
    if percent25_count >= MIN_PERCENT25_COUNT:
        return True
    if len(config) >= MAX_CONFIG_LENGTH:
        return True
    if '%2525' in config:
        return True
    return False

def is_config_format_valid(config_line):
    """简单验证配置格式是否有效，不进行网络测试"""
    # 检查基本格式是否正确
    url_part = config_line.split('#')[0].strip()
    
    # 检查是否以支持的协议开头
    supported_protocols = ['vmess://', 'vless://', 'ss://', 'ssr://', 'trojan://', 'tuic://', 'hysteria2://']
    if not any(url_part.startswith(proto) for proto in supported_protocols):
        return False
        
    # 检查长度是否合理
    if len(url_part) < 20 or len(url_part) > MAX_CONFIG_LENGTH:
        return False
        
    return True

async def fetch_url(session, url):
    """Fetch content from URL asynchronously"""
    try:
        async with session.get(url, timeout=REQUEST_TIMEOUT) as response:
            response.raise_for_status()
            html = await response.text()
            soup = BeautifulSoup(html, 'html.parser')
            text_content = ""
            # Extract text from important elements
            for element in soup.find_all(['pre', 'code', 'p', 'div', 'li', 'span', 'td']):
                text_content += element.get_text(separator='\n', strip=True) + "\n"
            # Fallback to full text if no elements found
            if not text_content:
                text_content = soup.get_text(separator=' ', strip=True)
            logging.info(f"Successfully fetched: {url}")
            return url, text_content
    except Exception as e:
        logging.warning(f"Failed to fetch or process {url}: {e}")
        return url, None

def find_matches(text, categories_data):
    """Find protocol matches in text content"""
    matches = {category: set() for category in categories_data}
    for category, patterns in categories_data.items():
        for pattern_str in patterns:
            if not isinstance(pattern_str, str):
                continue
            try:
                is_protocol_pattern = any(proto_prefix in pattern_str 
                                         for proto_prefix in [p.lower() + "://" for p in PROTOCOL_CATEGORIES])
                if category in PROTOCOL_CATEGORIES or is_protocol_pattern:
                    pattern = re.compile(pattern_str, re.IGNORECASE | re.MULTILINE)
                    found = pattern.findall(text)
                    if found:
                        cleaned_found = {item.strip() for item in found if item.strip()}
                        matches[category].update(cleaned_found)
            except re.error as e:
                logging.error(f"Regex error for '{pattern_str}' in category '{category}': {e}")
    return {k: v for k, v in matches.items() if v}

def save_to_file(directory, category_name, items_set):
    """Save items to file"""
    if not items_set:
        return False, 0
    # 确保目录存在
    os.makedirs(directory, exist_ok=True)
    file_path = os.path.join(directory, f"{category_name}.txt")
    count = len(items_set)
    try:
        # 对于所有文件都不排序，直接写入，大幅提升性能
        with open(file_path, 'w', encoding='utf-8') as f:
            for item in items_set:
                f.write(f"{item}\n")
        logging.info(f"Saved {count} items to {file_path}")
        return True, count
    except Exception as e:
        logging.error(f"Failed to write file {file_path}: {e}")
        return False, 0

# 国家代码到国家名称的映射
COUNTRY_CODE_MAPPING = {
    'US': 'USA',
    'UK': 'UK',
    'CN': 'China',
    'JP': 'Japan',
    'SG': 'Singapore',
    'KR': 'SouthKorea',
    'DE': 'Germany',
    'FR': 'France',
    'RU': 'Russia',
    'AU': 'Australia',
    'CA': 'Canada',
    'IN': 'India',
    'ID': 'Indonesia',
    'TH': 'Thailand',
    'VN': 'Vietnam',
    'MY': 'Malaysia',
    'BR': 'Brazil',
    'IT': 'Italy',
    'ES': 'Spain',
    'NL': 'Netherlands',
    'SE': 'Sweden',
    'CH': 'Switzerland',
    'AT': 'Austria',
    'BE': 'Belgium',
    'PL': 'Poland',
    'RO': 'Romania',
    'CZ': 'Czechia',
    'HU': 'Hungary',
    'FI': 'Finland',
    'NO': 'Norway',
    'PT': 'Portugal',
    'IE': 'Ireland',
    'IL': 'Israel',
    'TR': 'Turkey',
    'AE': 'UAE',
    'IR': 'Iran',
    'AR': 'Argentina',
    'BG': 'Bulgaria',
    'HR': 'Croatia',
    'DK': 'Denmark',
    'KZ': 'Kazakhstan',
    'LT': 'Lithuania',
    'LU': 'Luxembourg',
    'MD': 'Moldova',
    'ME': 'Montenegro',
    'PY': 'Paraguay',
    'RS': 'Russia',
    'SM': 'Samoa',
    'SI': 'Slovenia',
    'TJ': 'Tajikistan'
    # 可以根据需要添加更多国家代码映射
}

async def process_category(category, items, is_country=False, output_dir=OUTPUT_DIR):
    """处理单个分类的配置，合并重复逻辑"""
    category_type = "country" if is_country else "category"
    logging.info(f"Processing {category_type} {category}")
    
    if SAVE_WITHOUT_TESTING:
        return save_to_file(output_dir, category, items)
        
    # 导入节点测试器（在函数内部导入以避免循环依赖）
    from node_tester import deduplicate_and_test_configs, tester
    
    # 采样测试 - 如果节点数量过多
    if ENABLE_SAMPLING and len(items) > MAX_TEST_PER_CATEGORY:
        # 随机采样部分节点进行测试
        import random
        sampled_items = set(random.sample(list(items), MAX_TEST_PER_CATEGORY))
        logging.info(f"Sampling {len(sampled_items)} nodes out of {len(items)} for testing")
        valid_configs = await deduplicate_and_test_configs(sampled_items)
        # 合并未测试但有效的节点（基于协议格式验证）
        valid_configs.update([item for item in items if item not in sampled_items and is_config_format_valid(item)])
    else:
        valid_configs = await deduplicate_and_test_configs(items)
        
    return save_to_file(output_dir, category, valid_configs)

async def main():
    """Main entry point"""
    start_time = time.time()
    
    # Check input files existence
    if not os.path.exists(URLS_FILE):
        logging.critical("URLs file not found.")
        return

    # Load input data
    with open(URLS_FILE, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip()]
    
    # 使用直接定义在代码中的配置
    protocol_patterns = PROTOCOL_PATTERNS
    country_keywords = COUNTRY_KEYWORDS
    country_names = list(country_keywords.keys())

    logging.info(f"Loaded {len(urls)} URLs.")

    # Fetch URLs concurrently with rate limiting
    sem = asyncio.Semaphore(CONCURRENT_REQUESTS)
    async def fetch_with_sem(session, url):
        async with sem:
            return await fetch_url(session, url)
    
    async with aiohttp.ClientSession() as session:
        fetched_pages = await asyncio.gather(*[fetch_with_sem(session, u) for u in urls])

    # Initialize result structures
    final_configs_by_country = {cat: set() for cat in country_names}
    final_all_protocols = {cat: set() for cat in PROTOCOL_CATEGORIES}
    all_valid_configs = set()  # 汇总所有有效节点
    configs_with_country_info = []  # 存储带国家信息的节点，确保这里正确定义

    logging.info("Processing pages for config name association...")
    for url, text in fetched_pages:
        if not text:
            continue

        # Find protocol matches and filter invalid configs
        page_protocol_matches = find_matches(text, protocol_patterns)
        all_page_configs = set()
        for protocol_cat, configs_found in page_protocol_matches.items():
            if protocol_cat in PROTOCOL_CATEGORIES:
                for config in configs_found:
                    if should_filter_config(config):
                        continue
                    all_page_configs.add(config)
                    final_all_protocols[protocol_cat].add(config)
                    all_valid_configs.add(config)  # 添加到总汇总
        
        # 保存所有配置用于后续的IP国家分类
        configs_with_country_info.extend(all_page_configs)

    # 移除旧的基于名称的国家分类逻辑，使用IP地址进行国家分类
    if configs_with_country_info:
        logging.info("Classifying nodes by IP geolocation...")
        from node_tester import tester
        
        # 创建并发任务来获取每个节点的国家信息
        sem = asyncio.Semaphore(50)  # 限制并发IP查询数量
        
        async def get_country_with_sem(config):
            async with sem:
                country_code = await tester.get_node_country(config)
                if country_code and country_code in COUNTRY_CODE_MAPPING:
                    country_name = COUNTRY_CODE_MAPPING[country_code]
                    # 如果国家名称在我们的列表中，则添加到相应的集合
                    if country_name in final_configs_by_country:
                        final_configs_by_country[country_name].add(config)
                        return country_name
                return None
        
        # 并发获取所有节点的国家信息
        tasks = [get_country_with_sem(config) for config in configs_with_country_info]
        await asyncio.gather(*tasks)
        
        # 统计分类结果
        classified_count = sum(len(configs) for configs in final_configs_by_country.values())
        logging.info(f"Classified {classified_count} nodes by IP geolocation")

    # Prepare output directories
    directories = [OUTPUT_DIR, SUMMARY_DIR, PROTOCOLS_DIR, COUNTRIES_DIR]
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        # Clear existing files in directory
        for filename in os.listdir(directory):
            file_path = os.path.join(directory, filename)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
            except Exception as e:
                logging.error(f"Failed to delete {file_path}: {e}")
    
    # 保存总汇总节点
    logging.info(f"Preparing to save summary to directory: {SUMMARY_DIR}")
    if all_valid_configs:
        # 如果启用了测试，先测试汇总节点
        if not SAVE_WITHOUT_TESTING:
            from node_tester import deduplicate_and_test_configs
            valid_summary_configs = await deduplicate_and_test_configs(all_valid_configs)
            save_to_file(SUMMARY_DIR, "all_nodes", valid_summary_configs)
        else:
            save_to_file(SUMMARY_DIR, "all_nodes", all_valid_configs)
    
    logging.info(f"Preparing to save protocols to directory: {PROTOCOLS_DIR}")
    # 保存协议分类到protocols文件夹
    for category, items in final_all_protocols.items():
        if items:
            await process_category(category, items, output_dir=PROTOCOLS_DIR)
    
    logging.info(f"Preparing to save countries to directory: {COUNTRIES_DIR}")
    # 保存国家分类到countries文件夹
    for category, items in final_configs_by_country.items():
        if items:
            await process_category(category, items, is_country=True, output_dir=COUNTRIES_DIR)
    
    logging.info(f"--- Script Finished in {time.time() - start_time:.2f} seconds ---")

if __name__ == "__main__":
    asyncio.run(main())
