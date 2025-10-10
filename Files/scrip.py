import asyncio
import aiohttp
import json
import re
import logging
import os
import time
import base64
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
# 将SAVE_WITHOUT_TESTING从False改为True以取消测试
SAVE_WITHOUT_TESTING = True  # 是否直接保存不测试（最快但不保证有效性）

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
    "Vmess": [r"vmess://[A-Za-z0-9+/=]+"] ,
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

# 保留过滤和验证函数

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

# 修复 find_matches 函数定义

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

# 国家代码到国家名称的映射（英文和中文）
COUNTRY_CODE_MAPPING = {
    'US': ('USA', '美国'),
    'UK': ('UK', '英国'),
    'CN': ('China', '中国'),
    'JP': ('Japan', '日本'),
    'SG': ('Singapore', '新加坡'),
    'KR': ('SouthKorea', '韩国'),
    'DE': ('Germany', '德国'),
    'FR': ('France', '法国'),
    'RU': ('Russia', '俄罗斯'),
    'AU': ('Australia', '澳大利亚'),
    'CA': ('Canada', '加拿大'),
    'IN': ('India', '印度'),
    'ID': ('Indonesia', '印度尼西亚'),
    'TH': ('Thailand', '泰国'),
    'VN': ('Vietnam', '越南'),
    'MY': ('Malaysia', '马来西亚'),
    'BR': ('Brazil', '巴西'),
    'IT': ('Italy', '意大利'),
    'ES': ('Spain', '西班牙'),
    'NL': ('Netherlands', '荷兰'),
    'SE': ('Sweden', '瑞典'),
    'CH': ('Switzerland', '瑞士'),
    'AT': ('Austria', '奥地利'),
    'BE': ('Belgium', '比利时'),
    'PL': ('Poland', '波兰'),
    'RO': ('Romania', '罗马尼亚'),
    'CZ': ('Czechia', '捷克'),
    'HU': ('Hungary', '匈牙利'),
    'FI': ('Finland', '芬兰'),
    'NO': ('Norway', '挪威'),
    'PT': ('Portugal', '葡萄牙'),
    'IE': ('Ireland', '爱尔兰'),
    'IL': ('Israel', '以色列'),
    'TR': ('Turkey', '土耳其'),
    'AE': ('UAE', '阿联酋'),
    'IR': ('Iran', '伊朗'),
    'AR': ('Argentina', '阿根廷'),
    'BG': ('Bulgaria', '保加利亚'),
    'HR': ('Croatia', '克罗地亚'),
    'DK': ('Denmark', '丹麦'),
    'KZ': ('Kazakhstan', '哈萨克斯坦'),
    'LT': ('Lithuania', '立陶宛'),
    'LU': ('Luxembourg', '卢森堡'),
    'MD': ('Moldova', '摩尔多瓦'),
    'ME': ('Montenegro', '黑山'),
    'PY': ('Paraguay', '巴拉圭'),
    'RS': ('Russia', '俄罗斯'),
    'SM': ('Samoa', '萨摩亚'),
    'SI': ('Slovenia', '斯洛文尼亚'),
    'TJ': ('Tajikistan', '塔吉克斯坦')
}

# 添加save_to_file函数定义
# 将C++风格注释 // 改为Python风格注释 #
def save_to_file(directory, filename, items):
    """保存配置项到文件，确保目录存在"""
    try:
        # 确保目录存在
        os.makedirs(directory, exist_ok=True)
        
        # 构建完整的文件路径
        file_path = os.path.join(directory, f"{filename}.txt")
        
        # 获取文件名对应的中文国家名
        country_name_zh = None
        for code, (en_name, zh_name) in COUNTRY_CODE_MAPPING.items():
            if en_name == filename:
                country_name_zh = zh_name
                break
        
        # 准备文件内容
        file_content = []
        # 如果是国家分类文件，添加中文国家名注释
        if country_name_zh:
            file_content.append(f"# {country_name_zh}")
        
        # 添加节点数量统计
        file_content.append(f"# 节点数量: {len(items)}")
        file_content.append(f"# 更新时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        file_content.append("")  # 添加空行
        
        # 添加所有配置项
        file_content.extend(items)
        
        # 写入文件
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(file_content))
        
        logging.info(f"Successfully saved {len(items)} items to {file_path}")
        return True
    except Exception as e:
        logging.error(f"Failed to save items to {os.path.join(directory, filename)}.txt: {e}")
        return False

# 修复process_category函数，移除提前返回语句
async def process_category(category, items, is_country=False, output_dir=OUTPUT_DIR):
    """处理单个分类的配置，合并重复逻辑"""
    category_type = "country" if is_country else "category"
    logging.info(f"Processing {category_type} {category}")
    
    # 由于 SAVE_WITHOUT_TESTING=True，直接保存所有配置
    result = save_to_file(output_dir, category, items)
    
    # 以下代码被注释掉，因为SAVE_WITHOUT_TESTING=True
    # 导入节点测试器（在函数内部导入以避免循环依赖）
    # from node_tester import deduplicate_and_test_configs
    # 
    # 采样测试 - 如果节点数量过多
    # if ENABLE_SAMPLING and len(items) > MAX_TEST_PER_CATEGORY:
    #     # 随机采样部分节点进行测试
    #     import random
    #     sampled_items = set(random.sample(list(items), MAX_TEST_PER_CATEGORY))
    #     logging.info(f"Sampling {len(sampled_items)} nodes out of {len(items)} for testing")
    #     valid_configs = await deduplicate_and_test_configs(sampled_items)
    #     # 合并未测试但有效的节点（基于协议格式验证）
    #     valid_configs.update([item for item in items if item not in sampled_items and is_config_format_valid(item)])
    # else:
    #     valid_configs = await deduplicate_and_test_configs(items)
    # 
    # return save_to_file(output_dir, category, valid_configs)
    
    return result

# 修复main函数中的保存逻辑，确保正确缩进和调用顺序
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

    # 使用IP地址进行国家分类
    if configs_with_country_info:
        logging.info("Classifying nodes by IP geolocation...")
        from node_tester import tester
        
        # 创建并发任务来获取每个节点的国家信息
        sem = asyncio.Semaphore(50)  # 限制并发IP查询数量
        
        async def get_country_with_sem(config):
            async with sem:
                try:
                    country_code = await tester.get_node_country(config)
                    if country_code and country_code in COUNTRY_CODE_MAPPING:
                        country_info = COUNTRY_CODE_MAPPING[country_code]
                        country_name_en = country_info[0]  # 英文名称，用于文件名
                        country_name_zh = country_info[1]  # 中文名称，用于文件内容
                        
                        # 如果国家名称在我们的列表中，则添加到相应的集合
                        if country_name_en in final_configs_by_country:
                            # 将中文国家名添加到配置中
                            config_with_country = f"# {country_name_zh}\n{config}"
                            final_configs_by_country[country_name_en].add(config_with_country)
                            return country_name_en
                except Exception as e:
                    logging.warning(f"Error getting country for config: {e}")
                return None
        
        # 并发获取所有节点的国家信息
        tasks = [get_country_with_sem(config) for config in configs_with_country_info]
        await asyncio.gather(*tasks)
        
        # 统计分类结果
        classified_count = sum(len(configs) for configs in final_configs_by_country.values())
        logging.info(f"Classified {classified_count} nodes by IP geolocation")

    # 如果IP分类失败，回退到基于名称的分类方法
    fallback_classified = False
    if sum(len(configs) for configs in final_configs_by_country.values()) == 0:
        logging.info("No nodes classified by IP geolocation, falling back to name-based classification")
        # 使用节点名称进行国家分类
        for config in all_valid_configs:
            # 尝试从配置中提取节点名称
            name_part = config.split('#')
            node_name = name_part[1].strip() if len(name_part) > 1 else ""
            
            # 检查节点名称是否包含国家关键词
            matched_country = None
            for country, keywords in COUNTRY_KEYWORDS.items():
                for keyword in keywords:
                    if keyword.lower() in node_name.lower():
                        matched_country = country
                        break
                if matched_country:
                    break
            
            if matched_country and matched_country in final_configs_by_country:
                # 获取中文国家名
                country_name_zh = None
                # 查找对应的中文国家名
                for code, (en_name, zh_name) in COUNTRY_CODE_MAPPING.items():
                    if en_name == matched_country:
                        country_name_zh = zh_name
                        break
                
                # 将中文国家名添加到配置中
                config_with_country = f"# {country_name_zh}\n{config}" if country_name_zh else config
                final_configs_by_country[matched_country].add(config_with_country)
                fallback_classified = True
        
        if fallback_classified:
            classified_count = sum(len(configs) for configs in final_configs_by_country.values())
            logging.info(f"Classified {classified_count} nodes by name-based fallback")
    else:
        # 如果通过IP分类到了一些节点，为剩余节点尝试基于名称的分类
        remaining_configs = set()
        for config in all_valid_configs:
            found = False
            for country_configs in final_configs_by_country.values():
                for country_config in country_configs:
                    if config in country_config or country_config.endswith(config):
                        found = True
                        break
                    if found:
                        break
                if not found:
                    remaining_configs.add(config)
            
        if remaining_configs:
            logging.info(f"Classifying {len(remaining_configs)} remaining nodes by name")
            for config in remaining_configs:
                name_part = config.split('#')
                node_name = name_part[1].strip() if len(name_part) > 1 else ""
                
                matched_country = None
                for country, keywords in COUNTRY_KEYWORDS.items():
                    for keyword in keywords:
                        if keyword.lower() in node_name.lower():
                            matched_country = country
                            break
                    if matched_country:
                        break
                
                if matched_country and matched_country in final_configs_by_country:
                    country_name_zh = None
                    for code, (en_name, zh_name) in COUNTRY_CODE_MAPPING.items():
                        if en_name == matched_country:
                            country_name_zh = zh_name
                            break
                        config_with_country = f"# {country_name_zh}\n{config}" if country_name_zh else config
                        final_configs_by_country[matched_country].add(config_with_country)
                        fallback_classified = True

    # 准备输出目录
    directories = [OUTPUT_DIR, SUMMARY_DIR, PROTOCOLS_DIR, COUNTRIES_DIR]
    for directory in directories:
        # 确保目录存在
        os.makedirs(directory, exist_ok=True)
        # 清理目录中的现有文件
        for filename in os.listdir(directory):
            file_path = os.path.join(directory, filename)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
            except Exception as e:
                logging.error(f"Failed to delete {file_path}: {e}")
    
    # 保存汇总节点到 summary 目录
    logging.info(f"Preparing to save summary to directory: {SUMMARY_DIR}")
    if all_valid_configs:
        save_to_file(SUMMARY_DIR, "all_nodes", all_valid_configs)
        # 同时保存到根目录
        save_to_file(OUTPUT_DIR, "all_nodes", all_valid_configs)
    
    # 保存协议分类到 protocols 目录和根目录
    logging.info(f"Preparing to save protocols to directory: {PROTOCOLS_DIR}")
    for category, items in final_all_protocols.items():
        if items:
            save_to_file(PROTOCOLS_DIR, category, items)
            save_to_file(OUTPUT_DIR, category, items)
    
    # 保存国家分类到 countries 目录和根目录
    logging.info(f"Preparing to save countries to directory: {COUNTRIES_DIR}")
    country_files_count = 0
    for category, items in final_configs_by_country.items():
        if items:
            save_to_file(COUNTRIES_DIR, category, items)
            save_to_file(OUTPUT_DIR, category, items)
            country_files_count += 1
        else:
            logging.info(f"No items for country {category}")
    
    # 统计生成的国家文件数量
    logging.info(f"Generated {country_files_count} country files")
    
    logging.info(f"--- Script Finished in {time.time() - start_time:.2f} seconds ---")

if __name__ == "__main__":
    asyncio.run(main())
