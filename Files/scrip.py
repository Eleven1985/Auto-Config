import asyncio
import aiohttp
import json
import re
import logging
import os
import time  # 添加time模块导入
import shutil
import base64
from urllib.parse import parse_qs, unquote
import asyncio
from logging.handlers import RotatingFileHandler
from bs4 import BeautifulSoup

# 配置参数 - 集中管理
URLS_FILE = 'Files/urls.txt'
KEYWORDS_FILE = 'Files/key.json'
OUTPUT_DIR = 'configs'
REQUEST_TIMEOUT = 10  # 降低请求超时时间
CONCURRENT_REQUESTS = 15  # 增加并发请求数
MAX_CONFIG_LENGTH = 1500
MIN_PERCENT25_COUNT = 15
MAX_TEST_PER_CATEGORY = 200  # 降低每个分类测试的节点数
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
    """Save items to file - 优化版"""
    if not items_set:
        return False, 0
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

async def process_category(category, items, is_country=False):
    """处理单个分类的配置，合并重复逻辑"""
    category_type = "country" if is_country else "category"
    logging.info(f"Processing {category_type} {category}")
    
    if SAVE_WITHOUT_TESTING:
        return save_to_file(OUTPUT_DIR, category, items)
        
    # 导入节点测试器（在函数内部导入以避免循环依赖）
    from node_tester import deduplicate_and_test_configs
    
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
        
    return save_to_file(OUTPUT_DIR, category, valid_configs)

async def main():
    """Main entry point"""
    start_time = time.time()
    
    # Check input files existence
    if not os.path.exists(URLS_FILE) or not os.path.exists(KEYWORDS_FILE):
        logging.critical("Input files not found.")
        return

    # Load input data
    with open(URLS_FILE, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip()]
    with open(KEYWORDS_FILE, 'r', encoding='utf-8') as f:
        categories_data = json.load(f)

    # Prepare data structures
    protocol_patterns = {
        cat: patterns for cat, patterns in categories_data.items() if cat in PROTOCOL_CATEGORIES
    }
    country_keywords = {
        cat: patterns for cat, patterns in categories_data.items() if cat not in PROTOCOL_CATEGORIES
    }
    country_names = list(country_keywords.keys())

    logging.info(f"Loaded {len(urls)} URLs and {len(categories_data)} total categories from key.json.")

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

        # Categorize configs by country
        for config in all_page_configs:
            name_to_check = None
            if '#' in config:
                try:
                    potential_name = config.split('#', 1)[1]
                    name_to_check = unquote(potential_name).strip()
                    if not name_to_check:
                        name_to_check = None
                except IndexError:
                    pass

            if not name_to_check:
                if config.startswith('ssr://'):
                    name_to_check = get_ssr_name(config)
                elif config.startswith('vmess://'):
                    name_to_check = get_vmess_name(config)

            if not name_to_check:
                continue

            current_name = name_to_check if isinstance(name_to_check, str) else ""

            # Check country keywords
            for country_key, keywords_list in country_keywords.items():
                text_keywords = []
                if isinstance(keywords_list, list):
                    # Filter out emojis and short codes
                    for kw in keywords_list:
                        if isinstance(kw, str):
                            is_potential_emoji = (1 <= len(kw) <= 7) and not kw.isalnum()
                            if not is_potential_emoji:
                                text_keywords.append(kw)
                
                # Check for country matches
                for keyword in text_keywords:
                    if not isinstance(keyword, str):
                        continue
                    # Handle abbreviations differently
                    is_abbr = (len(keyword) == 2 or len(keyword) == 3) and re.match(r'^[A-Z]+$', keyword)
                    if is_abbr:
                        pattern = r'\b' + re.escape(keyword) + r'\b'
                        if re.search(pattern, current_name, re.IGNORECASE):
                            final_configs_by_country[country_key].add(config)
                            break
                    else:
                        if keyword.lower() in current_name.lower():
                            final_configs_by_country[country_key].add(config)
                            break
                else:
                    continue  # No match for this country, continue to next
                break  # Found a match, break out of the loop

    # Prepare output directory
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    # Clear existing files in configs directory
    for filename in os.listdir(OUTPUT_DIR):
        if filename != '.gitkeep':  # Preserve .gitkeep file
            file_path = os.path.join(OUTPUT_DIR, filename)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
            except Exception as e:
                logging.error(f"Failed to delete {file_path}: {e}")
    logging.info(f"Preparing to save files to directory: {OUTPUT_DIR}")

    # 先保存协议分类
    for category, items in final_all_protocols.items():
        if items:
            await process_category(category, items)
    
    # 然后保存国家分类
    for category, items in final_configs_by_country.items():
        if items:
            await process_category(category, items, is_country=True)
    
    logging.info(f"--- Script Finished in {time.time() - start_time:.2f} seconds ---")

if __name__ == "__main__":
    asyncio.run(main())
