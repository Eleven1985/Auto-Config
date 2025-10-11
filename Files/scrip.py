import asyncio
import time
import logging
import aiohttp
import os
import shutil
import re
import hashlib

# 配置参数
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.join(base_dir, 'configs')
SUMMARY_DIR = os.path.join(OUTPUT_DIR, 'summary')
PROTOCOLS_DIR = os.path.join(OUTPUT_DIR, 'protocols')
COUNTRIES_DIR = os.path.join(OUTPUT_DIR, 'countries')
URLS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'urls.txt')
CACHE_DIR = os.path.join(base_dir, 'cache')

# 请求设置
CONCURRENT_REQUESTS = 10
TIMEOUT = 30
CACHE_EXPIRY = 3600  # 缓存过期时间(秒)
RETRY_COUNT = 3      # 请求重试次数

# 确保必要目录存在
os.makedirs(os.path.join(base_dir, 'logs'), exist_ok=True)
os.makedirs(CACHE_DIR, exist_ok=True)

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(base_dir, 'logs/scrip.log')),
        logging.StreamHandler()
    ]
)

# 协议配置 - 统一管理协议前缀、正则和类别
PROTOCOLS = {
    'vmess': {
        'prefix': 'vmess://',
        'pattern': re.compile(r'vmess://[^\s,]+'),
        'category': 'Vmess'
    },
    'vless': {
        'prefix': 'vless://',
        'pattern': re.compile(r'vless://[^\s,]+'),
        'category': 'Vless'
    },
    'trojan': {
        'prefix': 'trojan://',
        'pattern': re.compile(r'trojan://[^\s,]+'),
        'category': 'Trojan'
    },
    'shadowsocks': {
        'prefix': 'ss://',
        'pattern': re.compile(r'ss://[^\s,]+'),
        'category': 'ShadowSocks'
    },
    'hysteria2': {
        'prefix': 'hy2://',
        'pattern': re.compile(r'hy2://[^\s,]+'),
        'category': 'Hysteria2'
    },
    'ssr': {
        'prefix': 'ssr://',
        'pattern': re.compile(r'ssr://[^\s,]+'),
        'category': 'ShadowSocksR'
    },
    'hysteria': {
        'prefix': 'hysteria://',
        'pattern': re.compile(r'hysteria://[^\s,]+'),
        'category': 'Hysteria'
    },
    'tuic': {
        'prefix': 'tuic://',
        'pattern': re.compile(r'tuic://[^\s,]+'),
        'category': 'TUIC'
    },
    'wireguard': {
        'prefix': 'wireguard://',
        'pattern': re.compile(r'wireguard://[^\s,]+'),
        'category': 'WireGuard'
    },
    'naiveproxy': {
        'prefix': 'naive://',
        'pattern': re.compile(r'naive://[^\s,]+'),
        'category': 'NaiveProxy'
    },
    'socks5': {
        'prefix': 'socks5://',
        'pattern': re.compile(r'socks5://[^\s,]+'),
        'category': 'SOCKS5'
    },
    'http': {
        'prefix': 'http://',
        'pattern': re.compile(r'http://[^\s,]+'),
        'category': 'HTTP'
    }
}

# 国家配置
COUNTRY_CONFIG = {
    'United States': {
        'keywords': ['us', 'usa', 'america', 'united states'],
        'code': 'US',
        'name_zh': '美国'
    },
    'China': {
        'keywords': ['cn', 'china', 'beijing', 'shanghai'],
        'code': 'CN',
        'name_zh': '中国'
    },
    'Japan': {
        'keywords': ['jp', 'japan', 'tokyo', 'osaka'],
        'code': 'JP',
        'name_zh': '日本'
    },
    'Singapore': {
        'keywords': ['sg', 'singapore'],
        'code': 'SG',
        'name_zh': '新加坡'
    },
    'Hong Kong': {
        'keywords': ['hk', 'hong kong'],
        'code': 'HK',
        'name_zh': '香港'
    },
    'South Korea': {
        'keywords': ['kr', 'korea', 'south korea', 'seoul'],
        'code': 'KR',
        'name_zh': '韩国'
    },
    'Germany': {
        'keywords': ['de', 'germany'],
        'code': 'DE',
        'name_zh': '德国'
    },
    'United Kingdom': {
        'keywords': ['uk', 'britain', 'united kingdom'],
        'code': 'GB',
        'name_zh': '英国'
    },
    'France': {
        'keywords': ['fr', 'france'],
        'code': 'FR',
        'name_zh': '法国'
    },
    'Canada': {
        'keywords': ['ca', 'canada'],
        'code': 'CA',
        'name_zh': '加拿大'
    },
    'Australia': {
        'keywords': ['au', 'australia'],
        'code': 'AU',
        'name_zh': '澳大利亚'
    },
    'Russia': {
        'keywords': ['ru', 'russia'],
        'code': 'RU',
        'name_zh': '俄罗斯'
    },
    'Netherlands': {
        'keywords': ['nl', 'netherlands'],
        'code': 'NL',
        'name_zh': '荷兰'
    },
    'Switzerland': {
        'keywords': ['ch', 'switzerland'],
        'code': 'CH',
        'name_zh': '瑞士'
    },
    'Italy': {
        'keywords': ['it', 'italy'],
        'code': 'IT',
        'name_zh': '意大利'
    }
}

# 创建目录准备函数
def prepare_directory(directory, clean_existing=True):
    """准备输出目录，可选择清理现有文件"""
    try:
        os.makedirs(directory, exist_ok=True)
        if clean_existing:
            for filename in os.listdir(directory):
                file_path = os.path.join(directory, filename)
                if os.path.isfile(file_path):
                    os.unlink(file_path)
        logging.info(f"Directory prepared: {directory}")
        return True
    except Exception as e:
        logging.error(f"Failed to prepare directory {directory}: {e}")
        return False

# 获取URL的缓存文件名
def get_cache_filename(url):
    """根据URL生成缓存文件名"""
    url_hash = hashlib.md5(url.encode()).hexdigest()
    return os.path.join(CACHE_DIR, f"{url_hash}.cache")

# 从缓存获取响应
def get_cached_response(url):
    """从缓存获取URL响应内容"""
    cache_file = get_cache_filename(url)
    try:
        if os.path.exists(cache_file):
            # 检查缓存是否过期
            cache_time = os.path.getmtime(cache_file)
            if time.time() - cache_time < CACHE_EXPIRY:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                logging.debug(f"Loaded cached response for {url}")
                return content
            else:
                logging.debug(f"Cache expired for {url}")
    except Exception as e:
        logging.error(f"Error reading cache for {url}: {e}")
    return None

# 保存响应到缓存
def save_response_to_cache(url, content):
    """将URL响应内容保存到缓存"""
    cache_file = get_cache_filename(url)
    try:
        with open(cache_file, 'w', encoding='utf-8') as f:
            f.write(content)
        logging.debug(f"Saved response to cache for {url}")
    except Exception as e:
        logging.error(f"Failed to save cache for {url}: {e}")

# 验证配置的有效性
def validate_config(config):
    """验证配置是否有效"""
    # 基本验证逻辑，可以根据需要扩展
    if not config or len(config) < 10:
        return False
    # 检查是否包含有效的协议前缀
    for protocol in PROTOCOLS.values():
        if config.startswith(protocol['prefix']):
            return True
    return False

# 异步获取URL内容，带缓存支持
async def fetch_url_with_retry(session, url, timeout=TIMEOUT, retries=RETRY_COUNT):
    """异步获取URL内容，支持重试"""
    # 先尝试从缓存获取
    cached_content = get_cached_response(url)
    if cached_content is not None:
        return url, cached_content
    
    for attempt in range(retries):
        try:
            async with session.get(url, timeout=timeout) as response:
                response.raise_for_status()
                text = await response.text()
                # 保存到缓存
                save_response_to_cache(url, text)
                logging.info(f"Successfully fetched {url}")
                return url, text
        except Exception as e:
            if attempt == retries - 1:
                logging.error(f"Failed to fetch {url} after {retries} attempts: {e}")
                return url, ""
            logging.warning(f"Attempt {attempt+1} failed for {url}, retrying...")
            await asyncio.sleep(1)  # 简单退避

# 在文本中查找匹配的协议配置
def find_matches(text):
    """在文本中查找匹配的协议配置"""
    matches = {}  # 确保即使没有匹配项也返回空字典
    
    for protocol_name, protocol_config in PROTOCOLS.items():
        try:
            found = protocol_config['pattern'].findall(text)
            if found:
                matches[protocol_name] = found
                logging.debug(f"Found {len(found)} {protocol_name} configurations")
        except Exception as e:
            logging.error(f"Error matching {protocol_name} patterns: {e}")
    
    return matches

# 保存配置项到文件
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

# 复制文件从源目录到目标目录
def copy_file(source_dir, target_dir, filename):
    """复制文件从源目录到目标目录"""
    source_path = os.path.join(source_dir, f"{filename}.txt")
    target_path = os.path.join(target_dir, f"{filename}.txt")
    if os.path.exists(source_path):
        try:
            shutil.copy2(source_path, target_path)
            logging.debug(f"Copied {filename} file to {target_dir}")
            return True
        except Exception as e:
            logging.error(f"Failed to copy {filename} file: {e}")
    return False

# 去除重复的节点配置
def remove_duplicate_configs(configs):
    """去除重复的节点配置"""
    # 使用集合推导式提高去重效率
    unique_configs = {config for config in configs if validate_config(config)}
    removed_count = len(configs) - len(unique_configs)
    
    if removed_count > 0:
        logging.info(f"Removed {removed_count} duplicate or invalid configs")
    
    return unique_configs

# 根据关键词对配置进行国家分类
def classify_by_country(config):
    """根据关键词对配置进行国家分类"""
    # 尝试从配置中提取节点名称
    name_part = config.split('#')
    node_name = name_part[1].strip() if len(name_part) > 1 else ""
    
    # 检查节点名称是否包含国家关键词
    matched_country = None
    for country_name, country_data in COUNTRY_CONFIG.items():
        for keyword in country_data['keywords']:
            if keyword.lower() in node_name.lower() or keyword.lower() in config.lower():
                matched_country = country_name
                break
        if matched_country:
            break
    
    if matched_country:
        # 将中文国家名添加到配置中
        config_with_country = f"# {COUNTRY_CONFIG[matched_country]['name_zh']}\n{config}"
        return matched_country, config_with_country
    
    return None, config

# 分类并保存配置
def classify_and_save(configs, final_configs_by_country, final_all_protocols):
    """统一处理配置的分类逻辑"""
    # 按协议分类
    logging.info("Classifying configs by protocol...")
    for config in configs:
        matched = False
        # 使用协议前缀直接匹配
        for protocol in PROTOCOLS.values():
            if config.startswith(protocol['prefix']):
                final_all_protocols[protocol['category']].add(config)
                matched = True
                break
        
        # 记录未匹配的协议格式，用于调试
        if not matched:
            # 只记录前50个字符以避免日志过长
            logging.debug(f"Unmatched protocol format: {config[:50]}...")
    
    # 记录各协议分类的配置数量
    for category, items in final_all_protocols.items():
        logging.info(f"{category}: {len(items)} items")
    
    # 使用基于名称的国家分类方法
    logging.info("Classifying nodes by name keywords")
    for config in configs:
        country, config_with_country = classify_by_country(config)
        if country and country in final_configs_by_country:
            final_configs_by_country[country].add(config_with_country)

# 主函数
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
                return await fetch_url_with_retry(session, url)
        
        async with aiohttp.ClientSession() as session:
            fetched_pages = await asyncio.gather(*[fetch_with_sem(session, u) for u in urls])

        # 初始化结果结构
        country_names = list(COUNTRY_CONFIG.keys())
        protocol_categories = [protocol['category'] for protocol in PROTOCOLS.values()]
        final_configs_by_country = {cat: set() for cat in country_names}
        final_all_protocols = {cat: set() for cat in protocol_categories}
        all_configs = []  # 先收集所有配置，之后再进行去重

        logging.info("Processing pages for configs...")
        for url, text in fetched_pages:
            if not text:
                continue

            # 查找协议匹配
            page_protocol_matches = find_matches(text)
            for protocol_name, configs_found in page_protocol_matches.items():
                all_configs.extend(configs_found)

        # 去除重复节点
        logging.info("Removing duplicate configs...")
        unique_configs = remove_duplicate_configs(all_configs)
        logging.info(f"Unique configs count: {len(unique_configs)}")

        # 统一处理分类逻辑
        classify_and_save(unique_configs, final_configs_by_country, final_all_protocols)

        # 准备输出目录
        directories = [OUTPUT_DIR, SUMMARY_DIR, PROTOCOLS_DIR, COUNTRIES_DIR]
        for directory in directories:
            prepare_directory(directory)
        
        # 保存配置到相应目录
        # 保存汇总节点到 summary 目录
        if unique_configs:
            save_to_file(SUMMARY_DIR, "all_nodes", unique_configs)
        
        # 保存协议分类到 protocols 目录
        protocol_files_count = 0
        for category, items in final_all_protocols.items():
            if items:
                save_to_file(PROTOCOLS_DIR, category, items)
                protocol_files_count += 1
        
        # 保存国家分类到 countries 目录
        country_files_count = 0
        for category, items in final_configs_by_country.items():
            if items:
                save_to_file(COUNTRIES_DIR, category, items)
                country_files_count += 1
        
        # 复制重要文件到根目录
        # 复制汇总文件到根目录
        if unique_configs:
            copy_file(SUMMARY_DIR, OUTPUT_DIR, "all_nodes")
        
        # 复制协议分类文件到根目录
        for category in protocol_categories:
            copy_file(PROTOCOLS_DIR, OUTPUT_DIR, category)
        
        # 复制国家分类文件到根目录
        for country in country_names:
            copy_file(COUNTRIES_DIR, OUTPUT_DIR, country)
        
        # 统计生成的文件数量
        logging.info(f"Generated {country_files_count} country files and {protocol_files_count} protocol files")
        
        # 检查是否有生成的国家文件
        if country_files_count == 0:
            logging.warning("没有生成任何国家文件！请检查分类逻辑是否正常工作。")
            logging.info(f"Total configs: {len(unique_configs)}")
            if unique_configs:
                # 输出一些配置样例用于调试
                sample_config = next(iter(unique_configs))
                logging.info(f"Sample config: {sample_config[:100]}...")

        logging.info(f"--- Script Finished in {time.time() - start_time:.2f} seconds ---")
    except Exception as e:
        logging.error(f"An error occurred during script execution: {e}")
        import traceback
        logging.error(traceback.format_exc())

if __name__ == "__main__":
    asyncio.run(main())