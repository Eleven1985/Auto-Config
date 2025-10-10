import os
import re
import asyncio
import time
import logging
import aiohttp
import sys

# 配置参数
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.join(base_dir, 'configs')
SUMMARY_DIR = os.path.join(OUTPUT_DIR, 'summary')
PROTOCOLS_DIR = os.path.join(OUTPUT_DIR, 'protocols')
COUNTRIES_DIR = os.path.join(OUTPUT_DIR, 'countries')
URLS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'urls.txt')

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

# 协议模式配置
PROTOCOL_PATTERNS = {
    'vmess': re.compile(r'vmess://[A-Za-z0-9+/=]+'),
    'vless': re.compile(r'vless://[A-Za-z0-9+/=]+'),
    'trojan': re.compile(r'trojan://[A-Za-z0-9+/=]+'),
    'shadowsocks': re.compile(r'ss://[A-Za-z0-9+/=]+'),
    'hysteria2': re.compile(r'hy2://[A-Za-z0-9+/=]+')
}

# 协议分类映射
PROTOCOL_CATEGORIES = {
    'vmess': 'Vmess',
    'vless': 'Vless',
    'trojan': 'Trojan',
    'shadowsocks': 'ShadowSocks',
    'hysteria2': 'Hysteria2'
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

# 查找匹配的协议配置
def find_matches(text, patterns):
    """在文本中查找匹配的协议配置"""
    matches = {}
    for protocol, pattern in patterns.items():
        found = pattern.findall(text)
        if found:
            matches[protocol] = found
            logging.info(f"Found {len(found)} {protocol} configurations")
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

async def main():
    """Main entry point"""
    start_time = time.time()
    
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
    all_valid_configs = set()  # 汇总所有有效节点

    logging.info("Processing pages for configs...")
    for url, text in fetched_pages:
        if not text:
            continue

        # 查找协议匹配
        page_protocol_matches = find_matches(text, PROTOCOL_PATTERNS)
        for protocol_cat, configs_found in page_protocol_matches.items():
            if protocol_cat in PROTOCOL_CATEGORIES:
                category = PROTOCOL_CATEGORIES[protocol_cat]
                for config in configs_found:
                    # 直接使用原始配置，不进行额外验证
                    all_valid_configs.add(config)
                    final_all_protocols[category].add(config)

    logging.info(f"Total valid configs: {len(all_valid_configs)}")

    # 使用基于名称的国家分类方法
    logging.info("Classifying nodes by name keywords")
    for config in all_valid_configs:
        # 尝试从配置中提取节点名称
        name_part = config.split('#')
        node_name = name_part[1].strip() if len(name_part) > 1 else ""
        
        # 检查节点名称是否包含国家关键词
        matched_country = None
        for country, keywords in COUNTRY_KEYWORDS.items():
            for keyword in keywords:
                if keyword.lower() in node_name.lower() or keyword.lower() in config.lower():
                    matched_country = country
                    break
            if matched_country:
                break
        
        if matched_country and matched_country in final_configs_by_country:
            # 获取中文国家名
            country_name_zh = None
            for code, (en_name, zh_name) in COUNTRY_CODE_MAPPING.items():
                if en_name == matched_country:
                    country_name_zh = zh_name
                    break
            
            # 将中文国家名添加到配置中（可选）
            config_with_country = f"# {country_name_zh}\n{config}" if country_name_zh else config
            final_configs_by_country[matched_country].add(config_with_country)

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
    logging.info(f"Preparing to save protocols to directory: {PROTOCOL_DIR}")
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
    
    # 检查是否有生成的国家文件
    if country_files_count == 0:
        logging.warning("没有生成任何国家文件！请检查分类逻辑是否正常工作。")
        logging.info(f"Total valid configs: {len(all_valid_configs)}")
        logging.info(f"Configured countries: {list(final_configs_by_country.keys())}")
        if all_valid_configs:
            # 输出一些配置样例用于调试
            sample_config = next(iter(all_valid_configs))
            logging.info(f"Sample config: {sample_config[:100]}...")

    logging.info(f"--- Script Finished in {time.time() - start_time:.2f} seconds ---")

if __name__ == "__main__":
    asyncio.run(main())
