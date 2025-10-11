# Auto-Config

自动获取、解析和分类代理配置的工具。

## 功能特点
- 从多个源URL获取代理配置
- 支持多种协议格式(vmess、vless、trojan、ss等)
- 按协议类型和国家/地区自动分类配置
- 去重处理，只保留有效配置
- 缓存机制，提高重复运行效率

## 使用方法
1. 确保安装了Python 3.7+和所需依赖
2. 修改`Files/urls.txt`添加或更新源URL
3. 运行脚本: `python Files/scrip.py`
4. 生成的配置文件将保存在`configs/`目录下

## 目录结构
- `Files/`: 包含主脚本、URL列表和依赖文件
- `configs/`: 存放生成的配置文件
  - `summary/`: 所有节点汇总
  - `protocols/`: 按协议分类的节点
  - `countries/`: 按国家分类的节点

## 依赖
- aiohttp: 用于异步HTTP请求