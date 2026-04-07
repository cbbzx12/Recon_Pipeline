#!/bin/bash
# ==========================================
# 面向 0-3 阶段的资产自动化合并入库脚本 (去绝对路径版)
# ==========================================

TARGET=$1

if [ -z "$TARGET" ]; then
    echo "用法: $0 <target.com>"
    exit 1
fi
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT_DIR=$(dirname "$SCRIPT_DIR")
WORKSPACE="$ROOT_DIR/Output/$TARGET/latest"
DB="$ROOT_DIR/db/recon.db"

echo "[*] =========================================="
echo "[*] 正在执行全节点数据投递 -> $TARGET"
echo "[*] 核心数据挂载点: $WORKSPACE"
echo "[*] =========================================="

# 如果库不在，自动建立新库
if [ ! -f "$DB" ]; then
    echo "[-] DB 不存在，正在试图初始化核心表结构..."
    python3 "$ROOT_DIR/init_db.py" --db "$DB" 2>/dev/null || echo "[!] 请确保在根目录部署了 init_db.py"
fi

# [阶段 0] 子域名打点
SUB_FILE="$WORKSPACE/subs/all_subs.txt"
if [ -f "$SUB_FILE" ]; then
    echo "[+] 提取 [阶段 0] 子域名枚举记录..."
    python3 "$ROOT_DIR/integrator.py" --db "$DB" --subfinder "$SUB_FILE"
else
    echo "[-] 跳过: $SUB_FILE 不存在"
fi

# [阶段 0.5] Web探活及指纹
# 1. 提取 Subdomain (默认顶级 Web) 资产指纹
HTTPX_FILE="$WORKSPACE/subs/httpx_services.json"
if [ -f "$HTTPX_FILE" ]; then
    echo "[+] 提取 [阶段 0.5 - 域探测] Web 应用指纹及基础 HTTP 映射..."
    python3 "$ROOT_DIR/integrator.py" --db "$DB" --httpx "$HTTPX_FILE"
else
    echo "[-] 跳过: $HTTPX_FILE 不存在"
fi

# 2. 提取 Nmap 大量非标端口引流出的存活 Web 资产指纹
HTTPX_PORT_FILE="$WORKSPACE/http/httpx_ports.json"
if [ -f "$HTTPX_PORT_FILE" ]; then
    echo "[+] 提取 [阶段 0.5 - 端口扫描] 非标 Web 应用指纹及基础 HTTP/Port 映射..."
    python3 "$ROOT_DIR/integrator.py" --db "$DB" --httpx "$HTTPX_PORT_FILE"
else
    echo "[-] 跳过: $HTTPX_PORT_FILE 不存在"
fi

# [阶段 1] 纵向收割 -> 历史流量、目录与前端源码 JS
CONTENT_DIR="$WORKSPACE/content"
if [ -d "$CONTENT_DIR" ]; then
    if [ -f "$CONTENT_DIR/all_urls.txt" ]; then
        echo "[+] 提取 [阶段 1] Wayback/Gau 历史 URL..."
        python3 "$ROOT_DIR/integrator.py" --db "$DB" --history "$CONTENT_DIR/all_urls.txt"
    fi
    if [ -f "$CONTENT_DIR/clean_js.txt" ]; then
        echo "[+] 提取 [阶段 1] 内部及外部调用的 js 端点..."
        python3 "$ROOT_DIR/integrator.py" --db "$DB" --js-urls "$CONTENT_DIR/clean_js.txt"
    fi
    
    # 将批量 ffuf 的 JSON 文件投递解析 (如果有的话，通常存放在类似目录)
    for ffuf_file in "$WORKSPACE"/content/ffuf_*.json; do
        if [ -f "$ffuf_file" ]; then
            python3 "$ROOT_DIR/integrator.py" --db "$DB" --ffuf "$ffuf_file" > /dev/null 2>&1
        fi
    done
else
    echo "[-] 跳过: $CONTENT_DIR 内容目录不存在"
fi

# [阶段 2 & 3] Arjun 爆破与利用 (预留结构)
ARJUN_FILE="$WORKSPACE/parameters/${TARGET}_arjun_results.json"
if [ -f "$ARJUN_FILE" ]; then
    echo "[+] 提取 [阶段 2-3] API 隐藏参数探测特征..."
    python3 "$ROOT_DIR/integrator.py" --db "$DB" --parameters "$ARJUN_FILE" --param-source arjun
else
    echo "[-] 跳过参数提取环节"
fi

echo "[*] =========================================="
echo "[+] 目标 $TARGET 全部阶段资产聚合入库完成！"
echo "[+] 您可以启动 python3 web_ui.py 通过 Web 仪表盘开始复盘审计。"
echo "[*] =========================================="
