#!/bin/bash
# ==========================================
# 面向 0-3 阶段的资产自动化合并入库脚本
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
INTEGRATOR="$ROOT_DIR/db/integrator.py"

echo "[*] =========================================="
echo "[*] 正在执行全节点数据投递 -> $TARGET"
echo "[*] 核心数据挂载点: $WORKSPACE"
echo "[*] =========================================="

# 如果库不在，自动建立新库
if [ ! -f "$DB" ]; then
    echo "[-] DB 不存在，正在试图初始化核心表结构..."
    python3 "$ROOT_DIR/db/init_db.py" 2>/dev/null || echo "[!] 请确保在 db/ 目录下部署了 init_db.py"
fi

# [阶段 0] 子域名打点
SUB_FILE="$WORKSPACE/subs/all_subs.txt"
if [ -f "$SUB_FILE" ]; then
    echo "[+] 提取 [阶段 0] 子域名枚举记录..."
    python3 "$INTEGRATOR" --db "$DB" --subfinder "$SUB_FILE"
else
    echo "[-] 跳过: $SUB_FILE 不存在"
fi

# [阶段 0.5] Web探活及指纹
# 1. 域名级 Web 应用指纹
HTTPX_FILE="$WORKSPACE/subs/httpx_services.json"
if [ -f "$HTTPX_FILE" ]; then
    echo "[+] 提取 [阶段 0.5 - 域探测] Web 应用指纹..."
    python3 "$INTEGRATOR" --db "$DB" --httpx "$HTTPX_FILE"
else
    echo "[-] 跳过: $HTTPX_FILE 不存在"
fi

# [阶段 1] 端口扫描结果
# 2. 端口扫描 CSV（masscan + nmap service/version）
PORT_CSV="$WORKSPACE/ports/results.csv"
if [ -f "$PORT_CSV" ]; then
    echo "[+] 提取 [阶段 1 - 端口扫描] 服务指纹（IP / port / service / version）..."
    python3 "$INTEGRATOR" --db "$DB" --port-csv "$PORT_CSV"
else
    echo "[-] 跳过: $PORT_CSV 不存在"
fi

# 3. 非标端口 httpx 验活结果
HTTPX_PORT_FILE="$WORKSPACE/http/httpx_ports.json"
if [ -f "$HTTPX_PORT_FILE" ]; then
    echo "[+] 提取 [阶段 1 - 端口扫描] 非标 Web 应用指纹..."
    python3 "$INTEGRATOR" --db "$DB" --httpx "$HTTPX_PORT_FILE"
else
    echo "[-] 跳过: $HTTPX_PORT_FILE 不存在"
fi

# [阶段 2] 纵向收割 -> 历史流量与前端 JS
CONTENT_DIR="$WORKSPACE/content"
if [ -d "$CONTENT_DIR" ]; then
    if [ -f "$CONTENT_DIR/all_urls.txt" ]; then
        echo "[+] 提取 [阶段 2] Wayback/Gau 历史 URL..."
        python3 "$INTEGRATOR" --db "$DB" --target "$TARGET" --urls "$CONTENT_DIR/all_urls.txt"
    fi
    if [ -f "$CONTENT_DIR/clean_js.txt" ]; then
        echo "[+] 提取 [阶段 2] 前端 JS 端点..."
        python3 "$INTEGRATOR" --db "$DB" --target "$TARGET" --js "$CONTENT_DIR/clean_js.txt"
    fi
    # TODO: 待 integrator 支持后，添加 --ffuf 目录爆破结果导入
    # TODO: 待 integrator 支持后，添加 --parameters arjun 参数探测导入
else
    echo "[-] 跳过: $CONTENT_DIR 内容目录不存在"
fi

echo "[*] =========================================="
echo "[+] 目标 $TARGET 全部阶段资产聚合入库完成！"
echo "[+] 启动面板: cd db && python3 web_ui.py  (http://0.0.0.0:8080)"
echo "[*] =========================================="
