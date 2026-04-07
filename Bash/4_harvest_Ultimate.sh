#!/bin/bash
# ===================================================
# 内容发现与监控组件 (JS/URL收集)
# 针对差异化增量进行重构版
# ===================================================

TARGET=$1

if [ -z "$TARGET" ]; then
    echo "用法: $0 <target.com>"
    exit 1
fi

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT_DIR=$(dirname "$SCRIPT_DIR")
WORKSPACE="$ROOT_DIR/Output/$TARGET/latest"

mkdir -p "$WORKSPACE/content"
cd "$WORKSPACE/content" || exit

echo "[*] =========================================="
echo "[*] 启动深度资产与监控收割 -> $TARGET"
echo "[*] =========================================="

# 1. 历史 URL 收集 (Gau / Waybackurls)
echo "[-] 正在收集全网 URL (Gau + Waybackurls)..."
gau --subs "$TARGET" > temp_urls.txt 2>/dev/null
waybackurls "$TARGET" >> temp_urls.txt 2>/dev/null
cat temp_urls.txt | grep -E "^http" | sort -u > all_urls.txt
rm -f temp_urls.txt
echo "[+] 成功抓取全网历史 URL"

# 2. JS 收集 (Katana)
echo "[-] 正在使用 Katana 收集实时 JS 与最新特征端点..."
# 依托存活域作为种子
LIVE_SUBS="$WORKSPACE/subs/live_subs.txt"
if [ -s "$LIVE_SUBS" ]; then
    katana -list "$LIVE_SUBS" -js-crawl -depth 3 -silent -em js > all_js_full.txt
    cat all_js_full.txt | grep "\.js" | sort -u > clean_js.txt
    echo "[+] 成功抓取前端 JS 文件链接"
else
    echo "[-] 存活源数据为空，跳过 Katana JS 收集。"
    > clean_js.txt
fi

echo "[*] =========================================="
echo "[+] $TARGET 内容层收割完毕。去重与增量打标将在入库环节交由 DB UPSERT 处理！"
echo "[*] =========================================="
