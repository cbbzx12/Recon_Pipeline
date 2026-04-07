#!/bin/bash

# ==========================================
# 自动化子域名收集与存活探测脚本
# ==========================================

# === 目录与项目配置 ===
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT_DIR=$(dirname "$SCRIPT_DIR")
OUTPUT_ROOT="$ROOT_DIR/Output"

CUR_DATE=$(date +%Y-%m-%d)
PROJECT_DOMAIN=$1 # 以第一个域名作为项目标识
WORKSPACE="$OUTPUT_ROOT/$PROJECT_DOMAIN/$CUR_DATE"
OUTPUT_DIR="$WORKSPACE/subs"

if [ -z "$PROJECT_DOMAIN" ]; then
    echo -e "用法: $0 <domain1.com> [domain2.com] ..."
    exit 1
fi

# 创建项目目录结构
mkdir -p "$OUTPUT_DIR"
# 创建/更新 latest 软链接
if [[ "$OSTYPE" != "msys" && "$OSTYPE" != "cygwin" && "$OSTYPE" != "win32" ]]; then
    ln -sfn "$CUR_DATE" "$OUTPUT_ROOT/$PROJECT_DOMAIN/latest"
fi

WORDLIST="$ROOT_DIR/subdomain/best-dns-wordlist.txt"
RESOLVERS="$ROOT_DIR/subdomain/resolvers.txt"
TRUSTED_RESOLVERS="$ROOT_DIR/subdomain/resolvers-trusted.txt"
ONEFORALL_DIR="$ROOT_DIR/subdomain/OneForAll"
SHUIZE_DIR="$ROOT_DIR/subdomain/ShuiZe_0x727"

# === 0. 词表更新提醒 (超 30 天未更新则警告) ===
if [ -f "$WORDLIST" ]; then
    OLD_WORDLIST=$(find "$WORDLIST" -mtime +30 -print)
    if [ -n "$OLD_WORDLIST" ]; then
        echo -e "\e[1;31m[!] 提醒: 你的 best-dns-wordlist.txt 已经超过 30 天没有更新了！质量决定命中率，请记得抽空下载最新版。\e[0m"
    fi
else
    echo -e "\e[1;31m[!] 致命错误: 未找到 $WORDLIST。请确保文件存在。\e[0m"
    exit 1
fi

# === 核心循环: 遍历所有输入的根域名 ===
for TARGET in "$@"; do
    echo -e "\n\e[1;35m[◆] 正在搜集项目资产: $TARGET (归并至 $PROJECT_DOMAIN)\e[0m"

    # 1. crt.sh
    echo "[-] 正在运行 crt.sh..."
    curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u >> "$OUTPUT_DIR/combined_raw.txt"

    # 2. subfinder
    echo "[-] 正在运行 subfinder..."
    subfinder -d "$TARGET" -silent -all >> "$OUTPUT_DIR/combined_raw.txt"

    # 3. chaos
    echo "[-] 正在运行 chaos..."
    chaos -d "$TARGET" -silent >> "$OUTPUT_DIR/combined_raw.txt"

    # 4. OneForAll
    if [ -d "$ONEFORALL_DIR" ]; then
        echo "[-] 正在运行 OneForAll..."
        cd "$ONEFORALL_DIR" || exit
        python3 oneforall.py --target "$TARGET" run > /dev/null 2>&1
        [ -f "results/$TARGET.csv" ] && awk -F, '{print $6}' "results/$TARGET.csv" | tail -n +2 >> "$OUTPUT_DIR/combined_raw.txt"
        cd - > /dev/null || exit
    fi

    # 5. ShuiZe_0x727
    if [ -d "$SHUIZE_DIR" ]; then
        echo "[-] 正在运行 ShuiZe_0x727..."
        cd "$SHUIZE_DIR" || exit
        python3 ShuiZe.py -d "$TARGET" --justInfoGather 1 > /dev/null 2>&1
        grep -hR "$TARGET" result/ 2>/dev/null | grep -oP "[a-zA-Z0-9.-]+\.$TARGET" >> "$OUTPUT_DIR/combined_raw.txt"
        cd - > /dev/null || exit
    fi

    # 6. puredns & 7. shuffledns (爆破仅针对核心域名执行一次或依次执行)
    echo "[-] 正在对 $TARGET 执行爆破..."
    puredns bruteforce "$WORDLIST" "$TARGET" -r "$RESOLVERS" --resolvers-trusted "$TRUSTED_RESOLVERS" -q >> "$OUTPUT_DIR/combined_raw.txt"
done

echo -e "\e[1;34m[*] 所有域名搜集完毕，正在全量汇总并洗数据...\e[0m"

# 8. 汇总、去重、清洗
# 核心逻辑：从所有收集到的内容中筛选出符合本项目任一根域名的子域
PATTERN=$(echo "$@" | sed 's/ /|/g' | sed 's/\./\\./g')
cat "$OUTPUT_DIR/combined_raw.txt" "$OUTPUT_DIR"/*.txt 2>/dev/null | \
    grep -E "($PATTERN)$" | sort -u | grep -v '^\*' > "$OUTPUT_DIR/all_subs.txt"

TOTAL=$(wc -l < "$OUTPUT_DIR/all_subs.txt")
echo -e "\e[1;32m[+] 项目全量去重后共发现 $TOTAL 个子域名。\e[0m"

echo -e "\e[1;34m[*] 正在运行 httpx 进行 Top Web Ports 服务探测 (核心架构升级)...\e[0m"

# 9. Top Web Ports 服务探测与指纹结构化
# 强制补充非标 Web 端口，采用 JSON 输出保留 Tech/Title 属性
TOP_PORTS="80,443,8080,8443,7001,7002,8888,9000,9090,5000,3000,8000"
httpx -l "$OUTPUT_DIR/all_subs.txt" -p $TOP_PORTS \
    -silent -random-agent -timeout 5 -threads 50 -retries 2 \
    -tech-detect -title -status-code -follow-redirects \
    -j -o "$OUTPUT_DIR/httpx_services.json"

# 提取用于下游扫描的存活 Base URL (重定向到 live_subs.txt 保持与 01_harvest 的无缝衔接)
jq -r '.url' "$OUTPUT_DIR/httpx_services.json" | sort -u > "$OUTPUT_DIR/live_subs.txt"
ALIVE=$(wc -l < "$OUTPUT_DIR/live_subs.txt")

echo -e "\e[1;32m[+] 扫描结束！项目共发现 $ALIVE 个存活服务。\e[0m"
rm "$OUTPUT_DIR/combined_raw.txt" 2>/dev/null

