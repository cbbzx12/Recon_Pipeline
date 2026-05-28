#!/bin/bash

# ==========================================
# 自动化子域名收集与存活探测脚本 (并行优化版)
# ==========================================

# === 目录与项目配置 ===
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT_DIR=$(dirname "$SCRIPT_DIR")
OUTPUT_ROOT="$ROOT_DIR/Output"

CUR_DATE=$(date +%Y-%m-%d)
PROJECT_DOMAIN=$1
WORKSPACE="$OUTPUT_ROOT/$PROJECT_DOMAIN/$CUR_DATE"
OUTPUT_DIR="$WORKSPACE/subs"

if [ -z "$PROJECT_DOMAIN" ]; then
    echo -e "用法: $0 <domain1.com> [domain2.com] ..."
    exit 1
fi

mkdir -p "$OUTPUT_DIR"
if [[ "$OSTYPE" != "msys" && "$OSTYPE" != "cygwin" && "$OSTYPE" != "win32" ]]; then
    ln -sfn "$CUR_DATE" "$OUTPUT_ROOT/$PROJECT_DOMAIN/latest"
fi

WORDLIST="$ROOT_DIR/subdomain/best-dns-wordlist.txt"
RESOLVERS="$ROOT_DIR/subdomain/resolvers.txt"
TRUSTED_RESOLVERS="$ROOT_DIR/subdomain/resolvers-trusted.txt"
ONEFORALL_DIR="$ROOT_DIR/subdomain/OneForAll"
SHUIZE_DIR="$ROOT_DIR/subdomain/ShuiZe_0x727"

# === 0. 词表更新提醒 ===
if [ -f "$WORDLIST" ]; then
    OLD_WORDLIST=$(find "$WORDLIST" -mtime +30 -print)
    if [ -n "$OLD_WORDLIST" ]; then
        echo -e "\e[1;31m[!] 提醒: best-dns-wordlist.txt 已超过 30 天未更新，请抽空下载最新版。\e[0m"
    fi
else
    echo -e "\e[1;31m[!] 致命错误: 未找到 $WORDLIST。\e[0m"
    exit 1
fi

# === 核心循环: 遍历所有输入的根域名 ===
for TARGET in "$@"; do
    echo -e "\n\e[1;35m[◆] 正在搜集项目资产: $TARGET (归并至 $PROJECT_DOMAIN)\e[0m"

    TMPDIR="$OUTPUT_DIR/.tmp_${TARGET}"
    mkdir -p "$TMPDIR"

    # --- 被动收集：全部并行启动 ---
    echo "[-] 并行启动被动收集 (crt.sh / subfinder / chaos / OneForAll / ShuiZe)..."

    # 1. crt.sh
    curl -s "https://crt.sh/?q=%25.$TARGET&output=json" \
        | jq -r '.[].name_value' 2>/dev/null \
        | sed 's/\*\.//g' | sort -u > "$TMPDIR/crt.txt" &

    # 2. subfinder
    subfinder -d "$TARGET" -silent -all > "$TMPDIR/subfinder.txt" &

    # 3. chaos
    chaos -d "$TARGET" -silent > "$TMPDIR/chaos.txt" &

    # 4. OneForAll — subshell 隔离 CWD，使用专属 venv
    if [ -d "$ONEFORALL_DIR" ]; then
        (
            cd "$ONEFORALL_DIR" || exit
            "$ONEFORALL_DIR/venv/bin/python3" oneforall.py --target "$TARGET" run > /dev/null 2>&1
            [ -f "results/$TARGET.csv" ] && awk -F, 'NR>1 {print $6}' "results/$TARGET.csv"
        ) > "$TMPDIR/oneforall.txt" &
    fi

    # 5. ShuiZe_0x727 — subshell 隔离 CWD，使用专属 venv
    if [ -d "$SHUIZE_DIR" ]; then
        (
            cd "$SHUIZE_DIR" || exit
            "$SHUIZE_DIR/venv/bin/python3" ShuiZe.py -d "$TARGET" --justInfoGather 1 > /dev/null 2>&1
            grep -hR "$TARGET" result/ 2>/dev/null | grep -oP "[a-zA-Z0-9.-]+\.$TARGET"
        ) > "$TMPDIR/shuize.txt" &
    fi

    # 6. github-subdomains (可选，需 go install github.com/gwen001/github-subdomains@latest)
    if command -v github-subdomains >/dev/null 2>&1; then
        github-subdomains -d "$TARGET" -raw -silent > "$TMPDIR/github.txt" 2>/dev/null &
    fi

    wait
    echo "[+] 被动收集完毕，正在启动 DNS 爆破..."

    # --- 主动爆破 (资源密集，等被动完成后串行跑) ---
    puredns bruteforce "$WORDLIST" "$TARGET" \
        -r "$RESOLVERS" --resolvers-trusted "$TRUSTED_RESOLVERS" -q \
        > "$TMPDIR/puredns.txt"

    # --- 合并当前域结果并清理临时目录 ---
    cat "$TMPDIR"/*.txt 2>/dev/null >> "$OUTPUT_DIR/combined_raw.txt"
    rm -rf "$TMPDIR"
done

echo -e "\e[1;34m[*] 所有域名搜集完毕，正在全量汇总并洗数据...\e[0m"

# 汇总、去重、过滤非本项目域名
PATTERN=$(echo "$@" | sed 's/ /|/g' | sed 's/\./\\./g')
cat "$OUTPUT_DIR/combined_raw.txt" 2>/dev/null \
    | grep -E "($PATTERN)$" | sort -u | grep -v '^\*' \
    > "$OUTPUT_DIR/all_subs.txt"

TOTAL=$(wc -l < "$OUTPUT_DIR/all_subs.txt")
echo -e "\e[1;32m[+] 去重后共发现 $TOTAL 个子域名。\e[0m"
rm -f "$OUTPUT_DIR/combined_raw.txt"

# --- dnsx 预过滤：剔除无 A 记录的死域，减少 httpx 噪声 ---
if command -v dnsx >/dev/null 2>&1; then
    echo -e "\e[1;34m[*] 使用 dnsx 预过滤无解析记录的死域...\e[0m"
    dnsx -l "$OUTPUT_DIR/all_subs.txt" -a -silent \
        | awk '{print $1}' | sort -u > "$OUTPUT_DIR/resolved_subs.txt"
    RESOLVED=$(wc -l < "$OUTPUT_DIR/resolved_subs.txt")
    echo -e "\e[1;32m[+] 有效解析子域: $RESOLVED 个 (过滤掉 $((TOTAL - RESOLVED)) 个死域)。\e[0m"
    HTTPX_INPUT="$OUTPUT_DIR/resolved_subs.txt"
else
    HTTPX_INPUT="$OUTPUT_DIR/all_subs.txt"
fi

echo -e "\e[1;34m[*] 正在运行 httpx 进行 Web 端口服务探测...\e[0m"

# 扩充端口：在原 12 个基础上补充常见中间件与管理后台
TOP_PORTS="80,443,8080,8443,7001,7002,8888,9000,9090,5000,3000,8000,4848,8161,8983,9200,5601,10000,8069,8089,8500,9001"

httpx -l "$HTTPX_INPUT" -p $TOP_PORTS \
    -silent -random-agent -timeout 5 -threads 50 -retries 2 \
    -tech-detect -title -status-code -follow-redirects \
    -j -o "$OUTPUT_DIR/httpx_services.json"

jq -r '.url' "$OUTPUT_DIR/httpx_services.json" | sort -u > "$OUTPUT_DIR/live_subs.txt"
ALIVE=$(wc -l < "$OUTPUT_DIR/live_subs.txt")

echo -e "\e[1;32m[+] 扫描结束！共发现 $ALIVE 个存活 Web 服务。\e[0m"
