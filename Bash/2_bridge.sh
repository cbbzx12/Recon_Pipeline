#!/bin/bash
# =========================================================
# 自动化衔接: 子域名 -> DNS解析 -> 智能CDN过滤/C段扩展 -> 端口扫描
# =========================================================

PROJECT_DOMAIN="$1"

if [ -z "$PROJECT_DOMAIN" ]; then
    echo -e "\e[1;31m用法: $0 <domain1.com> [domain2.com] ...\e[0m"
    echo "注意：第一个域名应与 subdomain_enum.sh 的第一个参数保持一致"
    exit 1
fi

# === 目录与路径配置 ===
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT_DIR=$(dirname "$SCRIPT_DIR")
OUTPUT_ROOT="$ROOT_DIR/Output"

CUR_DATE=$(date +%Y-%m-%d)
# 优先从 Output 目录下的 latest 读取项
if [ -d "$OUTPUT_ROOT/$PROJECT_DOMAIN/latest" ]; then
    WORKSPACE="$OUTPUT_ROOT/$PROJECT_DOMAIN/latest"
else
    WORKSPACE="$OUTPUT_ROOT/$PROJECT_DOMAIN/$CUR_DATE"
fi

SUBDOMAIN_FILE="$WORKSPACE/subs/all_subs.txt"
IP_FILE="$WORKSPACE/ports/resolved_ips.txt"
REAL_IP_FILE="$WORKSPACE/ports/real_ips.txt"
CCLASS_FILE="$WORKSPACE/ports/c_class_ips.txt"

# 确保输出目录存在
mkdir -p "$WORKSPACE/ports"

echo -e "\e[1;34m[*] ==========================================\e[0m"
echo -e "\e[1;34m[*] 阶段 1：将子域名解析为纯 IP 并去重\e[0m"
echo -e "\e[1;34m[*] ==========================================\e[0m"

if ! command -v dnsx &> /dev/null; then
    for domain in $(cat "$SUBDOMAIN_FILE"); do
        dig +short "$domain" | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b'
    done | sort -u > "$IP_FILE"
else
    cat "$SUBDOMAIN_FILE" | dnsx -a -resp-only -silent | sort -u > "$IP_FILE"
fi

TOTAL_IPS=$(wc -l < "$IP_FILE")
echo -e "\e[1;32m[+] 解析完成，共提取到 $TOTAL_IPS 个初步 IP。\e[0m"

echo ""
echo -e "\e[1;34m[*] ==========================================\e[0m"
echo -e "\e[1;34m[*] 阶段 2：智能识别、CDN 过滤与 C 段分析\e[0m"
echo -e "\e[1;34m[*] ==========================================\e[0m"

if ! command -v cdncheck &> /dev/null; then
    cat "$IP_FILE" | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | tr -d '\r' | sort -u > "$REAL_IP_FILE"
else
    cat "$IP_FILE" | cdncheck -exclude -unmatched -silent | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | tr -d '\r' | sort -u > "$REAL_IP_FILE"
fi

REAL_IPS_COUNT=$(wc -l < "$REAL_IP_FILE")

# ================= 核心修改区：容错与交互逻辑 =================
if [ "$REAL_IPS_COUNT" -eq 0 ]; then
    echo -e "\e[1;33m[!] 警告: cdncheck 过滤掉了所有的 $TOTAL_IPS 个 IP。\e[0m"
    echo "[-] 这可能是因为目标使用了全局 WAF，或者属于教育网(CERNET)等特殊网段，被工具误判。"
    echo "[-] 原始提取的部分 IP 如下："
    head -n 5 "$IP_FILE" | awk '{print "    " $0}'
    echo "    ..."
    
    echo ""
    echo -e "\e[1;36m请选择接下来的策略 (输入数字):\e[0m"
    echo "  1) 保守策略: 强制扫这 $TOTAL_IPS 个原始 IP (无视 CDN 警告)"
    echo "  2) 红队策略: 提取这些 IP 的 C 段 (/24) 进行全网段扫描 (推荐用于教育网内网扩张)"
    echo "  3) 放弃扫描: 安全退出"
    read -p "你的选择 [1/2/3]: " STRATEGY_CHOICE

    case $STRATEGY_CHOICE in
        1)
            echo "[-] 你选择了强制扫描原始 IP..."
            cat "$IP_FILE" | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | tr -d '\r' | sort -u > "$REAL_IP_FILE"
            ;;
        2)
            echo "[-] 你选择了 C 段降维打击，正在计算网段..."
            cat "$IP_FILE" | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | cut -d'.' -f1,2,3 | sort -u | awk '{print $1".0/24"}' > "$CCLASS_FILE"
            C_COUNT=$(wc -l < "$CCLASS_FILE")
            echo -e "\e[1;32m[+] 成功提取出 $C_COUNT 个 C 段网段！\e[0m"
            # 将目标文件指向 C 段文件
            cp "$CCLASS_FILE" "$REAL_IP_FILE"
            ;;
        *)
            echo -e "\e[1;31m[-] 流程已终止。\e[0m"
            exit 0
            ;;
    esac
else
    echo -e "\e[1;32m[+] 过滤与清洗完成，最终确认 $REAL_IPS_COUNT 个纯净的真实 IP。\e[0m"
fi
# ===============================================================

echo ""
echo -e "\e[1;34m[*] ==========================================\e[0m"
echo -e "\e[1;34m[*] 阶段 3：移交至端口扫描引擎\e[0m"
echo -e "\e[1;34m[*] ==========================================\e[0m"

if [ ! -x "$SCRIPT_DIR/3_port_scan.sh" ]; then
    chmod +x "$SCRIPT_DIR/3_port_scan.sh" 2>/dev/null
fi

if [ -f "$SCRIPT_DIR/3_port_scan.sh" ]; then
    TARGET_COUNT=$(wc -l < "$REAL_IP_FILE")
    echo "[-] 正在将 $TARGET_COUNT 个目标移交至 3_port_scan.sh ..."
    "$SCRIPT_DIR/3_port_scan.sh" "$REAL_IP_FILE"
else
    echo -e "\e[1;31m[!] 未找到 3_port_scan.sh 脚本：$SCRIPT_DIR/3_port_scan.sh\e[0m"
    exit 1
fi

echo -e "\e[1;32m[+] 自动化流水线交接结束！\e[0m"
