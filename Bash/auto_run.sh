#!/bin/bash
# ==========================================
# 每日自动化猎巡流水线调度脚本 (Crontab 多项目版)
# ==========================================
# 设置定时任务示例 (每天凌晨 2 点执行)：
# 0 2 * * * /绝对路径/Bash/auto_run.sh >> /绝对路径/Bash/auto_run.log 2>&1
# ==========================================

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
cd "$SCRIPT_DIR" || exit

TARGET_FILE="target.txt"

# 1. 检查目标文是否存在，不存在则自动降级建立范例
if [ ! -f "$TARGET_FILE" ]; then
    echo -e "\n[!] 缺失配置: 未找到 $TARGET_FILE 目标队列文件。"
    echo "[-] 正在当前目录下自动创建空白 target.txt..."
    echo -e "# 每行代表一个独立项目\n# 首个域名为主要项目名，其余同属项目的域用空格追加在后面\n# 示例:\n# example.com example.cn\ntarget.com" > "$TARGET_FILE"
    echo "[-] 请配置目标后重新执行本脚本。"
    exit 1
fi

echo "[*] =========================================="
echo "[*] 启动自动化侦察链路"
echo "[*] 运行时间: $(date '+%Y-%m-%d %H:%M:%S')"
echo "[*] 队列引擎: 逐行读取 $TARGET_FILE"
echo "[*] =========================================="

# 2. 逐行读取进行任务列队处理
while IFS= read -u 9 -r line || [[ -n "$line" ]]; do
    # 忽略纯空行和带有 # 的注释行
    if [[ -z "$(echo "$line" | tr -d ' \r\t')" ]] || [[ "$line" =~ ^# ]]; then
        continue
    fi

    # 提取数组游标中的第一位作为基础项目路径锚点名
    PROJECT_DOMAIN=$(echo "$line" | awk '{print $1}')
    
    echo -e "\n\n[*] =========================================="
    echo "[*] 正在加载与流转独立项目资产: $PROJECT_DOMAIN"
    echo "[*] 当前批次涵盖全部域列表: $line"
    echo "[*] =========================================="

    # ================================
    # 阶段 1: 子域枚举与 HTTP 探活
    # 机制：不加引号展开 $line，使其按空格分解传达给底层脚本遍历
    # ================================
    echo -e "\n[>>>] 执行阶段 1/4: 1_subdomain_enum.sh"
    bash ./1_subdomain_enum.sh $line


    # ================================
    # 阶段 2: DNS 解析、CDN 过滤、C段决策 -> 自动触发端口扫描
    # 机制：后续脚本仅需识别项目库名 $PROJECT_DOMAIN 进行路径寻址
    # ================================
    echo -e "\n[>>>] 执行阶段 2/4: 2_bridge.sh 及 3_port_scan.sh"
    echo "1" | bash ./2_bridge.sh "$PROJECT_DOMAIN"


    # ================================
    # 阶段 3: URL、JS等深度内容发现与搜集
    # ================================
    echo -e "\n[>>>] 执行阶段 3/4: 4_harvest_Ultimate.sh"
    bash ./4_harvest_Ultimate.sh "$PROJECT_DOMAIN"


    # ================================
    # 阶段 4: 汇总、清洗与统一入库 (包含 JS / URL 等全维度)
    # ================================
    echo -e "\n[>>>] 执行阶段 4/4: 5_import_to_db.sh"
    bash ./5_import_to_db.sh "$PROJECT_DOMAIN"

    echo -e "\n[+] 项目 $PROJECT_DOMAIN 全单元执行完毕"

done 9< "$TARGET_FILE"

echo -e "\n[*] =========================================="
echo "[+] 队列内部所有项目已结束扫描流程"
echo "[*] 日志已归档封卷，当前时间: $(date '+%Y-%m-%d %H:%M:%S')"
echo "[*] 存活资产已写入数据库"
echo "[*] =========================================="
