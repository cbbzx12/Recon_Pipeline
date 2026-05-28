#!/usr/bin/env bash
# 3_port_scan.sh — 阶段1: 端口扫描（masscan + nmap + httpx）
# 依赖: masscan（需 root）, nmap, httpx（可选）, python3+openpyxl（可选，XLSX）
#
# 用法（两种模式）：
#   # 由 2_bridge.sh 自动调用（传入 IP 文件）
#   sudo ./3_port_scan.sh /path/to/real_ips.txt [--fast] [--no-waf]
#
#   # 手动调用（传入项目域名，自动寻路 latest/）
#   sudo ./3_port_scan.sh example.com [--fast] [--no-waf]
#
#   # 列出/停止会话（不需要 root）
#   ./3_port_scan.sh --list
#   ./3_port_scan.sh --stop <project_domain>

set -euo pipefail

# ─── 默认配置（保守模式）────────────────────────────────────────────────────
MASS_RATE=300
MASS_WAIT=5
MASS_RETRIES=2
MASS_PORTS="1-65535"
DELAY_MIN=3
DELAY_MAX=8
NMAP_TIMING="-T2"
NMAP_MAX_RATE="--max-rate 50"
NMAP_FLAGS="-sV -Pn -n"
NMAP_SCRIPT_TIMEOUT="60s"
NMAP_TIMEOUT="--host-timeout 300s"
FAST_MODE=0
CHECK_WAF=1

MASSCAN=""
NMAP=""
INTERRUPTED=0

# ─── 路径变量（由 resolve_paths 填充）──────────────────────────────────────
WORKSPACE=""
TARGET_FILE=""
SESSION_DIR=""
TARGETS_FILE=""
COMPLETED_FILE=""
RESULTS_FILE=""
LOG_FILE=""
PID_FILE=""

# ─── 工具函数 ─────────────────────────────────────────────────────────────────
log() {
    local level="$1"; shift
    local msg="$*"
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    local line="[$ts] [$(printf '%-5s' "$level")] $msg"
    echo "$line"
    [[ -n "${LOG_FILE:-}" ]] && echo "$line" >> "$LOG_FILE"
}

die() { echo "[ERROR] $*" >&2; exit 1; }

# ─── Root 检测 ────────────────────────────────────────────────────────────────
check_root() {
    if [[ $EUID -ne 0 ]]; then
        die "masscan 需要 root 权限，请使用: sudo $0 $*"
    fi
}

# ─── 工具检测 ─────────────────────────────────────────────────────────────────
detect_tools() {
    MASSCAN=$(command -v masscan 2>/dev/null) \
        || die "未找到 masscan: apt install masscan 或 yum install masscan"
    NMAP=$(command -v nmap 2>/dev/null) \
        || die "未找到 nmap: apt install nmap"
}

# ─── CIDR 展开 ────────────────────────────────────────────────────────────────
expand_file() {
    local infile="$1"
    local outfile="$2"
    : > "$outfile"
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        line="${line// /}"
        [[ -z "$line" ]] && continue
        if [[ "$line" == */* ]]; then
            "$NMAP" -sL -n "$line" 2>/dev/null \
                | awk '/Nmap scan report for/{print $NF}' \
                >> "$outfile" \
                || die "CIDR 展开失败: $line"
        else
            echo "$line" >> "$outfile"
        fi
    done < "$infile"
}

# ─── 目录路径解析 ─────────────────────────────────────────────────────────────
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT_DIR=$(dirname "$SCRIPT_DIR")
OUTPUT_ROOT="$ROOT_DIR/Output"

resolve_paths() {
    local arg="$1"

    if [[ -f "$arg" ]]; then
        # 传入文件路径（来自 2_bridge.sh）
        TARGET_FILE=$(realpath "$arg")
        local ports_dir
        ports_dir=$(dirname "$TARGET_FILE")
        WORKSPACE=$(dirname "$ports_dir")
        # 安全兜底
        if [[ "$WORKSPACE" != "$OUTPUT_ROOT"* ]]; then
            WORKSPACE=$(dirname "$ports_dir")
        fi
    else
        # 传入 project_domain
        local domain="$arg"
        if [[ -d "$OUTPUT_ROOT/$domain/latest" ]]; then
            WORKSPACE="$OUTPUT_ROOT/$domain/latest"
        else
            WORKSPACE="$OUTPUT_ROOT/$domain/$(date +%Y-%m-%d)"
        fi
        TARGET_FILE="$WORKSPACE/ports/real_ips.txt"
        if [[ ! -f "$TARGET_FILE" ]]; then
            die "未找到 IP 文件: $TARGET_FILE\n请先运行 2_bridge.sh $domain"
        fi
    fi

    mkdir -p "$WORKSPACE/ports" "$WORKSPACE/http"
    SESSION_DIR="$WORKSPACE/ports"
    TARGETS_FILE="$SESSION_DIR/targets.txt"
    COMPLETED_FILE="$SESSION_DIR/completed.txt"
    RESULTS_FILE="$SESSION_DIR/results.csv"
    LOG_FILE="$SESSION_DIR/scan.log"
    PID_FILE="$SESSION_DIR/running.pid"
}

# ─── 列出/停止（以 domain 推导 WORKSPACE）────────────────────────────────────
list_sessions() {
    if [[ ! -d "$OUTPUT_ROOT" ]] || [[ -z "$(ls -A "$OUTPUT_ROOT" 2>/dev/null)" ]]; then
        echo "（无扫描记录）"; return
    fi
    printf "%-25s %-10s %-8s %-8s %-8s %s\n" \
        "项目" "状态" "总目标" "已完成" "服务数" "最后更新"
    printf "%-25s %-10s %-8s %-8s %-8s %s\n" \
        "-------------------------" "----------" "--------" "--------" "--------" "-------------------"
    for proj_dir in "$OUTPUT_ROOT"/*/latest; do
        [[ -d "$proj_dir" ]] || continue
        local name
        name=$(basename "$(dirname "$proj_dir")")
        local pdir="$proj_dir/ports"
        local total=0 done=0 svcs=0 status="未知" last_update="-"
        [[ -f "$pdir/targets.txt" ]]   && total=$(wc -l < "$pdir/targets.txt")
        [[ -f "$pdir/completed.txt" ]] && done=$(wc -l < "$pdir/completed.txt")
        if [[ -f "$pdir/results.csv" ]]; then
            svcs=$(( $(wc -l < "$pdir/results.csv") - 1 ))
            [[ $svcs -lt 0 ]] && svcs=0
        fi
        if [[ -f "$pdir/running.pid" ]]; then
            local pid; pid=$(cat "$pdir/running.pid")
            if kill -0 "$pid" 2>/dev/null; then status="运行中"
            else status="异常中断"; fi
        elif [[ $total -gt 0 && $done -ge $total ]]; then status="已完成"
        elif [[ $done -gt 0 ]]; then status="已暂停"
        else status="未开始"; fi
        [[ -f "$pdir/scan.log" ]] && last_update=$(stat -c '%y' "$pdir/scan.log" 2>/dev/null | cut -c1-16 || echo "-")
        printf "%-25s %-10s %-8s %-8s %-8s %s\n" \
            "$name" "$status" "$total" "$done" "$svcs" "$last_update"
    done
}

do_stop() {
    local arg="$1"
    resolve_paths "$arg"
    [[ ! -f "$PID_FILE" ]] && { echo "[INFO] 无运行中的扫描"; exit 0; }
    local pid; pid=$(cat "$PID_FILE")
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "[WARN] PID $pid 已不存在（上次异常退出），清除 pid 文件"
        rm -f "$PID_FILE"; exit 0
    fi
    echo "[INFO] 向 PID $pid 发送终止信号..."
    kill -TERM "$pid" 2>/dev/null || true
    local w=0
    while kill -0 "$pid" 2>/dev/null; do
        sleep 1; ((w++)) || true
        [[ $w -ge 15 ]] && { kill -9 "$pid" 2>/dev/null || true; break; }
    done
    rm -f "$PID_FILE"
    echo "[INFO] 已停止，续扫: sudo $0 $arg"
    exit 0
}

# ─── CSV → XLSX ───────────────────────────────────────────────────────────────
csv_to_xlsx() {
    local csv="$1"
    local xlsx="${csv%.csv}.xlsx"
    command -v python3 &>/dev/null || { log WARN "python3 未找到，跳过 XLSX 转换"; return; }
    python3 - "$csv" "$xlsx" <<'PYEOF'
import sys, csv, os
csv_path, xlsx_path = sys.argv[1], sys.argv[2]
try:
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment
    from openpyxl.utils import get_column_letter
except ImportError:
    print("[WARN] openpyxl 未安装: pip3 install openpyxl", file=sys.stderr); sys.exit(0)
wb = Workbook()
ws = wb.active
ws.title = "PortScan"
hf = Font(bold=True, color="FFFFFF")
hfill = PatternFill("solid", fgColor="2F5496")
ha = Alignment(horizontal="center")
col_widths = {}
with open(csv_path, newline='', encoding='utf-8') as f:
    for i, row in enumerate(csv.reader(f), 1):
        ws.append(row)
        for j, v in enumerate(row, 1):
            col_widths[j] = max(col_widths.get(j, 0), len(str(v)) + 2)
        if i == 1:
            for j in range(1, len(row)+1):
                c = ws.cell(row=1, column=j)
                c.font = hf; c.fill = hfill; c.alignment = ha
ws.freeze_panes = "A2"
for j, w in col_widths.items():
    ws.column_dimensions[get_column_letter(j)].width = min(w, 60)
wb.save(xlsx_path)
print(f"[INFO] XLSX 已生成: {xlsx_path}", file=sys.stderr)
PYEOF
}

# ─── WAF 检测 ─────────────────────────────────────────────────────────────────
WAF_SIGNATURES=(
    "cloudflare:CF-RAY"
    "cloudflare:cf-cache-status"
    "cloudflare:server:cloudflare"
    "akamai:X-Check-Cacheable"
    "akamai:X-Akamai-Transformed"
    "sucuri:x-sucuri-id"
    "incapsula:X-CDN:Incapsula"
    "f5-bigip:BIGipServer"
    "barracuda:barra_counter_session"
    "fortinet:FORTIWAFSID"
    "aws-waf:x-amzn-requestid"
    "modsecurity:mod_security"
    "aws-cf:x-amz-cf-id"
    "reblaze:rbzid"
)

detect_waf() {
    local ip="$1" nmap_output="$2"
    [[ $CHECK_WAF -eq 0 ]] && return
    for port in 80 443; do
        local scheme="http"
        [[ "$port" == "443" ]] && scheme="https"
        local headers
        headers=$(curl -sk --connect-timeout 5 --max-time 8 -I \
            "${scheme}://${ip}:${port}/" 2>/dev/null || true)
        [[ -z "$headers" ]] && continue
        for sig in "${WAF_SIGNATURES[@]}"; do
            local waf="${sig%%:*}" header="${sig#*:}"
            if echo "$headers" | grep -qi "$header"; then
                log WARN "[WAF] $ip 检测到 $waf（匹配: $header）"
                break 2
            fi
        done
    done
    # filtered 端口占比
    if [[ -n "$nmap_output" ]]; then
        local fc oc total
        fc=$(echo "$nmap_output" | grep -c '/filtered/' 2>/dev/null || true)
        oc=$(echo "$nmap_output" | grep -c '/open/'     2>/dev/null || true)
        total=$(( fc + oc ))
        if [[ $total -gt 0 && $fc -gt 0 ]]; then
            local ratio=$(( fc * 100 / total ))
            [[ $ratio -gt 50 ]] && log WARN "[WAF] $ip filtered 占比 ${ratio}%（${fc}/${total}），疑似 WAF/防火墙"
        fi
    fi
}

# ─── 扫描单个 IP ──────────────────────────────────────────────────────────────
scan_ip() {
    local ip="$1" idx="$2" total="$3"

    log INFO "[$idx/$total] 开始 masscan 扫描: $ip (端口: $MASS_PORTS, 速率: ${MASS_RATE}pps)"

    local ports
    ports=$("$MASSCAN" -p "$MASS_PORTS" "$ip" \
        --rate "$MASS_RATE" \
        --wait "$MASS_WAIT" \
        --retries "$MASS_RETRIES" \
        --open-only \
        -oL - 2>/dev/null \
        | awk '/^open/{print $3}' \
        | sort -n \
        | paste -sd ',' || true)

    if [[ -z "$ports" ]]; then
        log INFO "[$idx/$total] $ip: 无开放端口"
        echo "$ip" >> "$COMPLETED_FILE"
        return
    fi

    log INFO "[$idx/$total] $ip: masscan 发现端口: $ports"
    log INFO "[$idx/$total] $ip: 启动 nmap -sV..."

    # shellcheck disable=SC2086
    local nm_out
    nm_out=$("$NMAP" $NMAP_FLAGS $NMAP_TIMING $NMAP_MAX_RATE \
        -p "$ports" \
        --script-timeout "$NMAP_SCRIPT_TIMEOUT" \
        $NMAP_TIMEOUT \
        -oG - \
        "$ip" 2>/dev/null || true)

    local port_count=0
    while IFS= read -r match; do
        local port proto svc ver
        IFS='/' read -r port _ proto _ svc _ ver _ <<< "$match"
        ver="${ver:-unknown}"
        printf '"%s","%s/%s","%s","%s"\n' "$ip" "$port" "$proto" "$svc" "$ver" >> "$RESULTS_FILE"
        log INFO "[$idx/$total] [结果] $ip  $port/$proto  $svc  $ver"
        (( port_count++ )) || true
    done < <(echo "$nm_out" | grep "^Host:" | grep -oP '\d+/open/[^,\t ]+')

    [[ $port_count -eq 0 ]] && log WARN "[$idx/$total] $ip: nmap 未解析出服务（端口可能被过滤）"
    log INFO "[$idx/$total] $ip: nmap 完成，写入 $port_count 条记录"

    detect_waf "$ip" "$nm_out"
    echo "$ip" >> "$COMPLETED_FILE"
}

# ─── httpx Web 验活 ───────────────────────────────────────────────────────────
run_httpx() {
    command -v httpx &>/dev/null || { log WARN "未找到 httpx，跳过 Web 验活"; return; }

    local http_list="$SESSION_DIR/http_services.txt"
    local web_ports="80 443 8080 8443 8000 8888 8081 7001 9000 9090 5601 9200 4848 8161 8983"

    python3 - "$RESULTS_FILE" "$http_list" "$web_ports" <<'PYEOF'
import sys, csv
results_csv, out_file, web_set_str = sys.argv[1], sys.argv[2], sys.argv[3]
web_set = set(web_set_str.split())
entries = set()
try:
    with open(results_csv, newline="", encoding="utf-8") as f:
        for row in csv.reader(f):
            if len(row) < 2: continue
            ip   = row[0].strip('"')
            port = row[1].strip('"').split('/')[0]
            svc  = row[2].strip('"').lower() if len(row) > 2 else ""
            if port in web_set or 'http' in svc:
                entries.add(f"{ip}:{port}")
except FileNotFoundError:
    pass
with open(out_file, "w") as f:
    f.write("\n".join(sorted(entries)) + ("\n" if entries else ""))
PYEOF

    if [[ ! -s "$http_list" ]]; then
        log INFO "未发现 HTTP 服务，跳过 httpx 验活"
        return
    fi

    log INFO "httpx 验活 $(wc -l < "$http_list") 个 Web 服务..."
    mkdir -p "$WORKSPACE/http"
    httpx -l "$http_list" \
        -silent -random-agent -timeout 10 -retries 2 -threads 50 \
        -title -status-code -tech-detect -follow-redirects \
        -j -o "$WORKSPACE/http/httpx_ports.json" \
        | tee "$WORKSPACE/http/live_urls.txt"

    local alive
    alive=$(wc -l < "$WORKSPACE/http/live_urls.txt" 2>/dev/null || echo 0)
    log INFO "httpx 完成: ${alive} 个存活 Web 服务 → $WORKSPACE/http/httpx_ports.json"
}

# ─── 汇总打印 ─────────────────────────────────────────────────────────────────
print_summary() {
    local total="$1" done="$2"
    local svcs=0
    [[ -f "$RESULTS_FILE" ]] && svcs=$(( $(wc -l < "$RESULTS_FILE") - 1 ))
    [[ $svcs -lt 0 ]] && svcs=0
    echo ""
    echo "══════════════════════════════════════════════"
    echo " 阶段1 端口扫描汇总"
    echo "══════════════════════════════════════════════"
    printf " 扫描目标: %-5d  已完成: %-5d  发现服务: %d\n" "$total" "$done" "$svcs"
    echo " 结果文件: ${RESULTS_FILE%.csv}.xlsx"
    echo " 日志文件: $LOG_FILE"
    echo "══════════════════════════════════════════════"
    if [[ $svcs -gt 0 ]]; then
        echo ""
        echo " 结果预览（前 20 条）:"
        printf "%-18s %-12s %-20s %s\n" "IP" "PORT" "SERVICE" "VERSION"
        printf "%-18s %-12s %-20s %s\n" "------------------" "------------" "--------------------" "-------"
        tail -n +2 "$RESULTS_FILE" | head -20 | while IFS=',' read -r ip port svc ver; do
            ip="${ip//\"/}"; port="${port//\"/}"; svc="${svc//\"/}"; ver="${ver//\"/}"
            printf "%-18s %-12s %-20s %s\n" "$ip" "$port" "$svc" "$ver"
        done
    fi
}

# ─── 帮助信息 ─────────────────────────────────────────────────────────────────
usage() {
    cat <<EOF
用法:
  sudo $(basename "$0") <project_domain|ips_file> [--fast] [--no-waf]
  $(basename "$0") --list
  $(basename "$0") --stop <project_domain|ips_file>

masscan 参数（通过环境变量覆盖）:
  MASS_RATE=300     发包速率（pps），保守默认
  MASS_PORTS=1-65535
  MASS_WAIT=5       最后一包后等待秒数

模式:
  --fast            快速模式（rate=10000, nmap -T4 -sS -Pn -n，需 root）
  --no-waf          跳过 WAF 检测

示例:
  sudo $(basename "$0") example.com
  sudo $(basename "$0") /path/to/real_ips.txt --fast
  $(basename "$0") --list
  $(basename "$0") --stop example.com
EOF
    exit 0
}

# ─── 主函数 ───────────────────────────────────────────────────────────────────
main() {
    [[ $# -eq 0 || "${1:-}" == "-h" || "${1:-}" == "--help" ]] && usage

    # --list 和 --stop 不需要 root
    if [[ "${1:-}" == "--list" ]]; then
        list_sessions; exit 0
    fi
    if [[ "${1:-}" == "--stop" ]]; then
        [[ -z "${2:-}" ]] && die "--stop 需要指定 project_domain 或 ips_file"
        do_stop "$2"
    fi

    local arg="$1"; shift || true

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --fast)   FAST_MODE=1; shift ;;
            --no-waf) CHECK_WAF=0; shift ;;
            *) die "未知参数: $1" ;;
        esac
    done

    check_root
    detect_tools
    resolve_paths "$arg"

    # 快速模式覆盖
    if [[ $FAST_MODE -eq 1 ]]; then
        MASS_RATE=10000; MASS_WAIT=2; MASS_RETRIES=1
        DELAY_MIN=0; DELAY_MAX=0
        NMAP_TIMING="-T4"; NMAP_MAX_RATE=""
        NMAP_FLAGS="-sS -Pn -n -sV"
        NMAP_SCRIPT_TIMEOUT="10s"; NMAP_TIMEOUT="--host-timeout 60s"
        log INFO "快速模式已启用（masscan rate=$MASS_RATE, nmap $NMAP_TIMING）"
    fi

    log INFO "==== 阶段1 端口扫描启动 ===="
    log INFO "masscan: $MASSCAN | nmap: $NMAP"
    log INFO "工作目录: $WORKSPACE"
    log INFO "目标文件: $TARGET_FILE"
    log INFO "masscan: ports=$MASS_PORTS  rate=${MASS_RATE}pps  wait=${MASS_WAIT}s"
    log INFO "nmap:    $NMAP_TIMING  ${NMAP_MAX_RATE}  ${NMAP_TIMEOUT}"

    # PID 冲突检测（已有进程在跑）
    if [[ -f "$PID_FILE" ]]; then
        local old_pid; old_pid=$(cat "$PID_FILE")
        if kill -0 "$old_pid" 2>/dev/null; then
            die "扫描进程已在运行（PID $old_pid），如需停止: $0 --stop $arg"
        else
            log WARN "上次扫描（PID $old_pid）异常中断，自动续扫..."
            rm -f "$PID_FILE"
        fi
    fi

    # 构建展开后的目标列表（续扫时复用）
    local resume=0
    if [[ -f "$TARGETS_FILE" && -s "$TARGETS_FILE" && -f "$COMPLETED_FILE" ]]; then
        local done_prev total_prev
        done_prev=$(wc -l < "$COMPLETED_FILE")
        total_prev=$(wc -l < "$TARGETS_FILE")
        if [[ $done_prev -lt $total_prev ]]; then
            resume=1
            log INFO "检测到未完成会话，自动续扫（${done_prev}/${total_prev} 已完成）"
        fi
    fi

    if [[ $resume -eq 0 ]]; then
        log INFO "展开目标 IP（包含 CIDR）..."
        expand_file "$TARGET_FILE" "$TARGETS_FILE"
        : > "$COMPLETED_FILE"
        [[ -f "$RESULTS_FILE" ]] && rm -f "$RESULTS_FILE"
    fi

    # CSV 表头
    [[ ! -f "$RESULTS_FILE" ]] && echo '"IP","Port","Service","Version"' > "$RESULTS_FILE"

    local total
    total=$(wc -l < "$TARGETS_FILE")
    [[ $total -eq 0 ]] && die "目标列表为空"

    local done_count
    done_count=$(wc -l < "$COMPLETED_FILE")

    if [[ $done_count -ge $total ]]; then
        log INFO "所有 $total 个目标已完成，使用 --new 模式重新扫描"
        print_summary "$total" "$total"
        run_httpx
        exit 0
    fi

    log INFO "总目标: $total | 已完成: $done_count | 待扫描: $(( total - done_count ))"

    # 写 PID
    echo $$ > "$PID_FILE"

    # 优雅退出
    cleanup() {
        INTERRUPTED=1
        log INFO "收到中断信号，正在保存进度..."
        rm -f "$PID_FILE"
        local cur_done
        cur_done=$(wc -l < "$COMPLETED_FILE")
        log INFO "已完成 ${cur_done}/${total}，续扫: sudo $0 $arg"
        csv_to_xlsx "$RESULTS_FILE" 2>&1 || true
        exit 0
    }
    trap cleanup SIGINT SIGTERM

    # 主扫描循环
    local idx=0
    while IFS= read -r ip || [[ -n "$ip" ]]; do
        [[ -z "$ip" ]] && continue
        grep -qxF "$ip" "$COMPLETED_FILE" 2>/dev/null && continue
        (( idx++ )) || true
        scan_ip "$ip" "$((done_count + idx))" "$total"
        if [[ $INTERRUPTED -eq 0 && $idx -lt $(( total - done_count )) && $DELAY_MAX -gt 0 ]]; then
            local wait_sec
            wait_sec=$(( DELAY_MIN + RANDOM % (DELAY_MAX - DELAY_MIN + 1) ))
            log INFO "等待 ${wait_sec}s 后继续..."
            sleep "$wait_sec"
        fi
    done < "$TARGETS_FILE"

    rm -f "$PID_FILE"
    local final_done
    final_done=$(wc -l < "$COMPLETED_FILE")
    log INFO "==== 扫描完成 ===="
    print_summary "$total" "$final_done"
    csv_to_xlsx "$RESULTS_FILE" 2>&1 | tee -a "$LOG_FILE" || true
    run_httpx
}

main "$@"
