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
NMAP_FLAGS="-sS -sV -Pn -n"
NMAP_SCRIPT_TIMEOUT="60s"
NMAP_TIMEOUT="--host-timeout 300s"
FAST_MODE=0
CHECK_WAF=1
PARALLEL=1

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
LOCK_FILE=""

# ─── 工具函数 ─────────────────────────────────────────────────────────────────
log() {
    local level="$1"; shift
    local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
    local line="[$ts] [$(printf '%-5s' "$level")] $*"
    if [[ -n "${LOCK_FILE:-}" && -e "${LOCK_FILE}" ]]; then
        ( flock -x 200; echo "$line"; [[ -n "${LOG_FILE:-}" ]] && echo "$line" >> "$LOG_FILE" ) 200>"$LOCK_FILE"
    else
        echo "$line"
        [[ -n "${LOG_FILE:-}" ]] && echo "$line" >> "$LOG_FILE"
    fi
}

safe_append() {
    local file="$1"; shift
    ( flock -x 200; printf '%s\n' "$@" >> "$file" ) 200>"$LOCK_FILE"
}

safe_append_raw() {
    local file="$1"; shift
    ( flock -x 200; printf '%s' "$@" >> "$file" ) 200>"$LOCK_FILE"
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
    LOCK_FILE="$SESSION_DIR/.lock"
    : > "$LOCK_FILE"
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

# ─── CSV → HTML ───────────────────────────────────────────────────────────────
csv_to_html() {
    local csv="$1"
    local html_out="${csv%.csv}.html"
    local session_name
    session_name=$(basename "$(dirname "$(dirname "$csv")")")
    local total_targets=0 total_scanned=0
    [[ -f "$TARGETS_FILE" ]]   && total_targets=$(wc -l < "$TARGETS_FILE" | tr -d ' ')
    [[ -f "$COMPLETED_FILE" ]] && total_scanned=$(wc -l < "$COMPLETED_FILE" | tr -d ' ')
    command -v python3 &>/dev/null || { log WARN "python3 未找到，跳过 HTML 生成"; return; }
    python3 - "$csv" "$html_out" "$session_name" "$total_targets" "$total_scanned" <<'PYEOF'
import sys, csv, json, io
from collections import Counter
from datetime import datetime

csv_path, html_path, session = sys.argv[1], sys.argv[2], sys.argv[3]
total_tgts = int(sys.argv[4]) if len(sys.argv) > 4 else 0
total_done = int(sys.argv[5]) if len(sys.argv) > 5 else 0

rows = []
try:
    with open(csv_path, 'r', encoding='utf-8') as f:
        for row in csv.DictReader(io.StringIO(f.read())):
            ip  = row.get('IP','').strip('"')
            pt  = row.get('Port','').strip('"')
            svc = row.get('Service','').strip('"')
            ver = row.get('Version','').strip('"')
            if ip: rows.append({'ip':ip,'port':pt,'service':svc,'version':ver})
except Exception as e:
    print(f"[WARN] CSV 解析错误: {e}", file=sys.stderr)

total_ports = len(rows)
unique_ips  = len(set(r['ip'] for r in rows))
top_versions = Counter(r['version'] or 'unknown' for r in rows).most_common(10)
top_ports    = Counter(r['port'].split('/')[0] for r in rows).most_common(10)

WAF_SIGS = {
    'elb':'AWS ELB','awselb':'AWS ELB','openresty':'OpenResty/Ali WAF',
    'tengine':'Alibaba Tengine','cloudflare':'Cloudflare WAF',
    'akamai':'Akamai WAF','f5':'F5 BIG-IP','incapsula':'Incapsula WAF',
    'sucuri':'Sucuri WAF','huawei':'Huawei IPS',
}
SENS_PORTS = {
    '23':('Telnet','critical'),'3389':('RDP','high'),'3306':('MySQL','high'),
    '6379':('Redis','high'),'27017':('MongoDB','high'),'5432':('PostgreSQL','high'),
    '21':('FTP','medium'),'22':('SSH','info'),'1883':('MQTT','medium'),
}
RISK_ORD = {'critical':0,'high':1,'medium':2,'info':3,'low':4}

waf_map = {}
for r in rows:
    vl = r['version'].lower()
    for key,label in WAF_SIGS.items():
        if key in vl:
            waf_map.setdefault(r['ip'], label)
            break

sens_rows = sorted(
    [dict(**r, port_name=SENS_PORTS[p][0], risk=SENS_PORTS[p][1])
     for r in rows if (p:=r['port'].split('/')[0]) in SENS_PORTS],
    key=lambda x: RISK_ORD.get(x['risk'],9)
)
high_risk_count = sum(1 for r in sens_rows if r['risk'] in ('critical','high'))
now = datetime.now().strftime('%Y-%m-%d %H:%M')
stat_tgts = total_tgts if total_tgts > 0 else unique_ips
stat_done = total_done if total_done > 0 else unique_ips

cv_labels = json.dumps([v[0] for v in top_versions])
cv_data   = json.dumps([v[1] for v in top_versions])
cp_labels = json.dumps([f":{p[0]}" for p in top_ports])
cp_data   = json.dumps([p[1] for p in top_ports])

RISK_CSS = {
    'critical':'background:#fef2f2;color:#dc2626;border:1px solid #fecaca',
    'high':    'background:#fff7ed;color:#ea580c;border:1px solid #fed7aa',
    'medium':  'background:#fefce8;color:#ca8a04;border:1px solid #fef08a',
    'info':    'background:#eff6ff;color:#2563eb;border:1px solid #bfdbfe',
    'low':     'background:#f8fafc;color:#64748b;border:1px solid #e2e8f0',
}
RISK_LBL = {'critical':'严重','high':'高危','medium':'中危','info':'信息','low':'低危'}

def rbadge(risk):
    s = RISK_CSS.get(risk,'background:#f8fafc;color:#64748b')
    l = RISK_LBL.get(risk,'未知')
    return f'<span style="display:inline-block;padding:.15rem .5rem;border-radius:4px;font-size:.75rem;font-weight:600;{s}">{l}</span>'

waf_rows_html = ''.join(
    f'<tr><td class="ip">{ip}</td><td>{label}</td></tr>\n'
    for ip, label in waf_map.items()
)
sens_rows_html = ''.join(
    f'<tr data-risk="{r["risk"]}">'
    f'<td class="ip">{r["ip"]}</td>'
    f'<td style="font-family:monospace">{r["port"]} <span style="color:#94a3b8;font-size:.75rem">({r["port_name"]})</span></td>'
    f'<td>{rbadge(r["risk"])}</td>'
    f'<td><code>{r["version"] or "-"}</code></td></tr>\n'
    for r in sens_rows
)
all_rows_html = ''.join(
    f'<tr><td class="ip">{r["ip"]}</td>'
    f'<td style="font-family:monospace">{r["port"]}</td>'
    f'<td style="color:#475569">{r["service"]}</td>'
    f'<td><code>{r["version"] or "-"}</code></td></tr>\n'
    for r in rows
)

html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>端口扫描报告 · {session}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
:root{{--bg:#f1f5f9;--card:#ffffff;--bd:#e2e8f0;--txt:#1e293b;--mt:#64748b;--ac:#4f46e5;--ac2:#0891b2}}
body{{background:var(--bg);color:var(--txt);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px}}
.hdr{{background:#ffffff;border-bottom:1px solid var(--bd);padding:1.25rem 2rem;box-shadow:0 1px 3px rgba(0,0,0,.06)}}
.hdr h1{{font-size:1.4rem;font-weight:700;color:var(--ac)}}
.hdr p{{color:var(--mt);font-size:.82rem;margin-top:.2rem}}
.meta{{display:flex;gap:1.5rem;margin-top:.6rem;flex-wrap:wrap}}
.meta span{{color:var(--mt);font-size:.8rem}}.meta strong{{color:var(--txt)}}
.con{{max-width:1400px;margin:0 auto;padding:1.5rem 2rem}}
.sg{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1rem;margin-bottom:1.5rem}}
.sc{{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:1rem 1.2rem;border-top:3px solid transparent}}
.sc.b{{border-top-color:#3b82f6}}.sc.g{{border-top-color:#22c55e}}
.sc.y{{border-top-color:#f59e0b}}.sc.r{{border-top-color:#ef4444}}.sc.p{{border-top-color:#8b5cf6}}
.sc .lbl{{font-size:.72rem;color:var(--mt);text-transform:uppercase;letter-spacing:.05em;font-weight:500}}
.sc .val{{font-size:1.8rem;font-weight:700;margin-top:.2rem}}
.sc.b .val{{color:#2563eb}}.sc.g .val{{color:#16a34a}}.sc.y .val{{color:#d97706}}
.sc.r .val{{color:#dc2626}}.sc.p .val{{color:#7c3aed}}
.sc .sub{{font-size:.72rem;color:var(--mt);margin-top:.1rem}}
.cg{{display:grid;grid-template-columns:1fr 1fr;gap:1.2rem;margin-bottom:1.5rem}}
@media(max-width:800px){{.cg{{grid-template-columns:1fr}}}}
.cc{{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:1.2rem}}
.cc h3{{font-size:.85rem;font-weight:600;color:var(--txt);margin-bottom:.8rem;padding-bottom:.5rem;border-bottom:1px solid var(--bd)}}
.cw{{height:220px;position:relative}}
.sec{{background:var(--card);border:1px solid var(--bd);border-radius:10px;margin-bottom:1.5rem;overflow:hidden}}
.sh{{padding:.9rem 1.2rem;border-bottom:1px solid var(--bd);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.5rem;background:#fafafa}}
.sh h2{{font-size:.9rem;font-weight:600;color:var(--txt)}}
.ctrl{{display:flex;gap:.5rem;align-items:center}}
.si{{background:#ffffff;border:1px solid var(--bd);color:var(--txt);padding:.35rem .7rem;border-radius:6px;font-size:.82rem;width:200px;outline:none}}
.si:focus{{border-color:var(--ac);box-shadow:0 0 0 3px rgba(79,70,229,.1)}}
.fs{{background:#ffffff;border:1px solid var(--bd);color:var(--txt);padding:.35rem .55rem;border-radius:6px;font-size:.78rem;outline:none;cursor:pointer}}
.tw{{overflow-x:auto;max-height:440px;overflow-y:auto}}
table{{width:100%;border-collapse:collapse;font-size:.82rem}}
thead th{{background:#f8fafc;color:var(--mt);font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;padding:.6rem 1rem;text-align:left;position:sticky;top:0;z-index:1;border-bottom:1px solid var(--bd);white-space:nowrap;cursor:pointer;user-select:none;font-weight:600}}
thead th:hover{{color:var(--txt)}}
tbody tr{{border-bottom:1px solid #f1f5f9}}
tbody tr:hover{{background:#f8fafc}}
tbody td{{padding:.55rem 1rem;color:var(--txt)}}
.ip{{font-family:monospace;color:var(--ac2);font-weight:500}}
code{{color:#475569;font-size:.8rem;background:#f1f5f9;padding:.1rem .3rem;border-radius:3px}}
.ci{{font-size:.75rem;color:var(--mt);padding:.4rem 1rem;border-top:1px solid var(--bd);background:#fafafa}}
</style>
</head>
<body>
<div class="hdr">
<div style="max-width:1400px;margin:0 auto">
<div style="display:flex;align-items:center;gap:.75rem">
<div style="width:34px;height:34px;background:linear-gradient(135deg,#4f46e5,#0891b2);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:1rem;flex-shrink:0">🔍</div>
<div><h1>端口扫描报告 · {session}</h1><p>masscan + nmap 全端口版本探测结果</p></div>
</div>
<div class="meta">
<span>目标数: <strong>{stat_tgts:,}</strong></span>
<span>已扫描: <strong>{stat_done:,}</strong></span>
<span>生成时间: <strong>{now}</strong></span>
</div>
</div>
</div>
<div class="con">
<div class="sg">
<div class="sc b"><div class="lbl">目标 IP</div><div class="val">{stat_tgts:,}</div><div class="sub">已扫描 {stat_done:,} 个</div></div>
<div class="sc g"><div class="lbl">开放端口</div><div class="val">{total_ports:,}</div><div class="sub">{unique_ips} 个主机响应</div></div>
<div class="sc y"><div class="lbl">WAF / 防护</div><div class="val">{len(waf_map)}</div><div class="sub">检测到防护特征</div></div>
<div class="sc r"><div class="lbl">高危端口</div><div class="val">{high_risk_count}</div><div class="sub">含 RDP/DB/Telnet</div></div>
<div class="sc p"><div class="lbl">RDP 暴露</div><div class="val">{sum(1 for r in rows if r["port"].startswith("3389"))}</div><div class="sub">端口 3389</div></div>
</div>
<div class="cg">
<div class="cc"><h3>📊 服务版本分布 Top 10</h3><div class="cw"><canvas id="vc"></canvas></div></div>
<div class="cc"><h3>🔌 开放端口分布 Top 10</h3><div class="cw"><canvas id="pc"></canvas></div></div>
</div>
<div class="sec">
<div class="sh"><h2>🛡️ WAF / 防护设备 <span style="font-size:.75rem;font-weight:400;color:var(--mt)">({len(waf_map)} 个 IP)</span></h2>
<div class="ctrl"><input class="si" id="ws" placeholder="搜索 IP / 类型..." oninput="ft('wt','ws','wc')"></div></div>
<div class="tw"><table id="wt">
<thead><tr><th onclick="st('wt',0)">IP 地址 ⇅</th><th onclick="st('wt',1)">防护类型 ⇅</th></tr></thead>
<tbody>{waf_rows_html}</tbody></table></div>
<div class="ci" id="wc">共 {len(waf_map)} 条记录</div>
</div>
<div class="sec">
<div class="sh"><h2>⚠️ 高危端口暴露 <span style="font-size:.75rem;font-weight:400;color:var(--mt)">({len(sens_rows)} 条)</span></h2>
<div class="ctrl">
<input class="si" id="ss" placeholder="搜索 IP / 端口..." oninput="ft('st2','ss','sc2')">
<select class="fs" onchange="fr(this.value)"><option value="">全部风险</option>
<option value="critical">严重</option><option value="high">高危</option>
<option value="medium">中危</option><option value="info">信息</option></select>
</div></div>
<div class="tw"><table id="st2">
<thead><tr><th onclick="st('st2',0)">IP 地址 ⇅</th><th onclick="st('st2',1)">端口 ⇅</th>
<th onclick="st('st2',2)">风险等级 ⇅</th><th onclick="st('st2',3)">版本指纹 ⇅</th></tr></thead>
<tbody>{sens_rows_html}</tbody></table></div>
<div class="ci" id="sc2">共 {len(sens_rows)} 条记录</div>
</div>
<div class="sec">
<div class="sh"><h2>📋 全部扫描结果 <span style="font-size:.75rem;font-weight:400;color:var(--mt)">({total_ports} 条)</span></h2>
<div class="ctrl">
<input class="si" id="ms" placeholder="搜索 IP / 端口 / 版本..." oninput="ft('mt','ms','mc')">
<select class="fs" onchange="fc('mt',2,this.value,'mc')"><option value="">全部服务</option>
<option value="http">http</option><option value="ssl">ssl/https</option>
<option value="ssh">ssh</option><option value="ms-wbt-server">RDP</option></select>
</div></div>
<div class="tw"><table id="mt">
<thead><tr><th onclick="st('mt',0)">IP 地址 ⇅</th><th onclick="st('mt',1)">端口 ⇅</th>
<th onclick="st('mt',2)">服务类型 ⇅</th><th onclick="st('mt',3)">版本指纹 ⇅</th></tr></thead>
<tbody>{all_rows_html}</tbody></table></div>
<div class="ci" id="mc">共 {total_ports} 条记录</div>
</div>
</div>
<script>
const C=['#4f46e5','#0891b2','#f59e0b','#ef4444','#22c55e','#8b5cf6','#fb923c','#34d399','#60a5fa','#f472b6'];
new Chart(document.getElementById('vc'),{{type:'bar',data:{{labels:{cv_labels},datasets:[{{label:'数量',data:{cv_data},backgroundColor:C,borderRadius:3,borderSkipped:false}}]}},options:{{responsive:true,maintainAspectRatio:false,plugins:{{legend:{{display:false}}}},scales:{{x:{{ticks:{{color:'#64748b',font:{{size:10}}}},grid:{{color:'rgba(0,0,0,.05)'}}}},y:{{ticks:{{color:'#64748b'}},grid:{{color:'rgba(0,0,0,.05)'}}}}}}}}}});
new Chart(document.getElementById('pc'),{{type:'bar',data:{{labels:{cp_labels},datasets:[{{label:'数量',data:{cp_data},backgroundColor:C.slice(2),borderRadius:3,borderSkipped:false}}]}},options:{{indexAxis:'y',responsive:true,maintainAspectRatio:false,plugins:{{legend:{{display:false}}}},scales:{{x:{{ticks:{{color:'#64748b'}},grid:{{color:'rgba(0,0,0,.05)'}}}},y:{{ticks:{{color:'#64748b',font:{{size:10}}}},grid:{{display:false}}}}}}}}}});
function ft(tid,iid,cid){{const q=document.getElementById(iid).value.toLowerCase(),rows=document.querySelectorAll('#'+tid+' tbody tr');let n=0;rows.forEach(r=>{{const m=r.textContent.toLowerCase().includes(q);r.style.display=m?'':'none';if(m)n++}});document.getElementById(cid).textContent='显示 '+n+' / 共 '+rows.length+' 条记录'}}
function fr(risk){{const rows=document.querySelectorAll('#st2 tbody tr');let n=0;rows.forEach(r=>{{const m=!risk||r.dataset.risk===risk;r.style.display=m?'':'none';if(m)n++}});document.getElementById('sc2').textContent='显示 '+n+' / 共 '+rows.length+' 条记录'}}
function fc(tid,col,val,cid){{const q=val.toLowerCase(),rows=document.querySelectorAll('#'+tid+' tbody tr');let n=0;rows.forEach(r=>{{const c=r.cells[col],m=!q||(c&&c.textContent.toLowerCase().includes(q));r.style.display=m?'':'none';if(m)n++}});document.getElementById(cid).textContent='显示 '+n+' / 共 '+rows.length+' 条记录'}}
const ss={{}};
function st(tid,col){{const t=document.getElementById(tid),b=t.querySelector('tbody'),rows=[...b.querySelectorAll('tr')];const k=tid+'_'+col,asc=ss[k]!==true;ss[k]=asc;rows.sort((a,b)=>{{const av=a.cells[col]?.textContent.trim()||'',bv=b.cells[col]?.textContent.trim()||'';const an=parseFloat(av),bn=parseFloat(bv);if(!isNaN(an)&&!isNaN(bn))return asc?an-bn:bn-an;return asc?av.localeCompare(bv):bv.localeCompare(av)}});rows.forEach(r=>b.appendChild(r))}}
</script>
</body></html>"""

with open(html_path, 'w', encoding='utf-8') as f:
    f.write(html)
print(f"[INFO] HTML 报告已生成: {html_path}", file=sys.stderr)
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
    local csv_buf=""
    while IFS= read -r match; do
        local port proto svc ver
        IFS='/' read -r port _ proto _ svc _ ver _ <<< "$match"
        ver="${ver:-unknown}"
        csv_buf+="$(printf '"%s","%s/%s","%s","%s"\n' "$ip" "$port" "$proto" "$svc" "$ver")"
        log INFO "[$idx/$total] [结果] $ip  $port/$proto  $svc  $ver"
        (( port_count++ )) || true
    done < <(echo "$nm_out" | grep "^Host:" | grep -oP '\d+/open/[^,\t ]+')

    [[ -n "$csv_buf" ]] && safe_append_raw "$RESULTS_FILE" "$csv_buf"
    [[ $port_count -eq 0 ]] && log WARN "[$idx/$total] $ip: nmap 未解析出服务（端口可能被过滤）"
    log INFO "[$idx/$total] $ip: nmap 完成，写入 $port_count 条记录"

    detect_waf "$ip" "$nm_out"
    safe_append "$COMPLETED_FILE" "$ip"
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
    echo " 结果文件: ${RESULTS_FILE%.csv}.html"
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

并行与模式:
  --parallel N      同时扫描 N 个 IP（默认 1，--fast 默认 5）
  --fast            快速模式（rate=10000, nmap -T4 -sS -Pn -n，并行5）
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
    local user_set_parallel=0

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --fast)     FAST_MODE=1; shift ;;
            --no-waf)   CHECK_WAF=0; shift ;;
            --parallel) PARALLEL="$2"; user_set_parallel=1; shift 2 ;;
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
        [[ $user_set_parallel -eq 0 ]] && PARALLEL=5
        log INFO "快速模式已启用（masscan rate=$MASS_RATE, nmap $NMAP_TIMING, 并行=$PARALLEL）"
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

    # 构建待扫描列表（并行模式下必须预加载，避免竞态）
    local -a pending_ips=()
    while IFS= read -r ip || [[ -n "$ip" ]]; do
        [[ -z "$ip" ]] && continue
        grep -qxF "$ip" "$COMPLETED_FILE" 2>/dev/null || pending_ips+=("$ip")
    done < "$TARGETS_FILE"
    local pending=${#pending_ips[@]}

    log INFO "总目标: $total | 已完成: $done_count | 待扫描: $pending | 并行数: $PARALLEL"

    # 写 PID
    echo $$ > "$PID_FILE"

    # 优雅退出
    cleanup() {
        INTERRUPTED=1
        log INFO "收到中断信号，正在保存进度..."
        local child_pids
        child_pids=$(jobs -rp 2>/dev/null || true)
        [[ -n "$child_pids" ]] && kill $child_pids 2>/dev/null || true
        wait 2>/dev/null || true
        rm -f "$PID_FILE"
        local cur_done
        cur_done=$(wc -l < "$COMPLETED_FILE")
        log INFO "已完成 ${cur_done}/${total}，续扫: sudo $0 $arg"
        csv_to_html "$RESULTS_FILE" 2>&1 || true
        exit 0
    }
    trap cleanup SIGINT SIGTERM

    # 主扫描循环
    local idx=0
    for ip in "${pending_ips[@]}"; do
        [[ $INTERRUPTED -eq 1 ]] && break
        (( idx++ )) || true

        if [[ $PARALLEL -le 1 ]]; then
            scan_ip "$ip" "$((done_count + idx))" "$total"
            if [[ $INTERRUPTED -eq 0 && $idx -lt $pending && $DELAY_MAX -gt 0 ]]; then
                local wait_sec
                wait_sec=$(( DELAY_MIN + RANDOM % (DELAY_MAX - DELAY_MIN + 1) ))
                log INFO "等待 ${wait_sec}s 后继续..."
                sleep "$wait_sec"
            fi
        else
            scan_ip "$ip" "$((done_count + idx))" "$total" &
            while (( $(jobs -rp | wc -l) >= PARALLEL )); do
                wait -n 2>/dev/null || true
            done
        fi
    done

    # 等待所有并行子任务完成
    if [[ $PARALLEL -gt 1 ]]; then
        log INFO "等待剩余并行任务完成..."
        wait 2>/dev/null || true
    fi

    rm -f "$PID_FILE"
    local final_done
    final_done=$(wc -l < "$COMPLETED_FILE")
    log INFO "==== 扫描完成 ===="
    print_summary "$total" "$final_done"
    csv_to_html "$RESULTS_FILE" 2>&1 | tee -a "$LOG_FILE" || true
    run_httpx
}

main "$@"
