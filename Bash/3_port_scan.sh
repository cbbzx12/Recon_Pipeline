#!/bin/bash
# ==========================================
# 自动化端口扫描: Masscan -> Nmap -> httpx
# ==========================================

# === 目录与项目配置 ===
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT_DIR=$(dirname "$SCRIPT_DIR")
OUTPUT_ROOT="$ROOT_DIR/Output"

TARGET_FILE="$1"

if [ -z "$TARGET_FILE" ]; then
    echo "用法: $0 <ips.txt>"
    echo "请提供一个包含目标 IP 或 CIDR 的文本文件。"
    exit 1
fi

# 自动推导 WORKSPACE 路径 (从 Output/domain/date/ports/real_ips.txt 向上翻两级)
WORKSPACE=$(dirname "$(dirname "$TARGET_FILE")")
if [[ "$WORKSPACE" != "$OUTPUT_ROOT"* ]]; then
    # 兼容性处理：如果传入的不是标准 Output 路径，尝试从根目录推导
    WORKSPACE="$OUTPUT_ROOT/workspace_manual"
fi
OUTPUT_DIR="$WORKSPACE/ports"
mkdir -p "$OUTPUT_DIR/nmap"
cd "$OUTPUT_DIR" || exit

echo "[*] =========================================="
echo "[*] 阶段 1：使用 Masscan 快速发现端口"
echo "[*] =========================================="
# 限制 rate 为 5000 左右是一个相对安全的适中值，可防止目标网络拥塞或 IP 被封杀
masscan -p1-65535 -iL "$TARGET_FILE" \
  --rate=5000 \
  --exclude 255.255.255.255 \
  -oG masscan_all.gnmap

echo ""
echo "[*] =========================================="
echo "[*] 阶段 2：提取 主机:端口 的对应关系"
echo "[*] =========================================="
# 使用 Python 解析 Masscan 输出，生成精确的 主机和开放端口 映射
python3 - << 'EOF'
import re

hosts = {}
with open("masscan_all.gnmap") as f:
    for line in f:
        m = re.search(r'Host: (\S+).*Ports: ([\d,/a-z ]+)', line)
        if m:
            host = m.group(1)
            ports = re.findall(r'(\d+)/open', m.group(2))
            if host not in hosts:
                hosts[host] = set()
            hosts[host].update(ports)

with open("host_ports.txt", "w") as f:
    for host, ports in hosts.items():
        f.write(f"{host}:{','.join(sorted(ports, key=int))}\n")
EOF
echo "[+] 映射文件 host_ports.txt 生成完毕。"

echo ""
echo "[*] =========================================="
echo "[*] 阶段 3：针对开放端口运行精准 Nmap 扫描"
echo "[*] =========================================="
# 仅对 Masscan 发现的存活端口运行 Nmap 服务识别和脚本扫描
while IFS=: read host ports; do
  echo "[-] 正在深度扫描主机: $host, 目标端口: $ports"
  nmap -sV --version-intensity 5 -sC -p "$ports" \
    --open -T4 -Pn "$host" \
    -oA "nmap_${host//\./_}" 2>/dev/null
done < host_ports.txt

echo ""
echo "[*] =========================================="
echo "[*] 阶段 4：提取 HTTP 服务并对接 Web 扫描"
echo "[*] =========================================="
# 解析 Nmap 的 XML 输出，容错提取所有 Web 服务 (HTTP/HTTPS/未知)
python3 -c "
import xml.etree.ElementTree as ET
import glob
import sys

# 默认常见的 Web 端口，即使服务名识别不出来也提取
web_ports = {'80', '443', '8080', '8443', '8000', '8888', '8081', '7001', '9000', '9090'}

for xml_file in glob.glob('nmap_*.xml'):
    try:
        tree = ET.parse(xml_file)
        for host in tree.findall('.//host'):
            addr_elem = host.find('.//address')
            if addr_elem is None: continue
            addr = addr_elem.get('addr')
            
            for port in host.findall('.//port'):
                if port.find('state').get('state') == 'open':
                    portid = port.get('portid')
                    service = port.find('service')
                    service_name = service.get('name', '').lower() if service is not None else ''
                    
                    # 策略：只要包含 http，或者是默认 Web 端口，或者是 unknown，全都提取交给 httpx 验证
                    if 'http' in service_name or portid in web_ports or service_name == 'unknown':
                        print(f'{addr}:{portid}')
    except Exception as e:
        print(f'[!] XML解析异常 {xml_file}: {e}', file=sys.stderr)
" | sort -u > http_services.txt

TOTAL_WEB=$(wc -l < http_services.txt)
echo "[+] 提取完成，共发现 $TOTAL_WEB 个潜在 Web 服务。"

# 移交给 httpx 进行批量存活确认和框架探测
if [ -s http_services.txt ]; then
    echo "[-] 启动 httpx 探测..."
    mkdir -p "$WORKSPACE/http"
    httpx -l http_services.txt -silent -title -status-code -tech-detect -timeout 10 -retries 2 -j -o "$WORKSPACE/http/httpx_ports.json" | tee "$WORKSPACE/http/live_urls.txt"
else
    echo "[-] 未发现明确的 HTTP 服务。"
fi

cd - > /dev/null

echo ""
echo "[+] 全流程扫描结束！"

