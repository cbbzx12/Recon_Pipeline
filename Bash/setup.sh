#!/bin/bash
# ====================================================
# Red Teaming / Bug Bounty 环境自动化构建脚本
# 适用系统: Debian/Ubuntu/Kali Linux
# ====================================================

# 设定基础目录（自动定位到当前脚本的上级目录，即 GitHub 仓库根目录）
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "[+] 检测到当前项目根目录: $BASE_DIR"

mkdir -p "$BASE_DIR"/{Content,Git,JS,Output,Parameter,Port,subdomain,Sum}
mkdir -p "$BASE_DIR/Bash/logs"
mkdir -p "$BASE_DIR/JS/secretfinder"
mkdir -p "$BASE_DIR/Port/masscan"
mkdir -p "$BASE_DIR/subdomain/massdns"

# ====================================================
# 1. 基础系统依赖安装 (System Dependencies)
# ====================================================
echo "[+] 更新系统包并安装基础运行环境..."
# 关键逻辑注释：强制启用 DEBIAN_FRONTEND=noninteractive 避免安装 tzdata 等包时弹窗导致脚本永久挂起
export DEBIAN_FRONTEND=noninteractive
sudo -E apt-get update -y
sudo -E apt-get install -y git wget curl unzip jq make gcc libpcap-dev nmap masscan dnsutils \
    python3 python3-pip python3-venv ruby ruby-dev libcurl4-openssl-dev libssl-dev pipx

# ====================================================
# 2. Go 环境配置与工具链安装 (Go Toolchain)
# ====================================================
INSTALL_GO=false

if command -v go >/dev/null 2>&1; then
    CURRENT_GO_VER=$(go version | awk '{print $3}' | sed 's/go//')
    if dpkg --compare-versions "$CURRENT_GO_VER" "ge" "1.25"; then
        echo "[+] 检测到现有 Go 版本 ($CURRENT_GO_VER) >= 1.25，结构符合要求。"
    else
        echo -e "\e[1;33m[-] 检测到现有 Go 版本 ($CURRENT_GO_VER) 低于 1.25，可能会导致部分安全工具编译失败。\e[0m"
        read -p "[?] 是否升级 Go 到最新的稳定版 1.26？(y/N): " UPGRADE_CHOICE
        if [[ "$UPGRADE_CHOICE" =~ ^[Yy]$ ]]; then
            INSTALL_GO=true
        else
            echo "[*] 已跳过 Go 环境升级。"
        fi
    fi
else
    echo -e "\e[1;31m[-] 致命：未检测到基础系统 Go 开发环境！\e[0m"
    echo "[-] Red Teaming 工具链极度依赖 Go，如果跳过将导致核心模块瘫痪。"
    read -p "[?] 是否立即自动下载安装 Go 1.26 环境？(Y/n): " INSTALL_CHOICE
    if [[ ! "$INSTALL_CHOICE" =~ ^[Nn]$ ]]; then
        INSTALL_GO=true
    else
        echo -e "\e[1;33m[!] 注意：你拒绝了安装 Go，后续的 pdtm 及其安全生态链可能直接报错退出！\e[0m"
    fi
fi

if [ "$INSTALL_GO" = true ]; then
    echo "[*] 开始清理旧版 Go 环境..."
    sudo apt-get remove -y golang-go 2>/dev/null
    sudo apt-get autoremove -y 2>/dev/null
    sudo rm -rf /usr/local/go

    echo "[*] 下载并安装 Go 1.26.1..."
    wget -qO /tmp/go1.26.1.linux-amd64.tar.gz https://go.dev/dl/go1.26.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf /tmp/go1.26.1.linux-amd64.tar.gz
    rm /tmp/go1.26.1.linux-amd64.tar.gz

    echo "[*] 配置全局环境变量 (Environment Variables)..."
    echo 'export GOROOT=/usr/local/go' | sudo tee /etc/profile.d/go.sh > /dev/null
    echo 'export GOPATH=$HOME/go' | sudo tee -a /etc/profile.d/go.sh > /dev/null
    echo 'export PATH=$PATH:$GOROOT/bin:$GOPATH/bin' | sudo tee -a /etc/profile.d/go.sh > /dev/null
    sudo chmod +x /etc/profile.d/go.sh
fi

export GOROOT=/usr/local/go
export GOPATH=$HOME/go
export PATH=$PATH:$GOROOT/bin:$GOPATH/bin

echo "[*] 开始通过 原生 Go 环境 (go install) 部署安全工具链..."

echo "[-] 安装 ProjectDiscovery 核心生态..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

echo "[-] 安装 URL 收割与其他辅助工具..."
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/d3mondev/puredns/v2@latest
# ====================================================
# 3. 核心工具安装 (C/C++/Rust 二进制)
# ====================================================
echo "[+] 安装 MassDNS (puredns 依赖)..."
if [ ! -f "/usr/local/bin/massdns" ]; then
    git clone https://github.com/blechschmidt/massdns.git /tmp/massdns
    cd /tmp/massdns && make && sudo cp bin/massdns /usr/local/bin/
    cd - >/dev/null
    rm -rf /tmp/massdns
fi

echo "[+] 安装 Feroxbuster..."
if [ ! -f "/usr/local/bin/feroxbuster" ]; then
    curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash
    sudo mv feroxbuster /usr/local/bin/
fi

echo "[+] 安装 x8 (Hidden Parameter Discovery)..."
if [ ! -f "/usr/local/bin/x8" ]; then
    mkdir -p /tmp/x8_extract
    # 添加文件大小校验 (-s)，只有成功下载且文件非空时才执行解压
    wget -qO /tmp/x8.tar.gz https://github.com/shmilylty/x8/releases/download/v4.3.0/x8-linux-amd64.tar.gz
    
    if [ -s "/tmp/x8.tar.gz" ]; then
        tar -zxvf /tmp/x8.tar.gz -C /tmp/x8_extract
        sudo find /tmp/x8_extract -type f -name "x8" -exec mv {} /usr/local/bin/x8 \;
        echo "[+] x8 部署成功。"
    else
        echo "[-] x8 下载失败(网络或代理问题)，跳过该工具安装。"
    fi
    rm -rf /tmp/x8.tar.gz /tmp/x8_extract
fi

# ====================================================
# 4. Python 环境与工具部署 (Python Tools)
# ====================================================
echo "[+] 使用 pipx 隔离安装 Python 独立命令行工具..."
pipx ensurepath
export PATH=$PATH:$HOME/.local/bin
pipx install dirsearch
pipx install arjun
pipx install git+https://github.com/xnl-h4ck3r/xnLinkFinder.git

# 关键逻辑注释：对大型工程采用 python3 -m venv 创建独立环境，彻底阻断依赖冲突 (Dependency Conflict)
echo "[+] 部署大型 Python 渗透工程 (启用独立虚拟环境)..."

# OneForAll 部署
if [ ! -d "$BASE_DIR/subdomain/OneForAll" ]; then
    echo "[-] 拉取 OneForAll..."
    git clone https://gitee.com/shmilylty/OneForAll.git "$BASE_DIR/subdomain/OneForAll"
    python3 -m venv "$BASE_DIR/subdomain/OneForAll/venv"
    "$BASE_DIR/subdomain/OneForAll/venv/bin/pip" install -r "$BASE_DIR/subdomain/OneForAll/requirements.txt"
fi

# ShuiZe_0x727 部署
if [ ! -d "$BASE_DIR/subdomain/ShuiZe_0x727" ]; then
    echo "[-] 拉取 ShuiZe_0x727..."
    git clone https://github.com/0x727/ShuiZe_0x727.git "$BASE_DIR/subdomain/ShuiZe_0x727"
    python3 -m venv "$BASE_DIR/subdomain/ShuiZe_0x727/venv"
    "$BASE_DIR/subdomain/ShuiZe_0x727/venv/bin/pip" install -r "$BASE_DIR/subdomain/ShuiZe_0x727/requirements.txt"
    chmod 777 "$BASE_DIR/subdomain/ShuiZe_0x727/iniFile"/* 2>/dev/null
fi

# Packer-InfoFinder 部署
if [ ! -d "$BASE_DIR/JS/Packer-InfoFinder" ]; then
    echo "[-] 拉取 Packer-InfoFinder..."
    git clone https://github.com/TFour123/Packer-InfoFinder.git "$BASE_DIR/JS/Packer-InfoFinder"
    python3 -m venv "$BASE_DIR/JS/Packer-InfoFinder/venv"
    "$BASE_DIR/JS/Packer-InfoFinder/venv/bin/pip" install -r "$BASE_DIR/JS/Packer-InfoFinder/requirements.txt"
fi

touch "$BASE_DIR/JS/js_match.py"

# ====================================================
# 5. 字典集与 Payload (Wordlists)
# ====================================================
echo "[+] 下载所需的高质量字典..."

wget -qO "$BASE_DIR/subdomain/resolvers.txt" https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt
wget -qO "$BASE_DIR/subdomain/resolvers-trusted.txt" https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt

if [ ! -f "$BASE_DIR/subdomain/best-dns-wordlist.txt" ]; then
    wget -qO "$BASE_DIR/subdomain/best-dns-wordlist.txt" https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt
fi

if [ ! -f "$BASE_DIR/Content/raft-large-directories.txt" ]; then
    wget -qO "$BASE_DIR/Content/raft-large-directories.txt" https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt
fi
if [ ! -f "$BASE_DIR/Content/raft-large-files.txt" ]; then
    wget -qO "$BASE_DIR/Content/raft-large-files.txt" https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-files.txt
fi

# ====================================================
# 6. 权限赋予与环境收尾
# ====================================================
echo "[+] 赋予自定义 Shell 脚本执行权限..."
find "$BASE_DIR/Bash" -type f -name "*.sh" -exec chmod +x {} \;

echo -e "\n[+] 部署完成! \n目录已构建在: $BASE_DIR"
echo "[!] 注意: 调用大型 Python 工具时，请使用其专属 venv 的 Python 解释器。例如："
echo "    $BASE_DIR/subdomain/OneForAll/venv/bin/python3 oneforall.py"
echo "[+] 请执行 'source /etc/profile.d/go.sh && source ~/.bashrc' (或 zshrc) 以使全局环境变量生效。"