# Recon Pipeline

[![Platform](https://img.shields.io/badge/Platform-Linux-blue.svg)](https://github.com/)
[![Language](https://img.shields.io/badge/Language-Bash%20%2F%20Python-orange.svg)](https://github.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](https://github.com/)

基于 SQLite 的自动化漏洞挖掘与资产监控数据存储/展示套件。此工具链将红蓝对抗中的各类信息搜集工具（如 Subfinder, OneForAll, httpx, arjun 等）整合流水线，直接驱动可视化审计面板。


## 目录结构

主要项目结构包含执行部署后的所有字典与组件挂载路径，如下所示：

```text
.
├── API配置检查单.md       # 推荐配置的 API 密钥等检查配置
├── README.md             # 使用向导文档
├── db/                   # 侦察系统 SQLite 数据库集群存放目录
│   └── recon.db          # 核心资产漏洞数据库引擎
├── Bash/                 # 侦察业务执行引擎 (自动化核心脚本)
│   ├── setup.sh          # 【最优先】用于一键安装所有配套工具、初始化下述扩展目录
│   ├── auto_run.sh       # [无人值守] 多项目一键队列自动巡航扫描入口
│   ├── target.txt        # [队列清单] 自动巡航的目标域配置文件
│   ├── 1_subdomain_enum.sh   # [阶段 0] 子域名收集与 httpx 探活验证 
│   ├── 2_bridge.sh           # [防封调度] DNS解析、智能 CDN 清洗与网段切分
│   ├── 3_port_scan.sh        # [阶段 0.5] 非标端口发现、Web服务嗅探与指纹分析
│   ├── 4_harvest_Ultimate.sh # [阶段 1] URL、目录接口、敏感 JS 文件捕获
│   ├── 5_import_to_db.sh     # 入库持久化 (将 Output 中结果统一整合)
│   └── cert_monitor.py       # (功能挂机) 不间断的透明度证书网络新资产截获模块
├── Output/               # 所有扫描资产的落地输出空间 (执行流落盘点)
│   └── <项目名称>/latest/  # 每个独立目标下按日期归档的工作流文件夹
├── subdomain/            # [由 setup 建立] 子域名字典集、OneForAll 与水泽环境
├── JS/                   # [由 setup 建立] 信息收集与 JS 指纹提取引擎 (含 js_match.py)
├── Content/              # [由 setup 建立] 目录爆破级高频优质词表与工具链
├── Port/                 # [由 setup 建立] 端口利用套件、Masscan 配置文件等
├── Parameter/            # [由 setup 建立] Arjun 隐式参数发掘配置挂载点
└── Git/                  # [由 setup 建立] Gitleaks 等凭证猎捕工具存放点
```

*(注：`integrator.py`, `init_db.py`, `web_ui.py` 请直接部署于当前根目录。)*

---

## 安装与部署指南

强烈推荐在 **Ubuntu/Kali/Debian** 环境中进行运行。环境脚本会自动为你接管所有底层依赖：

```bash
# 1. 克隆代码仓库
git clone https://github.com/YourName/ReconPipeline.git
cd ReconPipeline/Bash

# 2. 授予安装脚本执行权限
chmod +x setup.sh

# 3. 运行基础环境安装（一键拉取原生二进制安全组件及 Python venv）
./setup.sh
# （注：安装过程为交互式，若探测到 Go 版本过低会提示询问是否升级）
```

> **[建议]** 安装完毕后，请遵循本目录下的 `API配置检查单.md` 配置相应的第三方 API 接口凭证，以确保工作流的检出率。

---

## 业务流水线与运行模式

本系统已整合各节点工具产出的日志，支持执行以下两种运行模式：**一键全栈自动化** 和 **分步独立执行**。

### 模式 A：一键全栈自动化

按照目标文件设定参数，可自动完成流水线调用与数据库写入编排。

1. **编辑目标列表**: 配置 `Bash/target.txt`，每行代表一个独立项目。

   ```text
   # 首个域名为主要项目名，其余同属项目的域用空格追加在后面
   target.com target.cn
   example.org
   ```

2. **启动挂机引擎**: 运行总控调度脚本或加入 `crontab` 定时任务。

   ```bash
   cd Bash
   ./auto_run.sh
   ```

执行完毕后，面板会自动载入聚合后的业务模型数据。

---

### 模式 B：分步独立调用

适用于对单一目标快速复测某一特定阶段的场景。各关联脚本会自动识别相同的目录结构：

1. **阶段 0：启动子域枚举**

   ```bash
   Bash/1_subdomain_enum.sh <项目名称>
   ```

2. **阶段 0.5：探活与指纹收集**
   *(由于脚本内部逻辑依赖，可直接使用 `2_bridge.sh` 转接，或独立调用 `3_port_scan.sh`)*
3. **阶段 1：收割路由与历史接口**

   ```bash
   Bash/4_harvest_Ultimate.sh <项目名称>
   ```

4. **一键落库（单项目收尾）**
   当某个项目的所有单项环节都跑完后，你可以独立执行这个动作：

   ```bash
   Bash/5_import_to_db.sh <项目名称>
   ```

只要跑完入库，就可以通过面板 `web_ui.py` 一览战果了。

---

## 增量监控及 Web 面板

如需建立企业级定时重跑监测任务，可设置 Cron Job：基于 Linux 原生指令（如 `comm -23`）生成新旧快照变动。

```bash
# 挂载增量资产并推入人工审查队列
python integrator.py --db recon.db \
  --delta diff_subdomains.txt \
  --delta-type subdomain

# 启动 Web 面板
python web_ui.py
# 浏览器访问 127.0.0.1:8080 进入资产大盘处理待判定资产
```
