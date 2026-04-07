# 侦察引擎 API 与核心配置检查单

根据你 `Discovery/` 目录中集成的高阶工具栈，以下为**明确需要、或强烈建议**配置 API Key / Token 才能释放完全战斗力的组件清单。

## 1. 必配：横向核心打点引擎 (资产爆发池)

横向探测极度依赖第三方 OSINT 接口，若不配 API，不仅扫描速度受限，而且至少错失 40% 的深水区边缘资产（尤其是有 CNAME 或解析废弃的野资产）。

*   **Subfinder** (`subdomain_enum.sh` 后台主力调用)
    *   **配置文件路径**: `~/.config/subfinder/provider-config.yaml`
    *   **高优先级 API**: SecurityTrails, Shodan, Censys, VirusTotal, Chaos, GitHub, AlienVault。
*   **OneForAll** (`Discovery/subdomain/OneForAll`)
    *   **配置文件路径**: `Discovery/subdomain/OneForAll/config/api.py`
    *   **高优先级 API**: FOFA, Shodan, ZoomEye, SecurityTrails (重中之重), VirusTotal (重中之重), BinaryEdge。
*   **水泽 ShuiZe_0x727** (`Discovery/subdomain/ShuiZe_0x727`)
    *   **配置文件路径**: `Discovery/subdomain/ShuiZe_0x727/iniFile/config.ini`
    *   **高优先级 API**: FOFA, FOFA Email, Hunter (鹰图), Quake (360), 以及可能配置的微步在线。

## 2. 补强：纵向收割与内容提取 (防频控降维打击)

历史库拉取和爬虫在没有 Token 授权状态下极易遭遇 Rate Limit / 403 / 验证码 拦截。

*   **Gau** (`01_harvest_Ultimate.sh` 阶段 1 中调用)
    *   **配置文件路径**: `~/.gau.toml`
    *   **建议配置 API**: URLScan (当目标反感 CommonCrawl 或屏蔽 Wayback 节点时，URLScan 常有奇效)。
*   **Katana** (`01_harvest_Ultimate.sh` 阶段 3 中调用)
    *   **配置文件路径**: `~/.config/katana/provider-config.yaml`
    *   **建议配置 API**: GitHub Token。允许 Katana 以授权身份在爬取过程中直接检索存放在 GitHub 的相关源码提取端点和 JS。
*   **Gitleaks** (`Discovery/Git/gitleaks`)
    *   **配置方式**: 运行前终端临时挂载 `export GITHUB_TOKEN="ghp_xxxx..."`
    *   **适用场景**: 当通过 `gitleaks` 探测目标的 GitHub Organization 或开发人员的 Remote 仓库池时，Token 能豁免原生 API 的频次熔断机制。

## 3. 选配：持久化寻线与监控告警 

涉及你的 `monitor_all.py` / `monitor.sh` 执行后，若产生新增资产 (diff)，需回调通知的 Webhook 凭证。

*   **Notify** (基于 ProjectDiscovery 生态的告警中继)
    *   **配置文件路径**: `~/.config/notify/provider-config.yaml`
    *   **配置内容**: 写入你的 飞书 (Feishu) / 钉钉 (DingTalk) / 企微 (WeChat) / Server酱 的 Bot Webhook Token。
    *   **联动**: 在 `monitor.sh` 后缀加上 `| notify -id feishu` 即可送达手机终端。
*   **Chaos Client** (持续安全监控子域流)
    *   vim ~/.config/chaos/config.yaml
    *   **配置方式**: `export CHAOS_KEY="your-chaos-key"`。
