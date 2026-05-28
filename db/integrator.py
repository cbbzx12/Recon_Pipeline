#!/usr/bin/env python3
"""
integrator.py — 数据驱动情报流水线引擎
覆盖：存活子域名、端口情况、JS、URL。
"""

import json, sqlite3, os, sys, argparse

class DataDrivenIntegrator:
    def __init__(self, db_path: str):
        if not os.path.exists(db_path):
            print(f"[!] 数据库 {db_path} 不存在，请先执行: python init_db.py")
            sys.exit(1)
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("PRAGMA foreign_keys = ON;")
        self.cur = self.conn.cursor()

    def integrate_subdomains(self, path: str):
        if not os.path.exists(path): return
        count = 0
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                domain = line.strip().lower().rstrip('.')
                if not domain or domain.startswith('#'): continue
                self.cur.execute("""
                    INSERT INTO domain_records (domain, source, is_live, last_seen) 
                    VALUES (?, 'merged-list', 1, CURRENT_TIMESTAMP)
                    ON CONFLICT(domain) DO UPDATE SET is_live=1, last_seen=CURRENT_TIMESTAMP
                """, (domain,))
                count += 1
        self.conn.commit()
        print(f"  [+] (子域名) 去重入库: {count} 条 <- {path}")

    def integrate_httpx_json(self, path: str):
        if not os.path.exists(path): return
        count = 0
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                try: r = json.loads(line.strip())
                except: continue

                domain = r.get('host', '').split(':')[0].lower()
                if not domain: continue
                
                ips = r.get('a', [])
                ip = ips[0] if ips else None
                is_cdn = 1 if r.get('cdn', False) else 0
                cdn_name = r.get('cdn-name', '')

                if ip:
                    ip_memo = f"[CDN Node] {cdn_name}" if is_cdn else ""
                    self.cur.execute("""
                        INSERT INTO ips (ip, memo, last_seen) VALUES (?, ?, CURRENT_TIMESTAMP) 
                        ON CONFLICT DO UPDATE SET memo=excluded.memo, last_seen=CURRENT_TIMESTAMP
                    """, (ip, ip_memo))
                    
                self.cur.execute("""
                    INSERT INTO domain_records (domain, resolved_ip, is_live, source, is_cdn, cdn_name, last_seen) 
                    VALUES (?, ?, 1, 'httpx', ?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(domain) DO UPDATE SET 
                        resolved_ip=excluded.resolved_ip, is_live=1, is_cdn=excluded.is_cdn,
                        cdn_name=excluded.cdn_name, last_seen=CURRENT_TIMESTAMP
                """, (domain, ip if ip else "", is_cdn, cdn_name))
                
                count += 1
        self.conn.commit()
        print(f"  [+] (子域名) 去重入库: {count}条 <- {path}")

    def integrate_port_csv(self, path: str):
        if not os.path.exists(path): return
        count = 0
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line: continue
                # 跳过表头
                if line.startswith('"IP"') or line.startswith('IP,'): continue
                parts = [p.strip().strip('"') for p in line.split(',')]
                if len(parts) < 2: continue
                ip = parts[0]
                port_proto = parts[1]   # "8080/tcp" 或 "8080"
                svc = parts[2] if len(parts) > 2 else ''
                ver = parts[3] if len(parts) > 3 else ''
                port_str = port_proto.split('/')[0]
                proto = port_proto.split('/')[1] if '/' in port_proto else 'tcp'
                try:
                    port_int = int(port_str)
                except ValueError:
                    continue
                self.cur.execute(
                    "INSERT INTO ips (ip, last_seen) VALUES (?, CURRENT_TIMESTAMP) "
                    "ON CONFLICT DO UPDATE SET last_seen=CURRENT_TIMESTAMP", (ip,))
                self.cur.execute("""
                    INSERT INTO services (ip, port, protocol, service, version, last_seen)
                    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(ip, port, protocol) DO UPDATE SET
                        service=excluded.service,
                        version=excluded.version,
                        last_seen=CURRENT_TIMESTAMP
                """, (ip, port_int, proto, svc, ver))
                count += 1
        self.conn.commit()
        print(f"  [+] (端口扫描) 去重入库: {count} 条 <- {path}")

    def integrate_js_urls(self, path: str, target: str):
        if not os.path.exists(path): return
        count = 0
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                url = line.strip()
                if not url: continue
                self.cur.execute("""
                    INSERT INTO js_files (url, target_domain, last_seen) 
                    VALUES (?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(url) DO UPDATE SET last_seen=CURRENT_TIMESTAMP
                """, (url, target))
                count += 1
        self.conn.commit()
        print(f"  [+] (JS) 前端JS去重入库: {count} 条 <- {path}")

    def integrate_url_paths(self, path: str, target: str):
        if not os.path.exists(path): return
        count = 0
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                url = line.strip()
                if not url: continue
                self.cur.execute("""
                    INSERT INTO url_paths (url, target_domain, last_seen) 
                    VALUES (?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(url) DO UPDATE SET last_seen=CURRENT_TIMESTAMP
                """, (url, target))
                count += 1
        self.conn.commit()
        print(f"  [+] (历史 URL) URL去重入库: {count} 条 <- {path}")

    def close(self): self.conn.close()

def main():
    parser = argparse.ArgumentParser(description='数据驱动 Pipeline 资产入库模块')
    parser.add_argument('--db',        required=True,  help='SQLite 数据库路径')
    parser.add_argument('--target',    default="unknown", help='目标项目标签')
    parser.add_argument('--subfinder', default=None,   help='存活子域名 .txt')
    parser.add_argument('--httpx',     default=None,   help='httpx -json 输出')
    parser.add_argument('--port-csv',  default=None,   help='3_port_scan.sh 产出的 results.csv')
    parser.add_argument('--js',        default=None,   help='clean_js.txt 路径')
    parser.add_argument('--urls',      default=None,   help='all_urls.txt 路径')
    args = parser.parse_args()

    db = DataDrivenIntegrator(args.db)

    if args.subfinder:  db.integrate_subdomains(args.subfinder)
    if args.httpx:      db.integrate_httpx_json(args.httpx)
    if args.port_csv:   db.integrate_port_csv(args.port_csv)
    if args.js:         db.integrate_js_urls(args.js, args.target)
    if args.urls:       db.integrate_url_paths(args.urls, args.target)

    db.close()
    print("[+] Pipeline 数据精准入库完毕。")

if __name__ == "__main__":
    main()
