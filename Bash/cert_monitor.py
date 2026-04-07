#!/usr/bin/env python3
"""
实时证书透明度监控脚本 (CertStream)
用于零延迟监控新签署的 HTTPS 证书并写入 DB。
"""

import sys
import os
import re
import sqlite3

try:
    import certstream
except ImportError:
    print("缺少 certstream 模块，请执行: pip3 install certstream")
    sys.exit(1)

def get_db():
    db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "db", "recon.db")
    if not os.path.exists(db_path):
        import traceback
        return None
    conn = sqlite3.connect(db_path)
    return conn

def start_monitor(target_keyword):
    print(f"[*] 正在后台实时监听 CertStream 证书透明度网络...")
    print(f"[*] 匹配条件: {target_keyword}")
    escaped = re.escape(target_keyword)
    
    # 兼容顶级域和纯企业名关键字匹配
    pattern = re.compile(rf'({escaped}|{target_keyword.replace(".", "")})', re.IGNORECASE)

    def callback(message, context):
        if message['message_type'] == 'certificate_update':
            domains = message['data']['leaf_cert']['all_domains']
            for domain in domains:
                if pattern.search(domain):
                    print(f" \033[1;32m[NEW CERT]\033[0m {domain}")
                    conn = get_db()
                    if conn:
                        try:
                            # 入库并触发去重与「未读」高亮
                            conn.execute("""
                                INSERT INTO certs (domain, target_domain, last_seen) 
                                VALUES (?, ?, CURRENT_TIMESTAMP)
                                ON CONFLICT(domain) DO UPDATE SET last_seen=CURRENT_TIMESTAMP
                            """, (domain, target_keyword))
                            conn.commit()
                        except Exception as e:
                            print(f"[!] DB Error: {e}")
                        finally:
                            conn.close()

    try:
        certstream.listen_for_events(callback, url='wss://certstream.calidog.io/')
    except KeyboardInterrupt:
        print("[*] 监控终止。")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python3 cert_monitor.py <target_keyword_or_domain>")
        print("建议配合 tmux 或 nohup 在后台常驻运行。")
        sys.exit(1)
    
    start_monitor(sys.argv[1])
