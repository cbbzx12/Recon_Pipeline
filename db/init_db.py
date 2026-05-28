import sqlite3
import os

DB_PATH = "recon.db"

def init_db():
    if os.path.exists(DB_PATH):
        print(f"[*] 数据库 {DB_PATH} 已存在，删除重建...")
        os.remove(DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON;")
    cur = conn.cursor()

    # 1. 目标与基础资产
    cur.execute('''CREATE TABLE targets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE NOT NULL,
        program_name TEXT,
        in_scope BOOLEAN DEFAULT 1,
        added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        is_new BOOLEAN DEFAULT 1
    )''')

    cur.execute('''CREATE TABLE domain_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE NOT NULL,
        resolved_ip TEXT,
        is_live BOOLEAN DEFAULT 0,
        source TEXT,
        is_cdn BOOLEAN DEFAULT 0,
        cdn_name TEXT,
        attack_value INTEGER DEFAULT 0,
        exposure_surface TEXT,
        is_entry_point BOOLEAN DEFAULT 0,
        first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_seen DATETIME,
        is_new BOOLEAN DEFAULT 1
    )''')

    cur.execute('''CREATE TABLE ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE NOT NULL,
        memo TEXT,
        first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_seen DATETIME,
        is_new BOOLEAN DEFAULT 1
    )''')

    cur.execute('''CREATE TABLE services (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        port INTEGER NOT NULL,
        protocol TEXT DEFAULT 'tcp',
        service TEXT DEFAULT '',
        version TEXT DEFAULT '',
        first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_seen DATETIME,
        is_new BOOLEAN DEFAULT 1,
        UNIQUE(ip, port, protocol)
    )''')

    conn.commit()
    conn.close()
    print("[+] 数据库表结构初始化完成！")

if __name__ == '__main__':
    init_db()
