import os
import sqlite3
from flask import Flask, render_template, jsonify, request

app = Flask(__name__)
DB_PATH = "recon.db"

def upgrade_schema():
    if not os.path.exists(DB_PATH): return
    conn = sqlite3.connect(DB_PATH)
    try:
        for col, definition in [('service', 'TEXT DEFAULT ""'), ('version', 'TEXT DEFAULT ""')]:
            try:
                conn.execute(f"ALTER TABLE services ADD COLUMN {col} {definition}")
            except Exception:
                pass
        conn.execute('''CREATE TABLE IF NOT EXISTS js_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE NOT NULL,
            target_domain TEXT,
            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen DATETIME,
            is_new BOOLEAN DEFAULT 1
        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS url_paths (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE NOT NULL,
            target_domain TEXT,
            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen DATETIME,
            is_new BOOLEAN DEFAULT 1
        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS certs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE NOT NULL,
            target_domain TEXT,
            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen DATETIME,
            is_new BOOLEAN DEFAULT 1
        )''')
        conn.commit()
    except Exception as e:
        print(f"Schema upgrade error: {e}")
    finally:
        conn.close()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/stats')
def api_stats():
    if not os.path.exists(DB_PATH):
        return jsonify({"error": "DB not found"}), 404
        
    conn = get_db()
    stats = {}
    
    tables = {
        'targets': '监控项目',
        'domain_records': '存活子域名',
        'ips': '解析的主机 IP',
        'services': '探测开放端口',
        'js_files': '监控的前端 JS',
        'url_paths': '发现的 URL 路径',
        'certs': '签发的实时证书',
    }
    
    for table, label in tables.items():
        try:
            count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            new_count = conn.execute(f"SELECT COUNT(*) FROM {table} WHERE is_new = 1").fetchone()[0]
            stats[table] = {"label": label, "count": count, "new_count": new_count}
        except Exception as e:
            stats[table] = {"label": label, "count": 0, "new_count": 0}

    conn.close()
    return jsonify(stats)

@app.route('/api/chain')
def api_chain():
    if not os.path.exists(DB_PATH): return jsonify([])
    conn = get_db()
    keyword = request.args.get('q', '')
    where = "1=1"
    params = []
    if keyword:
        where = "(d.domain LIKE ? OR i.ip LIKE ? OR s.port LIKE ?)"
        params = [f"%{keyword}%", f"%{keyword}%", f"%{keyword}%"]
    
    rows = conn.execute(f"""
        SELECT 
            d.domain, d.is_new AS is_new_domain, i.ip, d.is_cdn, d.cdn_name,
            (SELECT GROUP_CONCAT(s.port || '/' || COALESCE(NULLIF(s.service,''),'?') || CASE WHEN s.is_new = 1 THEN '#NEW' ELSE '' END, ', ') FROM services s WHERE s.ip = i.ip) AS ports_raw
        FROM domain_records d
        LEFT JOIN ips i ON i.ip = d.resolved_ip
        WHERE {where}
        GROUP BY d.domain, i.ip
        ORDER BY d.is_new DESC, d.domain
        LIMIT 300
    """, params).fetchall()
    
    results = []
    for r in rows:
        r_dict = dict(r)
        ports = []
        if r_dict['ports_raw']:
            for p in r_dict['ports_raw'].split(','):
                p = p.strip()
                if '#NEW' in p:
                    ports.append({'port': p.replace('#NEW', ''), 'is_new': True})
                else:
                    ports.append({'port': p, 'is_new': False})
        
        r_dict['ports'] = ports
        results.append(r_dict)
    conn.close()
    return jsonify(results)

@app.route('/api/content')
def api_content():
    if not os.path.exists(DB_PATH): return jsonify({"js":[], "urls":[], "certs":[]})
    conn = get_db()
    try:
        c_js = [dict(r) for r in conn.execute("SELECT url, is_new FROM js_files ORDER BY is_new DESC, last_seen DESC LIMIT 800").fetchall()]
        c_urls=[dict(r) for r in conn.execute("SELECT url, is_new FROM url_paths ORDER BY is_new DESC, last_seen DESC LIMIT 800").fetchall()]
        c_certs=[dict(r) for r in conn.execute("SELECT domain, is_new FROM certs ORDER BY is_new DESC, last_seen DESC LIMIT 800").fetchall()]
    except Exception:
        c_js, c_urls, c_certs = [], [], []
    conn.close()
    return jsonify({"js": c_js, "urls": c_urls, "certs": c_certs})

@app.route('/api/ack_all', methods=['POST'])
def api_ack_all():
    if not os.path.exists(DB_PATH): return jsonify({"status": "error"})
    conn = get_db()
    for t in ['targets', 'domain_records', 'ips', 'services', 'js_files', 'url_paths', 'certs']:
        try: conn.execute(f"UPDATE {t} SET is_new = 0")
        except: pass
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})

if __name__ == '__main__':
    print("[*] 正在执行数据库兼容性检查...")
    upgrade_schema()
    print("[*] 正在启动 Recon 资产聚合面板 (全维度监控版)...")
    print("[*] 访问: http://0.0.0.0:8080")
    app.run(host='0.0.0.0', port=8080, debug=True)
