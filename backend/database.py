import os
import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
import sqlite3
import datetime
import uuid
import json
import certifi
from pymongo import MongoClient
from bson.objectid import ObjectId
from dotenv import load_dotenv

load_dotenv()

# Configuration
MONGO_URI = os.getenv("MONGODB_URI")
SQLITE_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "codeguard.db")

# Connection flags
USE_MONGODB = False
mongo_client = None
db = None

# Attempt MongoDB Connection
if MONGO_URI:
    try:
        # Use certifi to fix SSL handshake errors on Windows
        mongo_client = MongoClient(
            MONGO_URI, 
            serverSelectionTimeoutMS=5000,
            tlsCAFile=certifi.where()
        )
        # Verify connection
        mongo_client.admin.command('ping')
        db = mongo_client.codeguard
        USE_MONGODB = True
        print("✅ MongoDB Atlas connected successfully using SSL certificates.")
    except Exception as e:
        print(f"⚠️ MongoDB Connection failed: {e}")
        print("💡 TIP: Check if your current IP is whitelisted in MongoDB Atlas.")
        print("📁 Falling back to local SQLite for reliability.")
        USE_MONGODB = False
else:
    print("ℹ️ No MONGODB_URI found. Using SQLite.")

# SQLite initialization
def get_sqlite_conn():
    conn = sqlite3.connect(SQLITE_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def get_db():
    if USE_MONGODB: return db
    # Mock for SQLite to prevent attribute crashes in agent logic
    class SQLiteDB:
        def __init__(self): self.vulnerabilities = None
    return SQLiteDB()

def init_sqlite():
    conn = get_sqlite_conn()
    # Scans table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            repo_url TEXT,
            status TEXT,
            date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            vulnerability_count INTEGER DEFAULT 0,
            user_id TEXT
        )
    ''')
    
    # Migration: Add user_id column if it doesn't exist in an old DB
    try:
        cursor = conn.execute("PRAGMA table_info(scans)")
        columns = [row['name'] for row in cursor.fetchall()]
        if 'user_id' not in columns:
            conn.execute("ALTER TABLE scans ADD COLUMN user_id TEXT")
            print("🚀 Migrated scans table: added user_id column.")
    except Exception as me:
        print(f"⚠️ Migration failed: {me}")

    # Vulnerabilities table (use file_path as in migration logic)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id TEXT PRIMARY KEY,
            scan_id TEXT,
            title TEXT,
            severity TEXT,
            category TEXT,
            file_path TEXT,
            line_number INTEGER,
            description TEXT,
            vulnerable_code TEXT,
            fixed_code TEXT,
            is_fixed INTEGER DEFAULT 0,
            start_line INTEGER DEFAULT 0,
            FOREIGN KEY (scan_id) REFERENCES scans (id)
        )
    ''')
    
    # Migration: Add start_line column if it doesn't exist in an old DB
    try:
        cursor = conn.execute("PRAGMA table_info(vulnerabilities)")
        columns = [row['name'] for row in cursor.fetchall()]
        if 'start_line' not in columns:
            conn.execute("ALTER TABLE vulnerabilities ADD COLUMN start_line INTEGER DEFAULT 0")
            print("🚀 Migrated vulnerabilities table: added start_line column.")
        
        if 'is_fixed' not in columns:
            conn.execute("ALTER TABLE vulnerabilities ADD COLUMN is_fixed INTEGER DEFAULT 0")
            print("🚀 Migrated vulnerabilities table: added is_fixed column.")
    except Exception as me:
        print(f"⚠️ Migration failed: {me}")
        
    conn.commit()
    conn.close()

if not USE_MONGODB:
    init_sqlite()

# Unified Interface Functions
def create_scan(repo_url, user_id=None):
    scan_id = str(uuid.uuid4().hex) if not USE_MONGODB else None
    now = datetime.datetime.utcnow()
    
    if USE_MONGODB:
        doc = {
            "repo_url": repo_url,
            "status": "In Progress",
            "date": now,
            "vulnerability_count": 0,
            "user_id": user_id
        }
        res = db.scans.insert_one(doc)
        return str(res.inserted_id)
    else:
        conn = get_sqlite_conn()
        conn.execute(
            'INSERT INTO scans (id, repo_url, status, user_id) VALUES (?, ?, ?, ?)',
            (scan_id, repo_url, 'In Progress', user_id)
        )
        conn.commit()
        conn.close()
        return scan_id

def update_scan_status(scan_id, status, vuln_count=None):
    if USE_MONGODB:
        update = {"status": status}
        if vuln_count is not None:
            update["vulnerability_count"] = vuln_count
        db.scans.update_one({"_id": ObjectId(scan_id)}, {"$set": update})
    else:
        conn = get_sqlite_conn()
        if vuln_count is not None:
            conn.execute('UPDATE scans SET status = ?, vulnerability_count = ? WHERE id = ?', (status, vuln_count, scan_id))
        else:
            conn.execute('UPDATE scans SET status = ? WHERE id = ?', (status, scan_id))
        conn.commit()
        conn.close()

def add_vulnerability(scan_id, v):
    if USE_MONGODB:
        v_doc = {
            "scan_id": ObjectId(scan_id),
            "title": v.get('title'),
            "severity": v.get('severity'),
            "category": v.get('category'),
            "file": v.get('file'),
            "line": v.get('line'),
            "description": v.get('description'),
            "vulnerableCode": v.get('vulnerableCode'),
            "start_line": v.get('start_line', 0),
            "fixed_code": v.get('fixed_code', ""),
            "is_fixed": False
        }
        db.vulnerabilities.insert_one(v_doc)
    else:
        conn = get_sqlite_conn()
        v_id = str(uuid.uuid4().hex)
        conn.execute('''
            INSERT INTO vulnerabilities (id, scan_id, title, severity, category, file_path, line_number, description, vulnerable_code, start_line, is_fixed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
        ''', (v_id, scan_id, v.get('title'), v.get('severity'), v.get('category'), v.get('file'), v.get('line'), v.get('description'), v.get('vulnerableCode'), v.get('start_line', 0)))
        conn.commit()
        conn.close()

def resolve_vulnerability(v_id):
    if USE_MONGODB:
        db.vulnerabilities.update_one({"_id": ObjectId(v_id)}, {"$set": {"is_fixed": True}})
    else:
        conn = get_sqlite_conn()
        conn.execute('UPDATE vulnerabilities SET is_fixed = 1 WHERE id = ?', (v_id,))
        conn.commit()
        conn.close()

def get_scan_results(scan_id):
    scan, vulns = None, []
    
    # Try MongoDB First
    if USE_MONGODB:
        try:
            res = db.scans.find_one({"_id": ObjectId(scan_id)})
            if res:
                scan = res
                scan['id'] = str(scan.pop('_id'))
                vulns = list(db.vulnerabilities.find({"scan_id": ObjectId(scan_id)}))
                for v in vulns:
                    v['id'] = str(v.pop('_id'))
                    v['scan_id'] = str(v['scan_id'])
        except Exception:
            pass

    # Fallback/Merge with SQLite if not found or always check SQLite for historical
    if not scan:
        try:
            conn = get_sqlite_conn()
            res = conn.execute('SELECT * FROM scans WHERE id = ?', (scan_id,)).fetchone()
            if res:
                scan = dict(res)
                v_rows = conn.execute('SELECT * FROM vulnerabilities WHERE scan_id = ?', (scan_id,)).fetchall()
                vulns = [dict(v) for v in v_rows]
                for v in vulns:
                    v['file'] = v.pop('file_path')
                    v['line'] = v.pop('line_number')
                    v['vulnerableCode'] = v.pop('vulnerable_code')
                    v['start_line'] = v.get('start_line', 0)
            conn.close()
        except Exception:
            pass
            
    return scan, vulns

def get_all_scans(user_id=None, user_email=None):
    all_scans = []
    
    # 1. Fetch from MongoDB
    if USE_MONGODB:
        try:
            q = {"user_id": user_id} if user_id else {}
            m_scans = list(db.scans.find(q).sort("date", -1))
            for s in m_scans:
                s['id'] = str(s.pop('_id'))
                # Enrich with counts
                sid_obj = ObjectId(s['id'])
                v_list = list(db.vulnerabilities.find({"scan_id": sid_obj}))
                
                severities = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                resolved_count = 0
                for v in v_list:
                    if v.get('is_fixed'):
                        resolved_count += 1
                    else:
                        sev = v.get('severity', 'medium').lower()
                        if sev in severities: severities[sev] += 1
                s['severities'] = severities
                s['resolved_count'] = resolved_count
                s['vulnerability_count'] = len(v_list)
                s['source'] = 'cloud'
            all_scans.extend(m_scans)
        except Exception:
            pass

    # 2. Fetch from SQLite
    try:
        conn = get_sqlite_conn()
        if user_id or user_email:
            # Use both ID and Email to retrieve historical SQLite data
            s_rows = conn.execute('SELECT * FROM scans WHERE user_id = ? OR user_id = ? ORDER BY date DESC', (user_id, user_email)).fetchall()
        else:
            s_rows = conn.execute('SELECT * FROM scans ORDER BY date DESC').fetchall()
            
        s_scans = [dict(s) for s in s_rows]
        for s in s_scans:
            sid = s['id']
            v_rows = conn.execute('SELECT severity, is_fixed FROM vulnerabilities WHERE scan_id = ?', (sid,)).fetchall()
            
            severities = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            resolved_count = 0
            for v in v_rows:
                v_dict = dict(v)
                if v_dict.get('is_fixed') or v_dict.get('is_fixed') == 1:
                    resolved_count += 1
                else:
                    sev = v_dict.get('severity', 'medium').lower()
                    if sev in severities: severities[sev] += 1
            s['severities'] = severities
            s['resolved_count'] = resolved_count
            s['vulnerability_count'] = len(v_rows)
            s['source'] = 'local'
        all_scans.extend(s_scans)
        conn.close()
    except Exception:
        pass

    # 3. Deduplication & Sorting
    # Hybrid Strategy: Sort by date. If multiple scans exist for same repo URL, hide older ones.
    # Convert dates to strings to avoid "TypeError: '<' not supported between instances of 'datetime.datetime' and 'str'"
    all_scans.sort(key=lambda x: str(x.get('date', '')), reverse=True)
    
    seen_repos = {}
    final_scans = []
    for s in all_scans:
        repo = s.get('repo_url')
        if repo not in seen_repos:
            seen_repos[repo] = s
            final_scans.append(s)
            
    return final_scans

def clear_user_data(user_id, user_email=None):
    if USE_MONGODB:
        q = {"user_id": user_id} if user_id else {}
        # Get all scan IDs to delete their vulnerabilities
        scans = list(db.scans.find(q))
        sid_list = [s['_id'] for s in scans]
        db.vulnerabilities.delete_many({"scan_id": {"$in": sid_list}})
        db.scans.delete_many(q)
    
    # Always clean up SQLite using both keys
    try:
        conn = get_sqlite_conn()
        if user_id or user_email:
            # Delete vulnerabilities for user's scans first
            conn.execute('''
                DELETE FROM vulnerabilities 
                WHERE scan_id IN (SELECT id FROM scans WHERE user_id = ? OR user_id = ?)
            ''', (user_id, user_email))
            conn.execute('DELETE FROM scans WHERE user_id = ? OR user_id = ?', (user_id, user_email))
        else:
            conn.execute('DELETE FROM vulnerabilities')
            conn.execute('DELETE FROM scans')
        conn.commit()
        conn.close()
    except Exception:
        pass

def get_user_analytics(user_id=None, user_email=None):
    # Simplified hybrid analytics
    scans = get_all_scans(user_id, user_email)
    stats = {
        "severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "categories": {}
    }
    for s in scans:
        sid = s['id']
        _, vulns = get_scan_results(sid)
        for v in vulns:
            sev = v.get('severity', 'medium').lower()
            if sev in stats['severity']: stats['severity'][sev] += 1
            cat = v.get('category', 'Other')
            stats['categories'][cat] = stats['categories'].get(cat, 0) + 1
            
    cat_list = [{"name": n, "count": c} for n, c in stats['categories'].items()]
    cat_list.sort(key=lambda x: x['count'], reverse=True)
    stats['categories'] = cat_list[:5]
    return stats

def get_user_by_email(email):
    if USE_MONGODB:
        user = db.users.find_one({'email': email})
        if user:
            user['_id'] = str(user['_id'])
        return user
    else:
        conn = get_sqlite_conn()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()
        if user:
            user_dict = dict(user)
            user_dict['_id'] = user_dict.get('id')
            return user_dict
        return None

def create_user(user_data):
    """user_data: {email, name, picture, google_id}"""
    user_data['created_at'] = datetime.datetime.utcnow()
    if USE_MONGODB:
        res = db.users.insert_one(user_data)
        user_data['_id'] = str(res.inserted_id)
        return user_data
    else:
        conn = get_sqlite_conn()
        user_id = str(uuid.uuid4().hex)
        conn.execute('''
            INSERT INTO users (id, email, name, picture, google_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, user_data['email'], user_data['name'], user_data['picture'], user_data['google_id'], user_data['created_at']))
        conn.commit()
        conn.close()
        user_data['_id'] = user_id
        return user_data

# Ensure all tables exist in SQLite
if not USE_MONGODB:
    init_sqlite()
    conn = get_sqlite_conn()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE,
            name TEXT,
            picture TEXT,
            google_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()
