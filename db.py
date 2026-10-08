import sqlite3
import os
import uuid
import json
import re
from datetime import datetime, timedelta
from contextlib import contextmanager
from werkzeug.security import generate_password_hash, check_password_hash

def get_db_path():
    env_path = os.getenv("DB_PATH")
    if env_path:
        return env_path
    base_dir = os.path.dirname(os.path.abspath(__file__))
    primary_path = os.path.join(base_dir, "lookup_data.db")
    try:
        test_file = os.path.join(base_dir, ".db_perm_test")
        with open(test_file, "w") as f:
            f.write("ok")
        if os.path.exists(test_file):
            os.remove(test_file)
        return primary_path
    except Exception:
        import tempfile
        return os.path.join(tempfile.gettempdir(), "lookup_data.db")

DB_PATH = get_db_path()

@contextmanager
def get_connection():
    conn = sqlite3.connect(get_db_path(), timeout=15)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    with get_connection() as conn:
        cursor = conn.cursor()
        
        # 1. Users Table with Authentication & Membership
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE,
                email TEXT UNIQUE,
                phone_number TEXT,
                password_hash TEXT,
                role TEXT DEFAULT 'user',
                is_banned INTEGER DEFAULT 0,
                ip_address TEXT,
                device_fingerprint TEXT,
                free_lookups_used INTEGER DEFAULT 0,
                plan_status TEXT DEFAULT 'free',
                plan_type TEXT DEFAULT NULL,
                plan_activated_at TEXT DEFAULT NULL,
                plan_expires_at TEXT DEFAULT NULL,
                created_at TEXT,
                last_seen TEXT
            )
        """)
        
        # Safe Migrations for users table (in case existing db is present)
        user_columns = [
            ("username", "TEXT UNIQUE"),
            ("email", "TEXT UNIQUE"),
            ("phone_number", "TEXT"),
            ("password_hash", "TEXT"),
            ("role", "TEXT DEFAULT 'user'"),
            ("is_banned", "INTEGER DEFAULT 0"),
            ("device_fingerprint", "TEXT"),
            ("free_lookups_used", "INTEGER DEFAULT 0"),
            ("plan_status", "TEXT DEFAULT 'free'"),
            ("plan_type", "TEXT DEFAULT NULL"),
            ("plan_activated_at", "TEXT DEFAULT NULL"),
            ("plan_expires_at", "TEXT DEFAULT NULL"),
            ("created_at", "TEXT"),
            ("last_seen", "TEXT")
        ]
        for col_name, col_type in user_columns:
            try:
                cursor.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_type}")
            except Exception:
                pass

        # Indexes for fast lookup
        try:
            cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username)")
            cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_fp ON users(device_fingerprint)")
        except Exception:
            pass

        # 2. Payment Requests Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS payment_requests (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                plan_type TEXT,
                amount INTEGER,
                utr TEXT,
                user_note TEXT,
                status TEXT DEFAULT 'pending',
                created_at TEXT,
                reviewed_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)
        try:
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_pay_utr ON payment_requests(utr)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_pay_user ON payment_requests(user_id)")
        except Exception:
            pass
        
        # 3. Comprehensive Lookup Activity Logs
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS lookup_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                ip_address TEXT,
                device_fingerprint TEXT,
                phone_number TEXT,
                status TEXT,
                data_payload TEXT,
                timestamp TEXT
            )
        """)
        
        # Safe Migrations for lookup_logs
        for col, ctype in [("ip_address", "TEXT"), ("device_fingerprint", "TEXT"), ("data_payload", "TEXT")]:
            try:
                cursor.execute(f"ALTER TABLE lookup_logs ADD COLUMN {col} {ctype}")
            except Exception:
                pass

        try:
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_user ON lookup_logs(user_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_phone ON lookup_logs(phone_number)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_time ON lookup_logs(timestamp)")
        except Exception:
            pass

        conn.commit()

def now_iso():
    return datetime.utcnow().isoformat()

# ==========================================
# User Authentication & Registration Engine
# ==========================================

def register_user(username, email, password, phone_number="", ip_address="", device_fingerprint=""):
    """
    Registers a new user with strong password hashing and anti-abuse quota protection.
    """
    username = (username or "").strip()
    email = (email or "").strip().lower()
    phone_number = re.sub(r"\D", "", phone_number or "")
    
    # Input Validation
    if not username or len(username) < 3 or len(username) > 30:
        return False, "Username 3 se 30 characters ke beech hona chahiye."
    if not re.match(r"^[a-zA-Z0-9_.-]+$", username):
        return False, "Username me sirf letters, numbers, underscore (_) ya hyphen (-) ho sakte hain."
    if not email or "@" not in email or "." not in email:
        return False, "Kripya valid email address enter karein."
    if not password or len(password) < 6:
        return False, "Password kam se kam 6 characters ka hona chahiye."

    with get_connection() as conn:
        cursor = conn.cursor()
        
        # Check if username or email already exists
        cursor.execute("SELECT id FROM users WHERE LOWER(username) = LOWER(?)", (username,))
        if cursor.fetchone():
            return False, "Ye username pehle se registered hai. Doosra username chunein."

        cursor.execute("SELECT id FROM users WHERE LOWER(email) = LOWER(?)", (email,))
        if cursor.fetchone():
            return False, "Ye email address pehle se registered hai. Kripya login karein."

        # Anti-abuse: Check if this physical device fingerprint or IP already exhausted free scans
        inherited_used = 0
        if device_fingerprint:
            cursor.execute("""
                SELECT MAX(free_lookups_used) FROM users 
                WHERE device_fingerprint = ?
            """, (device_fingerprint,))
            matched = cursor.fetchone()
            if matched and matched[0] is not None and matched[0] >= 3:
                inherited_used = 3

        if ip_address and ip_address not in ["127.0.0.1", "localhost", "::1"] and inherited_used < 3:
            cursor.execute("""
                SELECT COUNT(*) FROM lookup_logs 
                WHERE ip_address = ? AND status = 'success'
            """, (ip_address,))
            ip_count = cursor.fetchone()[0]
            if ip_count >= 5:
                inherited_used = 3

        user_id = f"usr_{uuid.uuid4().hex[:12]}"
        password_hash = generate_password_hash(password, method="pbkdf2:sha256")
        now_str = now_iso()

        cursor.execute("""
            INSERT INTO users (
                id, username, email, phone_number, password_hash, role, is_banned,
                ip_address, device_fingerprint, free_lookups_used, plan_status,
                created_at, last_seen
            ) VALUES (?, ?, ?, ?, ?, 'user', 0, ?, ?, ?, 'free', ?, ?)
        """, (user_id, username, email, phone_number, password_hash, ip_address, device_fingerprint, inherited_used, now_str, now_str))
        conn.commit()

        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = dict(cursor.fetchone())
        user.pop("password_hash", None)
        return True, user

def authenticate_user(identifier, password, ip_address="", device_fingerprint=""):
    """
    Authenticates user using Username or Email and verifies password hash.
    """
    ident = (identifier or "").strip().lower()
    if not ident or not password:
        return False, "Username/Email aur password enter karein."

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM users 
            WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)
        """, (ident, ident))
        row = cursor.fetchone()
        
        if not row:
            return False, "Account nahi mila. Kripya sahi username ya email enter karein."
        
        user = dict(row)

        if user.get("is_banned"):
            return False, "Aapka account security policy violation ki wajah se suspended hai."

        # Verify password hash
        stored_hash = user.get("password_hash")
        if not stored_hash or not check_password_hash(stored_hash, password):
            return False, "Password galat hai! Dobara prayas karein."

        # Update last seen, IP, and fingerprint
        now_str = now_iso()
        cursor.execute("""
            UPDATE users 
            SET last_seen = ?,
                ip_address = COALESCE(NULLIF(?, ''), ip_address),
                device_fingerprint = COALESCE(NULLIF(?, ''), device_fingerprint)
            WHERE id = ?
        """, (now_str, ip_address, device_fingerprint, user["id"]))
        conn.commit()

        user.pop("password_hash", None)
        return True, user

def get_user_by_id(user_id):
    """
    Fetches user profile by ID, auto-checks plan expiration.
    """
    if not user_id:
        return None
    with get_connection() as conn:
        cursor = conn.cursor()
        now = datetime.utcnow()
        now_str = now.isoformat()

        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        if not row:
            return None
        user = dict(row)

        # Plan expiration check
        if user["plan_status"] == "premium" and user["plan_expires_at"]:
            try:
                exp = datetime.fromisoformat(user["plan_expires_at"])
                if now > exp:
                    cursor.execute("UPDATE users SET plan_status = 'expired' WHERE id = ?", (user_id,))
                    conn.commit()
                    user["plan_status"] = "expired"
            except Exception:
                pass

        user.pop("password_hash", None)
        return user

def get_user_by_username(username):
    if not username:
        return None
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE LOWER(username) = LOWER(?)", (username.strip(),))
        row = cursor.fetchone()
        if not row:
            return None
        u = dict(row)
        u.pop("password_hash", None)
        return u

# ==========================================
# Quota & Lookup Permission Verification
# ==========================================

def can_user_lookup(user_id, ip_address="", device_fingerprint=""):
    user = get_user_by_id(user_id)
    if not user:
        return False, "USER_NOT_FOUND", {}

    if user.get("is_banned"):
        return False, "ACCOUNT_SUSPENDED", user

    if user.get("plan_status") == "premium":
        return True, "PREMIUM_ACTIVE", user

    # Anti-bypass cross check:
    with get_connection() as conn:
        cursor = conn.cursor()
        
        # 1. Device fingerprint check
        if device_fingerprint:
            cursor.execute("""
                SELECT COUNT(*) FROM users 
                WHERE device_fingerprint = ? AND free_lookups_used >= 3 AND plan_status != 'premium'
            """, (device_fingerprint,))
            if cursor.fetchone()[0] > 0 and user.get("free_lookups_used", 0) < 3:
                user["free_lookups_used"] = 3
                cursor.execute("UPDATE users SET free_lookups_used = 3 WHERE id = ?", (user_id,))
                conn.commit()

        # 2. IP rate-check
        if ip_address and ip_address not in ["127.0.0.1", "localhost", "::1"]:
            cursor.execute("""
                SELECT COUNT(*) FROM lookup_logs 
                WHERE ip_address = ? AND status = 'success'
            """, (ip_address,))
            total_ip_lookups = cursor.fetchone()[0]
            if total_ip_lookups >= 6 and user.get("free_lookups_used", 0) < 3:
                user["free_lookups_used"] = 3
                cursor.execute("UPDATE users SET free_lookups_used = 3 WHERE id = ?", (user_id,))
                conn.commit()

    free_used = user.get("free_lookups_used", 0)
    if free_used < 3:
        return True, f"FREE_TIER_{free_used + 1}_OF_3", user
    else:
        return False, "LIMIT_REACHED", user

def record_lookup_usage(user_id, phone_number, ip_address="", device_fingerprint="", data_payload=None, success=True):
    user = get_user_by_id(user_id)
    if not user:
        return
    with get_connection() as conn:
        cursor = conn.cursor()
        now_str = now_iso()
        
        # Only increment free count if user is not on active premium
        if user["plan_status"] != "premium":
            cursor.execute("""
                UPDATE users 
                SET free_lookups_used = free_lookups_used + 1, last_seen = ?
                WHERE id = ?
            """, (now_str, user_id))

            if device_fingerprint:
                cursor.execute("""
                    UPDATE users 
                    SET free_lookups_used = free_lookups_used + 1 
                    WHERE device_fingerprint = ? AND id != ? AND plan_status != 'premium'
                """, (device_fingerprint, user_id))

        # Store complete OSINT data payload in logs
        payload_str = json.dumps(data_payload, ensure_ascii=False) if data_payload else "{}"
        cursor.execute("""
            INSERT INTO lookup_logs (user_id, ip_address, device_fingerprint, phone_number, status, data_payload, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (user_id, ip_address, device_fingerprint, phone_number, "success" if success else "failed", payload_str, now_str))
        conn.commit()

# ==========================================
# Payment Management & UTR Verification
# ==========================================

def is_utr_already_used(utr):
    clean_utr = utr.strip()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, status FROM payment_requests WHERE utr = ?", (clean_utr,))
        row = cursor.fetchone()
        return bool(row)

def create_payment_request(user_id, plan_type, amount, utr, user_note=""):
    req_id = f"REQ-{uuid.uuid4().hex[:8].upper()}"
    now_str = now_iso()
    clean_utr = utr.strip()
    clean_note = (user_note or "").strip()

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO payment_requests (id, user_id, plan_type, amount, utr, user_note, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)
        """, (req_id, user_id, plan_type, amount, clean_utr, clean_note, now_str))
        conn.commit()
        
        cursor.execute("SELECT * FROM payment_requests WHERE id = ?", (req_id,))
        return dict(cursor.fetchone())

def get_latest_pending_payment(user_id):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM payment_requests 
            WHERE user_id = ? AND status = 'pending'
            ORDER BY created_at DESC LIMIT 1
        """, (user_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

def get_user_payment_history(user_id):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM payment_requests 
            WHERE user_id = ? 
            ORDER BY created_at DESC LIMIT 10
        """, (user_id,))
        return [dict(r) for r in cursor.fetchall()]

def get_all_payment_requests():
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT p.*, u.username, u.email, u.free_lookups_used, u.plan_status as current_user_plan
            FROM payment_requests p
            LEFT JOIN users u ON p.user_id = u.id
            ORDER BY p.created_at DESC
        """)
        return [dict(r) for r in cursor.fetchall()]

def approve_payment_request(req_id):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM payment_requests WHERE id = ?", (req_id,))
        req = cursor.fetchone()
        if not req:
            return False, "Request not found"
        req = dict(req)
        
        user_id = req["user_id"]
        plan_type = req["plan_type"]
        now = datetime.utcnow()
        days_to_add = 1 if plan_type == "1day" else 7
        
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user_row = cursor.fetchone()
        user = dict(user_row) if user_row else {}
        
        start_date = now
        if user.get("plan_status") == "premium" and user.get("plan_expires_at"):
            try:
                curr_exp = datetime.fromisoformat(user["plan_expires_at"])
                if curr_exp > now:
                    start_date = curr_exp
            except Exception:
                pass
                
        new_expiry = (start_date + timedelta(days=days_to_add)).isoformat()
        now_str = now.isoformat()
        
        cursor.execute("""
            UPDATE users 
            SET plan_status = 'premium',
                plan_type = ?,
                plan_activated_at = ?,
                plan_expires_at = ?,
                last_seen = ?
            WHERE id = ?
        """, (plan_type, now_str, new_expiry, now_str, user_id))
        
        cursor.execute("""
            UPDATE payment_requests 
            SET status = 'approved', reviewed_at = ?
            WHERE id = ?
        """, (now_str, req_id))
        
        conn.commit()
        return True, {
            "user_id": user_id,
            "username": user.get("username", "User"),
            "plan_type": plan_type,
            "new_expiry": new_expiry
        }

def reject_payment_request(req_id):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM payment_requests WHERE id = ?", (req_id,))
        req = cursor.fetchone()
        if not req:
            return False, "Request not found"
            
        now_str = now_iso()
        cursor.execute("""
            UPDATE payment_requests 
            SET status = 'rejected', reviewed_at = ?
            WHERE id = ?
        """, (now_str, req_id))
        conn.commit()
        return True, "Rejected"

# ==========================================
# Search Logs & Admin Telemetry
# ==========================================

def get_lookup_logs(search_query="", date_filter="", limit=100):
    with get_connection() as conn:
        cursor = conn.cursor()
        sql = """
            SELECT l.id, l.user_id, u.username, l.ip_address, l.device_fingerprint, 
                   l.phone_number, l.status, l.timestamp, length(l.data_payload) as payload_len 
            FROM lookup_logs l
            LEFT JOIN users u ON l.user_id = u.id
        """
        params = []
        conditions = []

        if search_query:
            conditions.append("(l.phone_number LIKE ? OR l.user_id LIKE ? OR u.username LIKE ? OR l.ip_address LIKE ?)")
            q = f"%{search_query.strip()}%"
            params.extend([q, q, q, q])

        if date_filter:
            conditions.append("l.timestamp LIKE ?")
            params.append(f"{date_filter.strip()}%")

        if conditions:
            sql += " WHERE " + " AND ".join(conditions)

        sql += " ORDER BY l.id DESC LIMIT ?"
        params.append(limit)

        cursor.execute(sql, tuple(params))
        return [dict(r) for r in cursor.fetchall()]

def get_user_search_history(user_id, limit=20):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, phone_number, status, timestamp 
            FROM lookup_logs 
            WHERE user_id = ? 
            ORDER BY id DESC LIMIT ?
        """, (user_id, limit))
        return [dict(r) for r in cursor.fetchall()]

def get_log_detail(log_id):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT l.*, u.username, u.email 
            FROM lookup_logs l
            LEFT JOIN users u ON l.user_id = u.id
            WHERE l.id = ?
        """, (log_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

# ==========================================
# Admin User Management
# ==========================================

def admin_get_all_users(search_query="", limit=100):
    with get_connection() as conn:
        cursor = conn.cursor()
        sql = "SELECT id, username, email, phone_number, role, is_banned, plan_status, plan_type, plan_expires_at, free_lookups_used, ip_address, created_at, last_seen FROM users"
        params = []
        if search_query:
            sql += " WHERE (username LIKE ? OR email LIKE ? OR id LIKE ? OR ip_address LIKE ?)"
            q = f"%{search_query.strip()}%"
            params.extend([q, q, q, q])
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        cursor.execute(sql, tuple(params))
        return [dict(r) for r in cursor.fetchall()]

def admin_toggle_ban_user(user_id):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT is_banned FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        if not row:
            return False, "User not found"
        new_state = 0 if row[0] == 1 else 1
        cursor.execute("UPDATE users SET is_banned = ? WHERE id = ?", (new_state, user_id))
        conn.commit()
        return True, new_state

def grant_vip_access(user_id, days=7):
    with get_connection() as conn:
        cursor = conn.cursor()
        now = datetime.utcnow()
        new_exp = (now + timedelta(days=days)).isoformat()
        now_str = now.isoformat()

        cursor.execute("""
            UPDATE users 
            SET plan_status = 'premium',
                plan_type = ?,
                plan_activated_at = ?,
                plan_expires_at = ?,
                last_seen = ?
            WHERE id = ?
        """, (f"{days}days", now_str, new_exp, now_str, user_id))
        conn.commit()
        return True, new_exp

def reset_user_quota(user_id):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET free_lookups_used = 0 WHERE id = ?", (user_id,))
        conn.commit()
        return True

def get_admin_stats():
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        total_users = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM users WHERE plan_status = 'premium'")
        active_subscribers = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM payment_requests WHERE status = 'pending'")
        pending_approvals = cursor.fetchone()[0]
        
        cursor.execute("SELECT COALESCE(SUM(amount), 0) FROM payment_requests WHERE status = 'approved'")
        total_revenue = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM lookup_logs")
        total_lookups = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT id, username, email, plan_type, plan_expires_at, ip_address 
            FROM users 
            WHERE plan_status = 'premium' 
            ORDER BY plan_expires_at DESC LIMIT 20
        """)
        active_users = [dict(r) for r in cursor.fetchall()]
        
        return {
            "total_users": total_users,
            "active_subscribers": active_subscribers,
            "pending_approvals": pending_approvals,
            "total_revenue": total_revenue,
            "total_lookups": total_lookups,
            "active_users": active_users
        }
