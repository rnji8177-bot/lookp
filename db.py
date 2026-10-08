import sqlite3
import os
import uuid
import json
import re
import secrets
from datetime import datetime, timedelta
from contextlib import contextmanager
from werkzeug.security import generate_password_hash, check_password_hash

# Try importing psycopg2 for cloud PostgreSQL support
try:
    import psycopg2
    import psycopg2.extras
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False

DATABASE_URL = os.getenv("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

IS_POSTGRES = bool(DATABASE_URL and PSYCOPG2_AVAILABLE)

def get_db_path():
    env_path = os.getenv("DB_PATH")
    if env_path:
        return env_path
    # Check if a persistent container volume like /app/data exists
    if os.path.isdir("/app/data"):
        return "/app/data/lookup_data.db"
    base_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_dir, "lookup_data.db")

DB_PATH = get_db_path()

# Query placeholder translator (SQLite uses ?, PostgreSQL uses %s)
def q(query):
    if IS_POSTGRES:
        return query.replace("?", "%s")
    return query

@contextmanager
def get_connection():
    if IS_POSTGRES:
        conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    else:
        conn = sqlite3.connect(get_db_path(), timeout=15)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

def init_db():
    with get_connection() as conn:
        cursor = conn.cursor()
        
        # 1. Users Table with Authentication & Membership
        cursor.execute(q("""
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
        """))
        
        # 2. Pending Registrations & OTP Table
        cursor.execute(q("""
            CREATE TABLE IF NOT EXISTS pending_registrations (
                email TEXT PRIMARY KEY,
                username TEXT,
                password_hash TEXT,
                phone_number TEXT,
                otp_code TEXT,
                ip_address TEXT,
                device_fingerprint TEXT,
                created_at TEXT,
                expires_at TEXT
            )
        """))

        # 3. Payment Requests Table
        cursor.execute(q("""
            CREATE TABLE IF NOT EXISTS payment_requests (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                plan_type TEXT,
                amount INTEGER,
                utr TEXT,
                user_note TEXT,
                status TEXT DEFAULT 'pending',
                created_at TEXT,
                reviewed_at TEXT
            )
        """))

        # 4. Lookup Activity Logs Table
        if IS_POSTGRES:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS lookup_logs (
                    id SERIAL PRIMARY KEY,
                    user_id TEXT,
                    ip_address TEXT,
                    device_fingerprint TEXT,
                    phone_number TEXT,
                    status TEXT,
                    data_payload TEXT,
                    timestamp TEXT
                )
            """)
        else:
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

        # Indexes for fast lookup
        try:
            cursor.execute(q("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)"))
            cursor.execute(q("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)"))
            cursor.execute(q("CREATE INDEX IF NOT EXISTS idx_users_fp ON users(device_fingerprint)"))
            cursor.execute(q("CREATE INDEX IF NOT EXISTS idx_pay_utr ON payment_requests(utr)"))
            cursor.execute(q("CREATE INDEX IF NOT EXISTS idx_pay_user ON payment_requests(user_id)"))
            cursor.execute(q("CREATE INDEX IF NOT EXISTS idx_logs_user ON lookup_logs(user_id)"))
            cursor.execute(q("CREATE INDEX IF NOT EXISTS idx_logs_phone ON lookup_logs(phone_number)"))
        except Exception:
            pass

def now_iso():
    return datetime.utcnow().isoformat()

# ==========================================
# Anti-Fraud: Disposable / Temporary Email Blocker
# ==========================================
DISPOSABLE_DOMAINS = {
    "leafflip.com", "tempmail.com", "mailinator.com", "guerrillamail.com",
    "10minutemail.com", "yopmail.com", "sharklasers.com", "dispostable.com",
    "getairmail.com", "fakeinbox.com", "trashmail.com", "generator.email",
    "tempail.com", "mohmal.com", "emailondeck.com", "mytemp.email",
    "crazymailing.com", "dropmail.me", "inboxkitten.com", "nada.ltd",
    "getnada.com", "burnermail.io", "temp-mail.org", "fakemailgenerator.com",
    "trashmail.net", "trashmail.org", "fakemail.net", "throwawaymail.com",
    "tempmailaddress.com", "tempmailgen.com", "inboxbear.com", "bupmail.com",
    "chacuo.net", "0-mail.com", "guerrillamailblock.com", "pokemail.net",
    "spam4.me", "bccto.me", "maildrop.cc", "disposablemail.com", "boximail.com",
    "tempr.email", "discard.email", "discardmail.com", "spambox.us", "mailcatch.com"
}

def is_disposable_email(email):
    """
    Detects if an email uses a known temporary, fake, or disposable domain.
    """
    if not email or "@" not in email:
        return True
    domain = email.strip().split("@")[-1].lower()
    
    if domain in DISPOSABLE_DOMAINS:
        return True
        
    # Check suspicious patterns in domain name
    suspicious_keywords = ["temp", "dispos", "fake", "trash", "throwaway", "burner", "generator", "10min"]
    for kw in suspicious_keywords:
        if kw in domain and domain not in ["temple.edu"]:
            return True
            
    return False

# ==========================================
# User OTP Registration & Verification Engine
# ==========================================

def create_pending_otp(username, email, password, phone_number="", ip_address="", device_fingerprint=""):
    """
    Generates a secure 6-digit OTP for registration and saves in pending_registrations.
    """
    username = (username or "").strip()
    email = (email or "").strip().lower()
    phone_number = re.sub(r"\D", "", phone_number or "")
    
    # Input Validation
    if not username or len(username) < 3 or len(username) > 30:
        return False, "Username 3 se 30 characters ke beech hona chahiye.", None
    if not re.match(r"^[a-zA-Z0-9_.-]+$", username):
        return False, "Username me sirf letters, numbers, underscore (_) ya hyphen (-) ho sakte hain.", None
    if not email or "@" not in email or "." not in email:
        return False, "Kripya valid email address enter karein.", None
    if is_disposable_email(email):
        return False, "Temporary / Fake disposable email allowed nahi hai! Kripya apna real Gmail, Yahoo, ya Outlook email use karein.", None
    if not password or len(password) < 6:
        return False, "Password kam se kam 6 characters ka hona chahiye.", None

    with get_connection() as conn:
        cursor = conn.cursor()
        
        # Check if username or email already exists in registered users
        cursor.execute(q("SELECT id FROM users WHERE LOWER(username) = LOWER(?)"), (username,))
        if cursor.fetchone():
            return False, "Ye username pehle se registered hai. Doosra username chunein.", None

        cursor.execute(q("SELECT id FROM users WHERE LOWER(email) = LOWER(?)"), (email,))
        if cursor.fetchone():
            return False, "Ye email address pehle se registered hai. Kripya login karein.", None

        # Generate 6-digit OTP code
        otp_code = str(secrets.randbelow(900000) + 100000)
        password_hash = generate_password_hash(password, method="pbkdf2:sha256")
        now = datetime.utcnow()
        now_str = now.isoformat()
        expires_at = (now + timedelta(minutes=10)).isoformat()

        # Delete any old pending record for this email
        cursor.execute(q("DELETE FROM pending_registrations WHERE LOWER(email) = LOWER(?)"), (email,))

        # Insert new pending registration record
        cursor.execute(q("""
            INSERT INTO pending_registrations (
                email, username, password_hash, phone_number, otp_code,
                ip_address, device_fingerprint, created_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """), (email, username, password_hash, phone_number, otp_code, ip_address, device_fingerprint, now_str, expires_at))

        return True, "OTP successfully generated", otp_code

def verify_registration_otp(email, otp_code):
    """
    Verifies the 6-digit OTP and completes user account registration.
    """
    email = (email or "").strip().lower()
    otp_code = (otp_code or "").strip()

    if not email or not otp_code:
        return False, "Email aur OTP code enter karein."

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(q("SELECT * FROM pending_registrations WHERE LOWER(email) = LOWER(?)"), (email,))
        row = cursor.fetchone()
        
        if not row:
            return False, "Pending registration nahi mili ya expire ho gayi. Kripya dobara register karein."
        
        pending = dict(row)
        now = datetime.utcnow()

        try:
            exp_time = datetime.fromisoformat(pending["expires_at"])
            if now > exp_time:
                cursor.execute(q("DELETE FROM pending_registrations WHERE LOWER(email) = LOWER(?)"), (email,))
                return False, "OTP expire ho gaya hai! Kripya 'Resend OTP' par click karein."
        except Exception:
            pass

        if pending["otp_code"] != otp_code:
            return False, "Galat OTP code! Kripya dobara check karke enter karein."

        # Anti-abuse: check physical device fingerprint & IP
        inherited_used = 0
        device_fingerprint = pending.get("device_fingerprint") or ""
        ip_address = pending.get("ip_address") or ""

        if device_fingerprint:
            cursor.execute(q("""
                SELECT MAX(free_lookups_used) FROM users 
                WHERE device_fingerprint = ?
            """), (device_fingerprint,))
            matched = cursor.fetchone()
            if matched and matched["max"] is not None if IS_POSTGRES else matched[0] is not None:
                val = matched["max"] if IS_POSTGRES else matched[0]
                if val >= 3:
                    inherited_used = 3

        if ip_address and ip_address not in ["127.0.0.1", "localhost", "::1"] and inherited_used < 3:
            cursor.execute(q("""
                SELECT COUNT(*) as cnt FROM lookup_logs 
                WHERE ip_address = ? AND status = 'success'
            """), (ip_address,))
            ip_row = cursor.fetchone()
            ip_count = ip_row["cnt"] if IS_POSTGRES else ip_row[0]
            if ip_count >= 5:
                inherited_used = 3

        user_id = f"usr_{uuid.uuid4().hex[:12]}"
        now_str = now.isoformat()

        # Insert into verified users table
        cursor.execute(q("""
            INSERT INTO users (
                id, username, email, phone_number, password_hash, role, is_banned,
                ip_address, device_fingerprint, free_lookups_used, plan_status,
                created_at, last_seen
            ) VALUES (?, ?, ?, ?, ?, 'user', 0, ?, ?, ?, 'free', ?, ?)
        """), (user_id, pending["username"], pending["email"], pending["phone_number"], 
               pending["password_hash"], ip_address, device_fingerprint, inherited_used, now_str, now_str))

        # Clear pending registration
        cursor.execute(q("DELETE FROM pending_registrations WHERE LOWER(email) = LOWER(?)"), (email,))

        cursor.execute(q("SELECT * FROM users WHERE id = ?"), (user_id,))
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
        cursor.execute(q("""
            SELECT * FROM users 
            WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)
        """), (ident, ident))
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
        cursor.execute(q("""
            UPDATE users 
            SET last_seen = ?,
                ip_address = COALESCE(NULLIF(?, ''), ip_address),
                device_fingerprint = COALESCE(NULLIF(?, ''), device_fingerprint)
            WHERE id = ?
        """), (now_str, ip_address, device_fingerprint, user["id"]))

        user.pop("password_hash", None)
        return True, user

def get_user_by_id(user_id):
    if not user_id:
        return None
    with get_connection() as conn:
        cursor = conn.cursor()
        now = datetime.utcnow()
        now_str = now.isoformat()

        cursor.execute(q("SELECT * FROM users WHERE id = ?"), (user_id,))
        row = cursor.fetchone()
        if not row:
            return None
        user = dict(row)

        # Plan expiration check
        if user["plan_status"] == "premium" and user["plan_expires_at"]:
            try:
                exp = datetime.fromisoformat(user["plan_expires_at"])
                if now > exp:
                    cursor.execute(q("UPDATE users SET plan_status = 'expired' WHERE id = ?"), (user_id,))
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
        cursor.execute(q("SELECT * FROM users WHERE LOWER(username) = LOWER(?)"), (username.strip(),))
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
            cursor.execute(q("""
                SELECT COUNT(*) as cnt FROM users 
                WHERE device_fingerprint = ? AND free_lookups_used >= 3 AND plan_status != 'premium'
            """), (device_fingerprint,))
            row = cursor.fetchone()
            cnt = row["cnt"] if IS_POSTGRES else row[0]
            if cnt > 0 and user.get("free_lookups_used", 0) < 3:
                user["free_lookups_used"] = 3
                cursor.execute(q("UPDATE users SET free_lookups_used = 3 WHERE id = ?"), (user_id,))

        # 2. IP rate-check
        if ip_address and ip_address not in ["127.0.0.1", "localhost", "::1"]:
            cursor.execute(q("""
                SELECT COUNT(*) as cnt FROM lookup_logs 
                WHERE ip_address = ? AND status = 'success'
            """), (ip_address,))
            row = cursor.fetchone()
            total_ip_lookups = row["cnt"] if IS_POSTGRES else row[0]
            if total_ip_lookups >= 6 and user.get("free_lookups_used", 0) < 3:
                user["free_lookups_used"] = 3
                cursor.execute(q("UPDATE users SET free_lookups_used = 3 WHERE id = ?"), (user_id,))

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
        
        if user["plan_status"] != "premium":
            cursor.execute(q("""
                UPDATE users 
                SET free_lookups_used = free_lookups_used + 1, last_seen = ?
                WHERE id = ?
            """), (now_str, user_id))

            if device_fingerprint:
                cursor.execute(q("""
                    UPDATE users 
                    SET free_lookups_used = free_lookups_used + 1 
                    WHERE device_fingerprint = ? AND id != ? AND plan_status != 'premium'
                """), (device_fingerprint, user_id))

        payload_str = json.dumps(data_payload, ensure_ascii=False) if data_payload else "{}"
        cursor.execute(q("""
            INSERT INTO lookup_logs (user_id, ip_address, device_fingerprint, phone_number, status, data_payload, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """), (user_id, ip_address, device_fingerprint, phone_number, "success" if success else "failed", payload_str, now_str))

# ==========================================
# Payment Management & UTR Verification
# ==========================================

def is_utr_already_used(utr):
    clean_utr = utr.strip()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(q("SELECT id, status FROM payment_requests WHERE utr = ?"), (clean_utr,))
        row = cursor.fetchone()
        return bool(row)

def create_payment_request(user_id, plan_type, amount, utr, user_note=""):
    req_id = f"REQ-{uuid.uuid4().hex[:8].upper()}"
    now_str = now_iso()
    clean_utr = utr.strip()
    clean_note = (user_note or "").strip()

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(q("""
            INSERT INTO payment_requests (id, user_id, plan_type, amount, utr, user_note, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)
        """), (req_id, user_id, plan_type, amount, clean_utr, clean_note, now_str))
        
        cursor.execute(q("SELECT * FROM payment_requests WHERE id = ?"), (req_id,))
        return dict(cursor.fetchone())

def get_latest_pending_payment(user_id):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(q("""
            SELECT * FROM payment_requests 
            WHERE user_id = ? AND status = 'pending'
            ORDER BY created_at DESC LIMIT 1
        """), (user_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

def get_all_payment_requests():
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(q("""
            SELECT p.*, u.username, u.email, u.free_lookups_used, u.plan_status as current_user_plan
            FROM payment_requests p
            LEFT JOIN users u ON p.user_id = u.id
            ORDER BY p.created_at DESC
        """))
        return [dict(r) for r in cursor.fetchall()]

def approve_payment_request(req_id):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(q("SELECT * FROM payment_requests WHERE id = ?"), (req_id,))
        req = cursor.fetchone()
        if not req:
            return False, "Request not found"
        req = dict(req)
        
        user_id = req["user_id"]
        plan_type = req["plan_type"]
        now = datetime.utcnow()
        days_to_add = 1 if plan_type == "1day" else 7
        
        cursor.execute(q("SELECT * FROM users WHERE id = ?"), (user_id,))
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
        
        cursor.execute(q("""
            UPDATE users 
            SET plan_status = 'premium',
                plan_type = ?,
                plan_activated_at = ?,
                plan_expires_at = ?,
                last_seen = ?
            WHERE id = ?
        """), (plan_type, now_str, new_expiry, now_str, user_id))
        
        cursor.execute(q("""
            UPDATE payment_requests 
            SET status = 'approved', reviewed_at = ?
            WHERE id = ?
        """), (now_str, req_id))
        
        return True, {
            "user_id": user_id,
            "username": user.get("username", "User"),
            "plan_type": plan_type,
            "new_expiry": new_expiry
        }

def reject_payment_request(req_id):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(q("SELECT * FROM payment_requests WHERE id = ?"), (req_id,))
        req = cursor.fetchone()
        if not req:
            return False, "Request not found"
            
        now_str = now_iso()
        cursor.execute(q("""
            UPDATE payment_requests 
            SET status = 'rejected', reviewed_at = ?
            WHERE id = ?
        """), (now_str, req_id))
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
            q_str = f"%{search_query.strip()}%"
            params.extend([q_str, q_str, q_str, q_str])

        if date_filter:
            conditions.append("l.timestamp LIKE ?")
            params.append(f"{date_filter.strip()}%")

        if conditions:
            sql += " WHERE " + " AND ".join(conditions)

        sql += " ORDER BY l.id DESC LIMIT ?"
        params.append(limit)

        cursor.execute(q(sql), tuple(params))
        return [dict(r) for r in cursor.fetchall()]

def get_log_detail(log_id):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(q("""
            SELECT l.*, u.username, u.email 
            FROM lookup_logs l
            LEFT JOIN users u ON l.user_id = u.id
            WHERE l.id = ?
        """), (log_id,))
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
            q_str = f"%{search_query.strip()}%"
            params.extend([q_str, q_str, q_str, q_str])
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        cursor.execute(q(sql), tuple(params))
        return [dict(r) for r in cursor.fetchall()]

def admin_toggle_ban_user(user_id):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(q("SELECT is_banned FROM users WHERE id = ?"), (user_id,))
        row = cursor.fetchone()
        if not row:
            return False, "User not found"
        is_banned = row["is_banned"] if IS_POSTGRES else row[0]
        new_state = 0 if is_banned == 1 else 1
        cursor.execute(q("UPDATE users SET is_banned = ? WHERE id = ?"), (new_state, user_id))
        return True, new_state

def grant_vip_access(user_id, days=7):
    with get_connection() as conn:
        cursor = conn.cursor()
        now = datetime.utcnow()
        new_exp = (now + timedelta(days=days)).isoformat()
        now_str = now.isoformat()

        cursor.execute(q("""
            UPDATE users 
            SET plan_status = 'premium',
                plan_type = ?,
                plan_activated_at = ?,
                plan_expires_at = ?,
                last_seen = ?
            WHERE id = ?
        """), (f"{days}days", now_str, new_exp, now_str, user_id))
        return True, new_exp

def reset_user_quota(user_id):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(q("UPDATE users SET free_lookups_used = 0 WHERE id = ?"), (user_id,))
        return True

def get_admin_stats():
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(q("SELECT COUNT(*) as cnt FROM users"))
        row = cursor.fetchone()
        total_users = row["cnt"] if IS_POSTGRES else row[0]
        
        cursor.execute(q("SELECT COUNT(*) as cnt FROM users WHERE plan_status = 'premium'"))
        row = cursor.fetchone()
        active_subscribers = row["cnt"] if IS_POSTGRES else row[0]
        
        cursor.execute(q("SELECT COUNT(*) as cnt FROM payment_requests WHERE status = 'pending'"))
        row = cursor.fetchone()
        pending_approvals = row["cnt"] if IS_POSTGRES else row[0]
        
        cursor.execute(q("SELECT COALESCE(SUM(amount), 0) as total FROM payment_requests WHERE status = 'approved'"))
        row = cursor.fetchone()
        total_revenue = row["total"] if IS_POSTGRES else row[0]
        
        cursor.execute(q("SELECT COUNT(*) as cnt FROM lookup_logs"))
        row = cursor.fetchone()
        total_lookups = row["cnt"] if IS_POSTGRES else row[0]
        
        cursor.execute(q("""
            SELECT id, username, email, plan_type, plan_expires_at, ip_address 
            FROM users 
            WHERE plan_status = 'premium' 
            ORDER BY plan_expires_at DESC LIMIT 20
        """))
        active_users = [dict(r) for r in cursor.fetchall()]
        
        return {
            "total_users": total_users,
            "active_subscribers": active_subscribers,
            "pending_approvals": pending_approvals,
            "total_revenue": total_revenue,
            "total_lookups": total_lookups,
            "active_users": active_users,
            "engine": "PostgreSQL" if IS_POSTGRES else "SQLite"
        }
