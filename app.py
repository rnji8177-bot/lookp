import os
import re
import csv
import io
import json
import time
import secrets
import sqlite3
import threading
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, Response
import requests
from dotenv import load_dotenv

import db

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Secret key generation / loading
app.secret_key = os.getenv("SECRET_KEY", "osint-lookup-premium-secret-key-391823-prod-safe")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)

# Initialize SQLite database & migrations
db.init_db()

# Configuration from .env
ACTIVEPIECES_WEBHOOK = os.getenv("ACTIVEPIECES_WEBHOOK", "https://cloud.activepieces.com/api/v1/webhooks/JFSUrToq7TDvTa5oHmBMp")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "8931669383:AAEiPZMhLHTOMXfD0CdNPw0BuAgLLQT9YkU")
ADMIN_CHAT_ID = os.getenv("ADMIN_CHAT_ID", "7166502503")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "Priy@nka00")
ADMIN_SECRET_TOKEN = os.getenv("ADMIN_SECRET_TOKEN", "osint_admin_secret_9988")
LOOKUP_API_KEY = os.getenv("LOOKUP_API_KEY", "anshapi")
LOOKUP_API_BASE = os.getenv("LOOKUP_API_BASE", "https://anshapi.vercel.app/api/num")
UPI_ID = os.getenv("UPI_ID", "s.maddheshia@ptaxis")
PAYEE_NAME = os.getenv("PAYEE_NAME", "SANDESH KUMAR MADDHESHIA")

# ==========================================
# In-Memory Rate Limiter (Anti-Brute-Force & Abuse)
# ==========================================
RATE_LIMIT_STORE = {}

def is_rate_limited(bucket_key, max_attempts=5, window_seconds=300):
    now = time.time()
    attempts = RATE_LIMIT_STORE.get(bucket_key, [])
    # Filter attempts within window
    valid_attempts = [t for t in attempts if now - t < window_seconds]
    if len(valid_attempts) >= max_attempts:
        RATE_LIMIT_STORE[bucket_key] = valid_attempts
        return True
    valid_attempts.append(now)
    RATE_LIMIT_STORE[bucket_key] = valid_attempts
    return False

def get_client_ip():
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
    return request.remote_addr or "127.0.0.1"

def get_device_fingerprint():
    return request.args.get("fp") or request.headers.get("X-Device-Fingerprint") or ""

def _dispatch_telegram(text):
    if not TELEGRAM_BOT_TOKEN or not ADMIN_CHAT_ID:
        return
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        requests.post(url, json={"chat_id": ADMIN_CHAT_ID, "text": text, "parse_mode": "HTML"}, timeout=4)
    except Exception as e:
        pass

def send_telegram_message(text):
    """Asynchronous background alert dispatcher so HTTP requests never block"""
    threading.Thread(target=_dispatch_telegram, args=(text,), daemon=True).start()

def _dispatch_webhook(payload):
    if not ACTIVEPIECES_WEBHOOK:
        return
    try:
        requests.post(ACTIVEPIECES_WEBHOOK, json=payload, timeout=4)
    except Exception:
        pass

def trigger_webhook_async(payload):
    threading.Thread(target=_dispatch_webhook, args=(payload,), daemon=True).start()



# ==========================================
# Authentication Guard Decorator
# ==========================================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id:
            if request.path.startswith("/api/") or request.path == "/lookup":
                return jsonify({"error": "AUTH_REQUIRED", "message": "Kripya aage badhne ke liye login karein.", "redirect": "/login"}), 401
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated_function

# ==========================================
# Health Check Routes (For Antideploy / Cloud probes)
# ==========================================

@app.route("/health")
@app.route("/healthz")
def health():
    return jsonify({
        "status": "healthy",
        "service": "osint-phone-lookup",
        "timestamp": datetime.utcnow().isoformat()
    }), 200

# ==========================================
# User Authentication Routes (Register / Login / Logout)
# ==========================================

@app.route("/login", methods=["GET"])
def login_page():
    if session.get("user_id"):
        return redirect(url_for("home"))
    return render_template("auth.html", tab="login")

@app.route("/register", methods=["GET"])
def register_page():
    if session.get("user_id"):
        return redirect(url_for("home"))
    return render_template("auth.html", tab="register")

@app.route("/api/register", methods=["POST"])
def api_register():
    ip = get_client_ip()
    # Rate limit: max 4 registrations per 15 minutes per IP
    if is_rate_limited(f"reg_{ip}", max_attempts=4, window_seconds=900):
        return jsonify({"error": "Bahut saare registration attempts! Kripya 15 minute baad prayas karein."}), 429

    payload = request.get_json() or {}
    username = payload.get("username", "").strip()
    email = payload.get("email", "").strip()
    password = payload.get("password", "")
    phone = payload.get("phone", "")
    fp = payload.get("fingerprint") or get_device_fingerprint()

    if not username or not email or not password:
        return jsonify({"error": "Username, email aur password required hain!"}), 400

    success, result = db.register_user(username, email, password, phone, ip, fp)
    if not success:
        return jsonify({"error": result}), 400

    user = result
    # Automatically log the user in
    session.permanent = True
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user.get("role", "user")

    # Send telegram alert for new registration
    try:
        reg_msg = f"<b>👤 New User Registered!</b>\n"
        reg_msg += f"Username: <b>{user['username']}</b>\n"
        reg_msg += f"Email: <code>{user['email']}</code>\n"
        reg_msg += f"IP: <code>{ip}</code>\n"
        reg_msg += f"Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}"
        send_telegram_message(reg_msg)
    except Exception:
        pass

    return jsonify({
        "success": True,
        "message": "Account successfully created!",
        "redirect": "/",
        "user": user
    })

@app.route("/api/login", methods=["POST"])
def api_login():
    ip = get_client_ip()
    # Rate limit: max 6 failed logins per 10 minutes per IP
    if is_rate_limited(f"login_fail_{ip}", max_attempts=6, window_seconds=600):
        return jsonify({"error": "Too many failed attempts! Security cooldown active. Kripya 10 minute baad try karein."}), 429

    payload = request.get_json() or {}
    identifier = payload.get("identifier", "").strip()
    password = payload.get("password", "")
    fp = payload.get("fingerprint") or get_device_fingerprint()

    if not identifier or not password:
        return jsonify({"error": "Username/Email aur Password dono enter karein."}), 400

    success, result = db.authenticate_user(identifier, password, ip, fp)
    if not success:
        return jsonify({"error": result}), 401

    user = result
    session.permanent = True
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user.get("role", "user")

    return jsonify({
        "success": True,
        "message": "Authentication successful!",
        "redirect": "/",
        "user": user
    })

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))

# ==========================================
# Frontend Protected Dashboard Route
# ==========================================

@app.route("/")
@login_required
def home():
    user_id = session.get("user_id")
    user = db.get_user_by_id(user_id)
    if not user:
        session.clear()
        return redirect(url_for("login_page"))

    if user.get("is_banned"):
        session.clear()
        return render_template("auth.html", error="Aapka account suspend kar diya gaya hai.")

    free_used = user.get("free_lookups_used", 0)
    free_left = max(0, 3 - free_used)
    user["free_lookups_left"] = free_left

    expires_in_human = None
    if user["plan_status"] == "premium" and user["plan_expires_at"]:
        try:
            exp = datetime.fromisoformat(user["plan_expires_at"])
            remaining = exp - datetime.utcnow()
            if remaining.total_seconds() > 0:
                hours = int(remaining.total_seconds() // 3600)
                minutes = int((remaining.total_seconds() % 3600) // 60)
                if hours >= 24:
                    days = hours // 24
                    expires_in_human = f"{days}d {hours % 24}h remaining"
                else:
                    expires_in_human = f"{hours}h {minutes}m remaining"
            else:
                expires_in_human = "Expired"
        except Exception:
            pass
    user["expires_in_human"] = expires_in_human

    return render_template("index.html", current_user=user, upi_id=UPI_ID, payee_name=PAYEE_NAME)

# ==========================================
# User & Subscription API Routes
# ==========================================

@app.route("/api/user-status", methods=["GET"])
@login_required
def user_status():
    user_id = session.get("user_id")
    user = db.get_user_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    pending_payment = db.get_latest_pending_payment(user_id)
    free_used = user.get("free_lookups_used", 0)
    free_left = max(0, 3 - free_used)
    
    expires_in_human = None
    if user["plan_status"] == "premium" and user["plan_expires_at"]:
        try:
            exp = datetime.fromisoformat(user["plan_expires_at"])
            remaining = exp - datetime.utcnow()
            if remaining.total_seconds() > 0:
                hours = int(remaining.total_seconds() // 3600)
                minutes = int((remaining.total_seconds() % 3600) // 60)
                if hours >= 24:
                    days = hours // 24
                    expires_in_human = f"{days}d {hours % 24}h remaining"
                else:
                    expires_in_human = f"{hours}h {minutes}m remaining"
            else:
                expires_in_human = "Expired"
        except Exception:
            pass

    return jsonify({
        "user_id": user["id"],
        "username": user.get("username", "User"),
        "plan_status": user["plan_status"],
        "plan_type": user["plan_type"],
        "free_lookups_used": free_used,
        "free_lookups_left": free_left,
        "is_premium": user["plan_status"] == "premium",
        "plan_expires_at": user["plan_expires_at"],
        "expires_in_human": expires_in_human,
        "pending_payment": pending_payment,
        "upi_id": UPI_ID,
        "payee_name": PAYEE_NAME
    })

@app.route("/lookup", methods=["GET"])
@login_required
def lookup():
    raw_number = request.args.get("number", "")
    # User ID is strictly retrieved from the authenticated server session
    user_id = session.get("user_id")
    fp = get_device_fingerprint()
    ip = get_client_ip()

    # Rate limiting on lookups: max 12 requests per minute
    if is_rate_limited(f"lookup_{user_id}_{ip}", max_attempts=12, window_seconds=60):
        return jsonify({
            "error": "RATE_LIMITED",
            "message": "Aap bahut tezi se searches kar rahe hain! Kripya 30 seconds wait karein."
        }), 429

    # Clean phone number (extract digits only)
    cleaned_number = re.sub(r"\D", "", raw_number)
    
    # Handle country code (+91 or 91 prefix)
    if len(cleaned_number) == 12 and cleaned_number.startswith("91"):
        cleaned_number = cleaned_number[2:]
    elif len(cleaned_number) == 11 and cleaned_number.startswith("0"):
        cleaned_number = cleaned_number[1:]
        
    if len(cleaned_number) != 10:
        return jsonify({
            "error": "Invalid phone number",
            "message": "Kripya valid 10-digit Indian phone number enter karein (e.g. 9876543210)"
        }), 400

    # 1. Anti-Abuse Check: Authenticated User + Device Fingerprint + IP Quota Check
    can_lookup, reason, user = db.can_user_lookup(user_id, ip, fp)
    if not can_lookup:
        return jsonify({
            "error": "LIMIT_REACHED",
            "require_plan": True,
            "message": "Aapki 3 Free Lookups limit khatam ho chuki hai! Aage search karne ke liye Premium Plan choose karein.",
            "free_lookups_used": user.get("free_lookups_used", 3),
            "free_lookups_left": 0
        }), 403

    # 2. Fetch data from OSINT API
    data = None
    try:
        api_url = f"{LOOKUP_API_BASE}?key={LOOKUP_API_KEY}&number={cleaned_number}"
        response = requests.get(api_url, timeout=7, headers={"User-Agent": "Mozilla/5.0 OSINT Lookup Pro/3.0"})
        if response.status_code == 200:
            data = response.json()
    except Exception as e:
        print(f"Upstream API lookup error: {e}")
        data = None

    # Fallback demo simulator for test numbers if upstream times out
    if not data or not isinstance(data, (dict, list)):
        if cleaned_number in ["9876543210", "9999999999", "8888888888", "7777777777", "9123456789"]:
            data = {
                "status": "success",
                "phone": cleaned_number,
                "name": "VIKRAM SINGH RATHORE",
                "father_name": "RAMESH SINGH",
                "carrier": "Reliance Jio Infocomm",
                "circle": "Delhi NCR / North India",
                "address": "Flat 402, Royal Palms, Block B, Sector 62",
                "city": "Noida",
                "district": "Gautam Buddha Nagar",
                "state": "Uttar Pradesh",
                "pincode": "201309",
                "alternate_numbers": ["9811223344", "8800112233"],
                "gender": "Male",
                "lookup_type": "Verified Telecom Node Record"
            }
        else:
            return jsonify({
                "error": "UPSTREAM_TIMEOUT",
                "message": "Telecom lookup server abhi busy hai ya time out ho raha hai. Kripya 10-15 seconds me dobara prayas karein."
            }), 504

    # 3. Record lookup usage in DB
    db.record_lookup_usage(user_id, cleaned_number, ip_address=ip, device_fingerprint=fp, data_payload=data, success=True)
    
    # Refresh updated user stats
    updated_user = db.get_user_by_id(user_id)
    free_used = updated_user.get("free_lookups_used", 0)
    free_left = max(0, 3 - free_used)

    # 4. Trigger Activepieces Webhook (Non-blocking background thread)
    trigger_webhook_async({
        "number": cleaned_number,
        "user_id": user_id,
        "username": session.get("username", ""),
        "ip": ip,
        "fingerprint": fp,
        "data": data,
        "timestamp": datetime.utcnow().isoformat()
    })


    # 5. Trigger Telegram Admin Notification
    try:
        summary_str = f"<b>🔍 New OSINT Lookup Alert</b>\n"
        summary_str += f"📱 <b>Number:</b> <code>{cleaned_number}</code>\n"
        summary_str += f"👤 <b>User:</b> <b>{session.get('username', user_id)}</b>\n"
        summary_str += f"🌐 <b>IP:</b> <code>{ip}</code>\n"
        summary_str += f"💎 <b>Plan:</b> {updated_user.get('plan_status', 'free').upper()}\n"
        summary_str += f"⏰ <b>Time:</b> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}"
        send_telegram_message(summary_str)
    except Exception as e:
        print(f"Telegram alert error: {e}")

    return jsonify({
        "success": True,
        "number": cleaned_number,
        "data": data,
        "is_premium": updated_user["plan_status"] == "premium",
        "free_lookups_used": free_used,
        "free_lookups_left": free_left
    })

# ==========================================
# Payment & Approval Routes
# ==========================================

@app.route("/api/submit-payment", methods=["POST"])
@login_required
def submit_payment():
    user_id = session.get("user_id")
    payload = request.get_json() or {}
    plan_type = payload.get("plan_type")
    utr = payload.get("utr", "").strip()
    user_note = payload.get("user_note", "").strip()

    if plan_type not in ["1day", "7days"]:
        return jsonify({"error": "Invalid plan selected. Choose 1day or 7days"}), 400

    if not utr or len(utr) < 6:
        return jsonify({"error": "Kripya valid 12-digit UPI UTR / Transaction Reference Number enter karein."}), 400

    # Anti-Cheat: Prevent duplicate UTR submission
    if db.is_utr_already_used(utr):
        return jsonify({"error": "Ye UTR / Reference ID pehle se submit kiya ja chuka hai! Duplicate submission allowed nahi hai."}), 400

    amount = 20 if plan_type == "1day" else 120
    plan_title = "1 Day Pass (24 Hours)" if plan_type == "1day" else "7 Days Pass (1 Week)"

    # Create payment request in database
    req = db.create_payment_request(user_id, plan_type, amount, utr, user_note)
    req_id = req["id"]

    username = session.get("username", user_id)

    # Send Instant Telegram Alert to Admin with Quick-Approve Link
    host = request.host_url.rstrip('/')
    quick_approve_url = f"{host}/admin/quick-approve?req_id={req_id}&token={ADMIN_SECRET_TOKEN}"
    admin_panel_url = f"{host}/admin"

    msg = f"<b>🚨 NAYI PAYMENT APPROVAL REQUEST!</b>\n"
    msg += f"━━━━━━━━━━━━━━━━━━━━\n"
    msg += f"🆔 <b>Request ID:</b> <code>{req_id}</code>\n"
    msg += f"👤 <b>Username:</b> <b>{username}</b>\n"
    msg += f"💳 <b>Plan:</b> <b>{plan_title}</b>\n"
    msg += f"💰 <b>Amount:</b> ₹{amount}\n"
    msg += f"🔢 <b>UTR / Txn Ref:</b> <code>{utr}</code>\n"
    if user_note:
        msg += f"📝 <b>Note:</b> {user_note}\n"
    msg += f"⏰ <b>Time:</b> {datetime.utcnow().strftime('%d-%m-%Y %I:%M %p')}\n"
    msg += f"━━━━━━━━━━━━━━━━━━━━\n"
    msg += f"👉 <b>1-Click Quick Approve:</b>\n{quick_approve_url}\n\n"
    msg += f"🛠 <b>Open Admin Panel:</b>\n{admin_panel_url}"

    send_telegram_message(msg)

    return jsonify({
        "success": True,
        "message": "Payment details submitted! Admin verification in progress.",
        "request": req
    })

# ==========================================
# Admin Panel & Approval Endpoints
# ==========================================

@app.route("/admin", methods=["GET", "POST"])
def admin_panel():
    if request.method == "POST":
        entered_pass = request.form.get("admin_key") or request.form.get("password")
        if entered_pass == ADMIN_PASSWORD:
            session["admin_logged_in"] = True
            return redirect(url_for("admin_panel"))
        else:
            return render_template("admin.html", error="Galat Master Key! Dobara koshish karein.", logged_in=False)

    if session.get("admin_logged_in"):
        stats = db.get_admin_stats()
        payment_requests = db.get_all_payment_requests()
        all_users = db.admin_get_all_users(limit=100)
        
        # Search & Date Filters for Logs
        search_query = request.args.get("q", "").strip()
        date_filter = request.args.get("date", "").strip()
        logs = db.get_lookup_logs(search_query=search_query, date_filter=date_filter, limit=100)

        return render_template("admin.html", 
                               logged_in=True, 
                               stats=stats, 
                               payment_requests=payment_requests,
                               all_users=all_users,
                               logs=logs,
                               search_query=search_query,
                               date_filter=date_filter,
                               admin_token=ADMIN_SECRET_TOKEN)

    return render_template("admin.html", logged_in=False)

@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_logged_in", None)
    return redirect(url_for("admin_panel"))

@app.route("/api/payment-review", methods=["POST"])
@app.route("/admin/action", methods=["POST"])
def admin_action():
    if not session.get("admin_logged_in") and request.headers.get("X-Admin-Token") != ADMIN_SECRET_TOKEN:
        return jsonify({"error": "Unauthorized"}), 401

    payload = request.get_json() or {}
    action = payload.get("action")
    req_id = payload.get("request_id")

    if not req_id:
        return jsonify({"error": "Request ID required"}), 400

    if action == "approve":
        success, result = db.approve_payment_request(req_id)
        if success:
            send_telegram_message(f"✅ <b>Payment Approved!</b>\nReq ID: <code>{req_id}</code>\nUser: <b>{result.get('username', result['user_id'])}</b>\nExpiry: {result['new_expiry']}")
            return jsonify({"success": True, "data": result})
        return jsonify({"error": result}), 400

    elif action == "reject":
        success, result = db.reject_payment_request(req_id)
        if success:
            send_telegram_message(f"❌ <b>Payment Rejected!</b>\nReq ID: <code>{req_id}</code>")
            return jsonify({"success": True})
        return jsonify({"error": result}), 400

    return jsonify({"error": "Invalid action"}), 400

@app.route("/admin/api/log/<int:log_id>")
def admin_log_detail(log_id):
    if not session.get("admin_logged_in") and request.headers.get("X-Admin-Token") != ADMIN_SECRET_TOKEN:
        return jsonify({"error": "Unauthorized"}), 401

    log = db.get_log_detail(log_id)
    if not log:
        return jsonify({"error": "Log record not found"}), 404
        
    return jsonify(log)

@app.route("/admin/user-action", methods=["POST"])
def admin_user_action():
    if not session.get("admin_logged_in") and request.headers.get("X-Admin-Token") != ADMIN_SECRET_TOKEN:
        return jsonify({"error": "Unauthorized"}), 401

    payload = request.get_json() or {}
    action = payload.get("action")
    target_user_id = payload.get("user_id")

    if not target_user_id:
        return jsonify({"error": "Target user ID required"}), 400

    if action == "grant_vip":
        days = int(payload.get("days", 7))
        success, exp = db.grant_vip_access(target_user_id, days)
        return jsonify({"success": success, "new_expiry": exp})
    elif action == "reset_quota":
        success = db.reset_user_quota(target_user_id)
        return jsonify({"success": success})
    elif action == "toggle_ban":
        success, new_state = db.admin_toggle_ban_user(target_user_id)
        return jsonify({"success": success, "is_banned": new_state})

    return jsonify({"error": "Invalid action"}), 400

@app.route("/admin/update-key", methods=["POST"])
@app.route("/admin/change-password", methods=["POST"])
def admin_change_password():
    if not session.get("admin_logged_in"):
        return jsonify({"error": "Unauthorized"}), 401
        
    payload = request.get_json() or {}
    old_pass = payload.get("old_key") or payload.get("old_password", "")
    new_pass = (payload.get("new_key") or payload.get("new_password", "")).strip()
    
    global ADMIN_PASSWORD
    if old_pass != ADMIN_PASSWORD:
        return jsonify({"error": "Current password galat hai! Kripya sahi password enter karein."}), 400
        
    if len(new_pass) < 6:
        return jsonify({"error": "Naya password kam se kam 6 characters ka hona chahiye!"}), 400
        
    ADMIN_PASSWORD = new_pass
    
    # Update in .env file securely
    try:
        env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
        if os.path.exists(env_path):
            with open(env_path, "r", encoding="utf-8") as f:
                content = f.read()
            if "ADMIN_PASSWORD=" in content:
                content = re.sub(r"ADMIN_PASSWORD=.*", f"ADMIN_PASSWORD={new_pass}", content)
            else:
                content += f"\nADMIN_PASSWORD={new_pass}\n"
            with open(env_path, "w", encoding="utf-8") as f:
                f.write(content)
    except Exception as e:
        print("Error updating .env password:", e)

    send_telegram_message(f"🔐 <b>Admin Password Updated!</b>\nNew password set successfully from IP: <code>{get_client_ip()}</code>")

    return jsonify({"success": True, "message": "Password successfully updated!"})

@app.route("/admin/export-logs")
def export_logs():
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_panel"))

    logs = db.get_lookup_logs(limit=2000)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Log ID", "Date Time (UTC)", "User ID", "Username", "IP Address", "Device Fingerprint", "Phone Number", "Status"])
    for l in logs:
        writer.writerow([l["id"], l["timestamp"], l["user_id"], l.get("username", "N/A"), l["ip_address"] or "N/A", l["device_fingerprint"] or "N/A", l["phone_number"], l["status"]])
        
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=OSINT_Lookup_Audit_Logs.csv"}
    )

@app.route("/admin/quick-approve", methods=["GET"])
def quick_approve():
    token = request.args.get("token")
    req_id = request.args.get("req_id")

    if token != ADMIN_SECRET_TOKEN:
        return "<h2 style='color:red; font-family:sans-serif;'>❌ Invalid or expired admin token!</h2>", 403

    if not req_id:
        return "<h2 style='color:red; font-family:sans-serif;'>❌ Missing request ID!</h2>", 400

    success, result = db.approve_payment_request(req_id)
    if success:
        send_telegram_message(f"⚡ <b>Quick Approved via Telegram Link!</b>\nReq ID: <code>{req_id}</code>\nUser: <b>{result.get('username', result['user_id'])}</b>")
        return f"""
        <html>
        <head><title>Payment Approved</title></head>
        <body style="background:#090d16; color:#00f5a0; font-family:sans-serif; text-align:center; padding:50px;">
            <div style="background:rgba(255,255,255,0.05); border:1px solid #00f5a0; border-radius:16px; padding:30px; display:inline-block; max-width:500px;">
                <h1 style="font-size:40px; margin-bottom:10px;">✅ Approved!</h1>
                <p style="color:#ffffff; font-size:18px;">Payment Request <b>{req_id}</b> has been successfully approved.</p>
                <div style="background:#111827; padding:15px; border-radius:8px; text-align:left; margin:20px 0; color:#9ca3af; font-family:monospace;">
                    <div>User: <span style="color:#fff;">{result.get('username', result['user_id'])}</span></div>
                    <div>Plan: <span style="color:#00f5a0;">{result['plan_type'].upper()}</span></div>
                    <div>Valid Until: <span style="color:#ffd700;">{result['new_expiry']}</span></div>
                </div>
                <a href="/admin" style="display:inline-block; padding:12px 24px; background:#00f5a0; color:#000; font-weight:bold; text-decoration:none; border-radius:8px;">Open Admin Panel</a>
            </div>
        </body>
        </html>
        """
    else:
        return f"<h2 style='color:red; font-family:sans-serif;'>❌ Error: {result}</h2>", 400

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("DEBUG", "False").lower() in ["true", "1"]
    app.run(host="0.0.0.0", port=port, debug=debug)
