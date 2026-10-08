# ⚡ OSINT Phone Intelligence Pro (v3.0)

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Flask 3.x](https://img.shields.io/badge/Framework-Flask_3.x-black.svg)](https://flask.palletsprojects.com/)
[![Auth-PBKDF2](https://img.shields.io/badge/Auth-PBKDF2_Hashed-00f5a0.svg)](#)
[![UI-Glassmorphism](https://img.shields.io/badge/UI-Dark_Glassmorphism-00f5a0.svg)](#)
[![Monetization-UPI](https://img.shields.io/badge/Payment-UPI_QR_%2B_Direct_App-ffd700.svg)](#)
[![Alerts-Telegram](https://img.shields.io/badge/Alerts-Telegram_Bot_Async-0088cc.svg)](#)

A high-performance, production-grade **Phone Number OSINT Intelligence & Reconnaissance Platform** built with Flask, SQLite, and an ultra-modern Dark Glassmorphism interface. Designed for cybersecurity analysts, fraud investigators, and scam prevention teams.

---

## 🌟 Key Features (v3.0 Release)

### 1. 🛡️ Advanced Security & Mandatory User Authentication
* **Interactive Cyber Gateway (`/login` & `/register`):**
  * Modern animated cyber matrix canvas background with real-time interactive particle nodes.
  * Fluid dual-tab sliding card switching between **Sign In** and **Create Account**.
  * **PBKDF2 SHA-256 Hashed Passwords:** Zero plaintext storage using Werkzeug security.
  * **Real-time Live Password Entropy Meter:** 4-segment visual indicator (Weak, Fair, Strong, Elite).
  * **Show/Hide Password Toggle** and formatted validation rules.
* **Server-Side Session Guard (`@login_required`):**
  * Mandatory authentication before entering the lookup dashboard.
  * HTTP-only and SameSite protected signed session cookies.
  * Server-enforced identity prevents client-side quota forgery.
* **Anti-Brute-Force & Rate Limiting:**
  * Rate-limits failed login attempts, registrations, and lookup queries.
  * Anti-sybil quota enforcement: prevents users from creating dozens of accounts from the same physical device/IP to abuse free scans.

### 2. 💎 Free Quota & Pro Monetization Paywall
* **3 Free Lookups per User Account:** Every registered user starts with 3 free scans tracked in SQLite.
* **Automated Paywall Lockout:**
  * Once the 3 free scans are exhausted, search is locked with a prominent warning banner.
  * The Pro Membership Modal automatically opens:
    * ⚡ **Daily Pass:** ₹20 / 1 Day (24 Hours Unlimited Searches)
    * 👑 **Weekly Pass:** ₹120 / 7 Days (7 Days Full Unlimited Access) - Most Popular
* **Seamless UPI QR & Direct App Integration:**
  * Displays high-tech scanner frame with Payee QR Code (`/static/qr.png`).
  * Direct 1-Click UPI deep links to launch PhonePe, Google Pay, or Paytm directly with pre-filled amount.
  * One-click UPI ID copy with feedback toast.
* **Anti-Cheat UTR Verification Flow:**
  * Users enter their 12-digit UPI UTR / Reference ID.
  * **Duplicate UTR Protection:** Rejects any UTR that has already been submitted or approved.
  * Non-blocking asynchronous real-time Telegram alert sent to Admin with 1-click quick approval link.
  * Live status auto-polling checks until Admin approves, then automatically activates plan and unlocks searches!

### 3. 🎮 Cyberpunk / FinTech Glassmorphic Dashboard
* **Animated Radar Scanner:** Rotating beam sweep with radar concentric rings and simulated terminal logs during query.
* **Skeleton Loading:** Shimmer placeholders while waiting for telecom routing node responses.
* **Structured Data Presentation:**
  * 🪪 **Identity Profile Card:** Full Name, Father's Name, Telephony verification badge.
  * 📍 **Registered Location Card:** Street address, city, district, state, PIN code + **"Open in Google Maps"** shortcut.
  * 📡 **Telecom Routing Card:** Carrier badge (Jio, Airtel, Vi, BSNL) and regional circle.
  * 🔗 **Linked Contacts:** Clickable chips for alternate numbers that auto-trigger lookup on click!
* **XSS Sanitized Rendering:** Defensive output encoding prevents script injection.
* **Report Tools:** One-click **"Copy Full Report"** and **"Download .TXT"** buttons.
* **Recent Search History:** Local drawer to quickly re-inspect previously queried numbers.

### 4. 🔒 Admin Master Dashboard (`/admin`)
* **Live Telemetry:** Active subscribers count, pending approvals, total revenue collected, total searches ran, registered users count.
* **User Account Management:**
  * View registered usernames, emails, registration dates, and IP logs.
  * **[ +7D VIP ]** and **[ +1D Pass ]** instant manual plan activations.
  * **[ Reset Quota ]** to restore free search counts.
  * **[ Ban / Unban ]** to suspend abusive accounts.
* **Approval Actions:** Review pending UTRs and click **[ ✅ Approve ]** or **[ ❌ Reject ]**.
* **Telegram 1-Click Quick Approve:** Admin can approve payments directly from Telegram without logging in via secure token links.
* **Master Password Management:** Change master access key from the UI with automated `.env` file updating.

---

## 🚀 Quick Setup & Installation

### 1. Clone & Navigate
```bash
git clone https://github.com/rnji8177-bot/lookp.git
cd lookp
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure Environment Variables
Copy `.env.example` to `.env` and fill in your details:
```bash
cp .env.example .env
```

Edit `.env`:
```ini
SECRET_KEY=your_random_secret_key_here
TELEGRAM_BOT_TOKEN=your_telegram_bot_token
ADMIN_CHAT_ID=your_chat_id
ADMIN_PASSWORD=your_admin_master_password
ADMIN_SECRET_TOKEN=your_unique_secret_token
UPI_ID=s.maddheshia@ptaxis
PAYEE_NAME=SANDESH KUMAR MADDHESHIA
PORT=5000
```

### 4. Run the Application
```bash
python app.py
```
* Main Application: `http://localhost:5000` (Redirects to `/login` if unauthenticated)
* Admin Dashboard: `http://localhost:5000/admin`

---

## 📁 Project Architecture

```
lookp/
├── app.py                  # Main Flask application, authentication & API routes
├── db.py                   # SQLite engine, password hashing, quota & telemetry
├── requirements.txt        # Python package dependencies (Flask, Werkzeug, Requests, etc.)
├── .env.example            # Environment variables template
├── .gitignore              # Protects secrets and database from git commits
├── static/
│   ├── style.css           # Ultra-modern dark glassmorphism stylesheet
│   ├── script.js           # Client controller, XSS sanitizer & payment poller
│   ├── qr.png              # Futuristic UPI QR Code
│   └── qr_cyber.png        # Cyberpunk QR asset
└── templates/
    ├── auth.html           # Advanced animated cyber Login & Register portal
    ├── index.html          # Main authenticated OSINT lookup dashboard
    └── admin.html          # Admin dashboard & user account manager
```

---

## 🌐 Deployment Guide (Antideploy.com / Render / Railway)

### Deploying to Antideploy.com:
1. **Push your Code to GitHub:**
   - Commit all changes to your repository (`rnji8177-bot/lookp`).
2. **Create New Web Service on Antideploy:**
   - Log in to [antideploy.com](https://antideploy.com) and click **"New Project" / "Deploy Git Repo"**.
   - Connect your GitHub account and select this repository.
3. **Configure Build & Start Commands:**
   - **Environment / Runtime:** `Python 3.10+`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app --workers 2 --bind 0.0.0.0:$PORT`
4. **Set Environment Variables:**
   Under project **Environment Variables / Settings**, add:
   * `SECRET_KEY` = `generate_a_random_hex_string`
   * `TELEGRAM_BOT_TOKEN` = `your_telegram_bot_token`
   * `ADMIN_CHAT_ID` = `your_telegram_chat_id`
   * `ADMIN_PASSWORD` = `your_secure_password`
   * `ADMIN_SECRET_TOKEN` = `your_unique_random_token_string`
   * `UPI_ID` = `s.maddheshia@ptaxis`
   * `PAYEE_NAME` = `SANDESH KUMAR MADDHESHIA`
5. **Deploy & Verify:**
   - Click **Deploy**. Once the build finishes, open your live HTTPS URL.
   - Test `/register`, `/login`, `/` (dashboard), and `/admin`.

---

## 🔒 Security Best Practices
* **Zero Hardcoded Secrets in Git:** Always keep `.env` and `*.db` in `.gitignore`.
* **Password Hashing:** All user passwords are encrypted using PBKDF2:SHA256 with secure salt.
* **Output Sanitization:** All telecom records are strictly sanitized against XSS attacks before rendering.
* **Asynchronous Alerts:** All Telegram notifications and webhooks execute on daemon threads to prevent denial-of-service and latency bottlenecks.

---

## ⚖️ Legal Disclaimer
This software is intended strictly for educational, cybersecurity research, fraud prevention, and scam tracing purposes under applicable telecommunications and cyber laws. The authors assume no liability for misuse.
