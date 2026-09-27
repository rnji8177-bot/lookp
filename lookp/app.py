import os
from flask import Flask, request, jsonify, render_template
import requests

app = Flask(__name__)

# Activepieces webhook URL
ACTIVEPIECES_WEBHOOK = "https://cloud.activepieces.com/api/v1/webhooks/JFSUrToq7TDvTa5oHmBMp"

# Telegram Bot details
TELEGRAM_BOT_TOKEN = "8931669383:AAEiPZMhLHTOMXfD0CdNPw0BuAgLLQT9YkU"
ADMIN_CHAT_ID = "7166502503"

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/lookup", methods=["GET"])
def lookup():
    number = request.args.get("number")
    if not number:
        return jsonify({"error": "No number provided"}), 400
    try:
        api_url = f"https://anshapi.vercel.app/api/num?key=anshapi&number={number}"
        response = requests.get(api_url, timeout=10)
        data = response.json()

        # ✅ Send lookup result to Activepieces webhook
        try:
            requests.post(ACTIVEPIECES_WEBHOOK, json=data)
        except Exception as e:
            print(f"Activepieces webhook error: {e}")

        # ✅ Send Telegram alert to admin
        try:
            alert_text = (
                f"🔍 Lookup Alert\n"
                f"Number: {data.get('number','N/A')}\n"
                f"Status: {data.get('status','N/A')}\n"
                f"Name: {data.get('name','N/A')}"
            )
            requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                json={"chat_id": ADMIN_CHAT_ID, "text": alert_text}
            )
        except Exception as e:
            print(f"Telegram alert error: {e}")

        return jsonify(data)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
