import os
from flask import Flask, request, jsonify, render_template
import requests

app = Flask(__name__)

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
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
