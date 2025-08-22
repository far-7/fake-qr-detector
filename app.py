import os
import time
import threading
import base64
import requests
from flask import Flask, render_template, request, redirect, url_for
from pyzbar.pyzbar import decode
from PIL import Image
from dotenv import load_dotenv

# Load API keys from .env
load_dotenv()
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")

app = Flask(__name__)
app.secret_key = "supersecretkey"

# Upload folder for temporary QR images
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Temporary storage for scan results
TEMP_RESULTS = {}

# Auto-delete results after 1 minute
def auto_delete_result(scan_id):
    time.sleep(60)
    TEMP_RESULTS.pop(scan_id, None)

# Extract URL from QR code
def extract_qr_code(filepath):
    img = Image.open(filepath)
    decoded_objects = decode(img)
    for obj in decoded_objects:
        return obj.data.decode("utf-8")
    return None

# Google Safe Browsing API (primary)
def check_google_safe(url):
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
    body = {
        "client": {"clientId": "qr-checker", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(api_url, json=body)
        result = response.json()
        if "matches" in result:
            return {"status":"danger", "message":"⚠️ Unsafe URL detected by Google Safe Browsing"}
        return {"status":"safe", "message":"✅ Safe according to Google Safe Browsing"}
    except Exception as e:
        print(f"[ERROR] Google API failed: {e}")
        return None

# VirusTotal API (backup)
def check_virustotal(url):
    api_url = "https://www.virustotal.com/api/v3/urls"
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(f"{api_url}/{url_id}", headers=headers)
        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
        if stats["malicious"] > 0:
            return {"status":"danger","message":"⚠️ Unsafe URL detected by VirusTotal"}
        return {"status":"safe","message":"✅ Safe according to VirusTotal"}
    except Exception as e:
        print(f"[ERROR] VirusTotal API failed: {e}")
        return {"status":"unknown","message":"⚠️ Could not check with VirusTotal"}

@app.route("/", methods=["GET","POST"])
def index():
    if request.method=="POST":
        if "qrfile" not in request.files:
            return redirect(request.url)
        file = request.files["qrfile"]
        if file.filename == "":
            return redirect(request.url)

        # Save QR image temporarily
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
        file.save(filepath)

        # Extract URL
        qr_data = extract_qr_code(filepath)
        if not qr_data:
            return render_template("result.html", result={"status":"unknown","message":"❌ No QR code detected"})

        # Check URL: Google primary, VirusTotal backup
        result = check_google_safe(qr_data)
        if result is not None:
            result["api"] = "Google Safe Browsing"
        else:
            result = check_virustotal(qr_data)
            result["api"] = "VirusTotal"

        # Store result temporarily and auto-delete after 1 min
        scan_id = str(time.time())
        TEMP_RESULTS[scan_id] = result
        threading.Thread(target=auto_delete_result, args=(scan_id,), daemon=True).start()

        return redirect(url_for("result", scan_id=scan_id, url=qr_data))
    return render_template("index.html")

@app.route("/result/<scan_id>")
def result(scan_id):
    result = TEMP_RESULTS.get(scan_id, {"status":"unknown","message":"Result expired"})
    url = request.args.get("url","")
    return render_template("result.html", result=result, url=url)

if __name__=="__main__":
    app.run(debug=True)


