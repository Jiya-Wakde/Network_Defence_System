from flask import Flask, render_template, request, jsonify
from flask_cors import CORS

import json
import os
import pickle
import whois
import datetime
import Levenshtein
import re
from urllib.parse import urlparse


app = Flask(__name__)
CORS(app)


# -----------------------------
# Load ML Models
# -----------------------------

url_model = pickle.load(open("url_model.pkl","rb"))
vectorizer = pickle.load(open("url_vectorizer.pkl","rb"))


# -----------------------------
# Manual Phishing Websites
# -----------------------------

manual_phish_domains = {

"bitpaxos.com",
"brightonboard.com",
"universalcb.org",
"moneyswift.munya.co.zw",
"allegrolokalnie.pl-aukcja189560.icu",
"fynterasprime.com",
"fintechelitepro.sbs",
"expresscargopro.sbs"
}


# -----------------------------
# Known Brands
# -----------------------------

brands = [
"google","amazon","facebook","netflix",
"paypal","apple","microsoft","sbi","paytm","github"
]


# -----------------------------
# Extract Domain
# -----------------------------

def get_domain(url):

    try:

        parsed = urlparse(url)

        return parsed.netloc.lower()

    except:

        return ""


# -----------------------------
# Manual Phishing Detection
# -----------------------------

def is_manual_phish(url):

    domain = get_domain(url)

    for bad in manual_phish_domains:

        if bad in domain:
            return True

    return False


# -----------------------------
# ML Prediction
# -----------------------------

def ml_predict(url):

    vec = vectorizer.transform([url])

    pred = url_model.predict(vec)[0]

    prob = url_model.predict_proba(vec).max()

    return pred, prob


# -----------------------------
# Typosquatting detection
# -----------------------------

def typo_check(url):

    domain = get_domain(url)

    name = domain.split(".")[0]

    for brand in brands:

        distance = Levenshtein.distance(name, brand)

        if distance <= 2 and name != brand:
            return True

    return False


# -----------------------------
# Domain age check
# -----------------------------

def domain_age(url):

    try:

        domain = get_domain(url)

        w = whois.whois(domain)

        creation = w.creation_date

        if isinstance(creation, list):
            creation = creation[0]

        age = (datetime.datetime.now() - creation).days

        return age

    except:
        return None


# -----------------------------
# Detection Engine
# -----------------------------

def detect_url(url):

    risk = 0

    url_lower = url.lower()


    # -----------------------------
    # Manual phishing list
    # -----------------------------

    if is_manual_phish(url):

        return {
            "url": url,
            "risk_score": 100,
            "status": "Phishing",
            "confidence": 1.0
        }


    pred, prob = ml_predict(url)

    if pred == 1:
        risk += 40


    keywords = [
        "login","verify","secure","account",
        "bank","confirm","update","signin","password"
    ]

    keyword_hits = sum(1 for k in keywords if k in url_lower)

    risk += keyword_hits * 20


    if typo_check(url):
        risk += 40


    suspicious_tlds = [
        ".xyz",".top",".tk",".ml",".ga",".cf"
    ]

    if any(url_lower.endswith(tld) for tld in suspicious_tlds):
        risk += 25


    age = domain_age(url)

    if age is not None:

        if age < 30:
            risk += 40

        elif age < 180:
            risk += 20


    if url.count("-") >= 2:
        risk += 15


    if len(url) > 60:
        risk += 10


    risk = min(risk,92)

    log_scan(url, risk)

    status = "Phishing" if risk >= 60 else "Safe"


    return {
        "url": url,
        "risk_score": risk,
        "status": status,
        "confidence": round(prob,2)
    }


# -----------------------------
# URL detection helper
# -----------------------------

def is_url(text):

    pattern = re.compile(r"https?://|www\.")

    return bool(pattern.search(text))


# -----------------------------
# Web Routes
# -----------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["GET","POST"])
def scan():

    result = None

    if request.method == "POST":

        text = request.form.get("url")

        if text:

            if is_url(text):

                result = detect_url(text)

    return render_template("scan.html", result=result)



@app.route("/extension")
def extension():
    return render_template("extension.html")

def log_scan(url, risk):

    log = {
        "url": url,
        "risk_score": risk
    }

    if not os.path.exists("scan_logs.json"):

        with open("scan_logs.json","w") as f:
            json.dump([],f)

    with open("scan_logs.json","r") as f:
        data = json.load(f)

    data.append(log)

    with open("scan_logs.json","w") as f:
        json.dump(data,f)
# -----------------------------
# API for Chrome Extension
# -----------------------------

@app.route("/api/scan", methods=["POST"])
def api_scan():

    data = request.get_json()

    url = data.get("url")

    result = detect_url(url)

    return jsonify(result)


# -----------------------------
def get_threat_stats():

    if not os.path.exists("scan_logs.json"):
        return None

    with open("scan_logs.json") as f:
        data = json.load(f)

    if not data:
        return None

    total = len(data)

    risky = sum(1 for x in data if x["risk_score"] >= 60)

    safe = total - risky

    safe_percent = round((safe/total)*100)

    risky_percent = round((risky/total)*100)

    most_dangerous = max(data, key=lambda x: x["risk_score"])

    return {

        "most_url": most_dangerous["url"],
        "risk_score": most_dangerous["risk_score"],
        "safe_percent": safe_percent,
        "risky_percent": risky_percent,
        "total": total

    }

@app.route("/threats")
def threats():

    stats = get_threat_stats()

    return render_template("threat.html", stats=stats)


if __name__ == "__main__":
    app.run(debug=True)