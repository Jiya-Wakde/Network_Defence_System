from flask import Flask, render_template, request, jsonify
from flask_cors import CORS

import pickle
import whois
import datetime
import Levenshtein
import re
from urllib.parse import urlparse


app = Flask(__name__)
CORS(app)


# --------------------------------------------------
# Load ML Model
# --------------------------------------------------

print("Loading URL detection model...")

url_model = pickle.load(open("url_model.pkl", "rb"))
url_vectorizer = pickle.load(open("url_vectorizer.pkl", "rb"))

print("Model loaded successfully")


# --------------------------------------------------
# Known Brands (typosquatting detection)
# --------------------------------------------------

brands = [
"google","amazon","facebook","netflix",
"paypal","apple","microsoft","github",
"sbi","paytm","allegro","alibaba"
]


# --------------------------------------------------
# Manual phishing domains (guaranteed detection)
# --------------------------------------------------

blacklist_domains = [

"bitpaxos.com",
"brightonboard.com",
"universalcb.org",
"moneyswift.munya.co.zw",
"allegrolokalnie.pl-aukcja189560.icu"

]


# --------------------------------------------------
# Normalize URL
# --------------------------------------------------

def normalize_url(url):

    url = url.strip().lower()

    if not url.startswith("http"):
        url = "http://" + url

    return url


# --------------------------------------------------
# Extract domain
# --------------------------------------------------

def get_domain(url):

    try:

        parsed = urlparse(url)

        return parsed.netloc.lower()

    except:

        return ""


# --------------------------------------------------
# ML prediction
# --------------------------------------------------

def ml_predict(url):

    vec = url_vectorizer.transform([url])

    pred = url_model.predict(vec)[0]

    prob = url_model.predict_proba(vec).max()

    return pred, prob


# --------------------------------------------------
# Check blacklist
# --------------------------------------------------

def is_blacklisted(url):

    domain = get_domain(url)

    for bad in blacklist_domains:

        if bad in domain:
            return True

    return False


# --------------------------------------------------
# Typosquatting detection
# --------------------------------------------------

def typo_check(url):

    domain = get_domain(url)

    name = domain.split(".")[0]

    for brand in brands:

        distance = Levenshtein.distance(name, brand)

        if distance <= 2 and name != brand:
            return True

        if brand in name and brand != name:
            return True

    return False


# --------------------------------------------------
# Domain age detection
# --------------------------------------------------

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


# --------------------------------------------------
# URL Detection Engine
# --------------------------------------------------

def detect_url(url):

    url = normalize_url(url)

    risk = 0

    url_lower = url.lower()


    # --------------------------------
    # Blacklist detection
    # --------------------------------

    if is_blacklisted(url):

        return {
        "type":"URL",
        "input":url,
        "risk_score":100,
        "status":"Phishing",
        "confidence":1.0
        }


    # --------------------------------
    # ML detection
    # --------------------------------

    pred, prob = ml_predict(url)

    if pred == 1:
        risk += 40


    # --------------------------------
    # phishing keywords
    # --------------------------------

    keywords = [

    "login","verify","secure","account",
    "bank","confirm","update","signin",
    "password","wallet","payment"

    ]

    keyword_hits = sum(1 for k in keywords if k in url_lower)

    risk += keyword_hits * 15


    # --------------------------------
    # typosquatting
    # --------------------------------

    if typo_check(url):
        risk += 40


    # --------------------------------
    # suspicious TLD
    # --------------------------------

    suspicious_tlds = [

    ".xyz",".top",".tk",".ml",".ga",".cf",".zip"

    ]

    if any(url_lower.endswith(tld) for tld in suspicious_tlds):
        risk += 25


    # --------------------------------
    # domain age
    # --------------------------------

    age = domain_age(url)

    if age is not None:

        if age < 30:
            risk += 40

        elif age < 180:
            risk += 20


    # --------------------------------
    # URL structure analysis
    # --------------------------------

    if url.count("-") >= 2:
        risk += 15

    if len(url) > 60:
        risk += 10


    risk = min(risk,100)

    status = "Phishing" if risk >= 60 else "Safe"


    return {

    "type":"URL",
    "input":url,
    "risk_score":risk,
    "status":status,
    "confidence":round(prob,2)

    }


# --------------------------------------------------
# Web Routes
# --------------------------------------------------

@app.route("/")
def index():

    return render_template("index.html")


@app.route("/scan", methods=["GET","POST"])
def scan():

    result = None

    if request.method == "POST":

        url = request.form.get("url")

        if url:

            result = detect_url(url)

    return render_template("scan.html", result=result)


@app.route("/threats")
def threats():

    return render_template("threat.html")


@app.route("/extension")
def extension():

    return render_template("extension.html")


# --------------------------------------------------
# API for Chrome Extension
# --------------------------------------------------

@app.route("/api/scan", methods=["POST"])
def api_scan():

    data = request.get_json()

    url = data.get("url")

    result = detect_url(url)

    return jsonify(result)


# --------------------------------------------------

if __name__ == "__main__":

    print("SentinelAI server running...")

    app.run(debug=True)