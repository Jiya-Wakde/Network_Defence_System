from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import pickle
import whois
import datetime
import Levenshtein

app = Flask(__name__)
CORS(app)
# -----------------------------
# Load ML Models
# -----------------------------

url_model = pickle.load(open("url_model.pkl","rb"))
vectorizer = pickle.load(open("url_vectorizer.pkl","rb"))

brands = [
    "google","amazon","facebook","netflix",
    "paypal","apple","microsoft","sbi","paytm","github"
]

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

    domain = url.split("//")[-1].split("/")[0]

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

        domain = url.split("//")[-1].split("/")[0]

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

    pred, prob = ml_predict(url)

    url_lower = url.lower()

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

    risk = min(risk,100)

    status = "Phishing" if risk >= 60 else "Safe"

    return {
        "url": url,
        "risk_score": risk,
        "status": status,
        "confidence": round(prob,2)
    }


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

        url = request.form["url"]

        result = detect_url(url)

    return render_template("scan.html", result=result)


@app.route("/threats")
def threats():
    return render_template("threat.html")


@app.route("/extension")
def extension():
    return render_template("extension.html")


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

if __name__ == "__main__":
    app.run(debug=True)