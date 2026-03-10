from fastapi import FastAPI
from pydantic import BaseModel
import pickle
import whois
import datetime
import Levenshtein

app = FastAPI(title="SentinelAI Cyber Defense")


# -----------------------------
# Load Models
# -----------------------------

url_model = pickle.load(open("url_model.pkl","rb"))
vectorizer = pickle.load(open("url_vectorizer.pkl","rb"))


class URLRequest(BaseModel):
    url: str


# -----------------------------
# Known brands
# -----------------------------

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

    # ML signal
    if pred == 1:
        risk += 40


    # phishing keywords
    keywords = [
        "login","verify","secure","account",
        "bank","confirm","update","signin","password"
    ]

    keyword_hits = sum(1 for k in keywords if k in url_lower)

    risk += keyword_hits * 20


    # typosquatting
    if typo_check(url):
        risk += 40


    # suspicious TLD
    suspicious_tlds = [
        ".xyz",".top",".tk",".ml",".ga",".cf"
    ]

    if any(url_lower.endswith(tld) for tld in suspicious_tlds):
        risk += 25


    # domain age
    age = domain_age(url)

    if age is not None:

        if age < 30:
            risk += 40
        elif age < 180:
            risk += 20


    # suspicious URL structure
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
# API Routes
# -----------------------------

@app.post("/scan-url")
def scan_url(data: URLRequest):

    return detect_url(data.url)


@app.get("/")
def home():
    return {"message":"SentinelAI backend running"}