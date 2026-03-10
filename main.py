from fastapi import FastAPI
from pydantic import BaseModel
from datetime import datetime
from collections import Counter
import pickle
import re

app = FastAPI(title="SentinelAI Cyber Defense System")

# -----------------------------
# Load Models
# -----------------------------

sms_model = pickle.load(open("scam_model.pkl", "rb"))
vectorizer = pickle.load(open("vectorizer.pkl", "rb"))

url_model = pickle.load(open("url_model.pkl", "rb"))

# -----------------------------
# In-Memory Storage
# -----------------------------

scan_logs = []
message_logs = []

leaderboard = {
    "Rahul": 920,
    "Aditi": 880,
    "Jiya": 840
}

# -----------------------------
# Request Models
# -----------------------------

class URLRequest(BaseModel):
    url: str

class MessageRequest(BaseModel):
    message: str

class ReportScam(BaseModel):
    message: str
    location: str


# -----------------------------
# Text Cleaning
# -----------------------------

def clean_text(text):

    text = text.lower()

    text = re.sub(r"http\S+", "", text)

    text = re.sub(r"[^a-zA-Z\s]", "", text)

    return text


# -----------------------------
# SMS Prediction
# -----------------------------

def predict_message(message):

    cleaned = clean_text(message)

    vector = vectorizer.transform([cleaned])

    prediction = sms_model.predict(vector)[0]

    probability = sms_model.predict_proba(vector).max()

    risk_score = int(probability * 100)

    return prediction, probability, risk_score


# -----------------------------
# URL Feature Extraction
# -----------------------------

def extract_url_features(url):

    return [
        len(url),
        url.count("."),
        url.count("/"),
        1 if "https" in url else 0,
        1 if "login" in url else 0,
        1 if "verify" in url else 0,
        len(re.findall(r"[@\-_=]", url))
    ]


# -----------------------------
# URL Prediction
# -----------------------------

def predict_url(url):

    features = extract_url_features(url)

    prediction = url_model.predict([features])[0]

    probability = url_model.predict_proba([features]).max()

    risk_score = int(probability * 100)

    return prediction, probability, risk_score


# -----------------------------
# Routes
# -----------------------------

@app.get("/")
def home():
    return {"message": "SentinelAI Backend Running"}


# -----------------------------
# Scan URL
# -----------------------------

@app.post("/scan-url")
def scan_url(data: URLRequest):

    prediction, probability, risk_score = predict_url(data.url)

    result = {
        "url": data.url,
        "risk_score": risk_score,
        "type": "Phishing" if prediction == 1 else "Safe",
        "confidence": round(probability, 2),
        "timestamp": str(datetime.now())
    }

    scan_logs.append(result)

    return result


# -----------------------------
# Scan Message
# -----------------------------

@app.post("/scan-message")
def scan_message(data: MessageRequest):

    prediction, probability, risk_score = predict_message(data.message)

    result = {
        "message": data.message,
        "risk_score": risk_score,
        "type": "Scam" if prediction == "spam" else "Safe",
        "confidence": round(probability, 2),
        "timestamp": str(datetime.now())
    }

    message_logs.append(result)

    return result


# -----------------------------
# Threat Feed
# -----------------------------

@app.get("/threat-feed")
def threat_feed():

    alerts = []

    for scan in scan_logs[-5:]:

        if scan["risk_score"] > 50:
            alerts.append(f"⚠ Phishing detected: {scan['url']}")

    return {"alerts": alerts}


# -----------------------------
# Leaderboard
# -----------------------------

@app.get("/leaderboard")
def get_leaderboard():

    sorted_board = sorted(
        leaderboard.items(),
        key=lambda x: x[1],
        reverse=True
    )

    result = []

    rank = 1

    for name, score in sorted_board:

        result.append({
            "rank": rank,
            "name": name,
            "score": score
        })

        rank += 1

    return result


# -----------------------------
# Report Scam
# -----------------------------

@app.post("/report-scam")
def report_scam(data: ReportScam):

    message_logs.append({
        "message": data.message,
        "location": data.location,
        "time": str(datetime.now())
    })

    return {"status": "Report submitted"}


# -----------------------------
# Scam Trends
# -----------------------------

@app.get("/scam-trends")
def scam_trends():

    words = []

    for log in message_logs:

        msg = log.get("message", "")

        words.extend(msg.lower().split())

    if not words:
        return {"trend": "No data yet"}

    most_common = Counter(words).most_common(1)[0]

    return {
        "top_scam_pattern": most_common[0],
        "frequency": most_common[1],
        "trend": "Increasing",
        "confidence": round(min(0.5 + most_common[1]*0.05, 0.95), 2)
    }