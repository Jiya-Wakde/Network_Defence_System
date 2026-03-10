import pickle
import whois
import datetime
import Levenshtein

print("Loading models...")

url_model = pickle.load(open("url_model.pkl","rb"))
vectorizer = pickle.load(open("url_vectorizer.pkl","rb"))

print("Models loaded successfully.")


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

        if isinstance(creation,list):
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

    # ---------------------------
    # ML Prediction
    # ---------------------------

    pred, prob = ml_predict(url)

    if pred == 1:
        risk += 50


    # ---------------------------
    # Suspicious Keywords
    # ---------------------------

    keywords = [
        "login","verify","secure","account",
        "bank","confirm","update","signin",
        "password","reset","wallet","payment",
        "crypto","bonus","gift","free"
    ]

    keyword_hits = sum(1 for k in keywords if k in url_lower)

    risk += keyword_hits * 15


    # ---------------------------
    # Suspicious Login Pages
    # ---------------------------

    suspicious_paths = [
        "login.php",
        "verify.php",
        "update.php",
        "signin.php",
        "account.php"
    ]

    if any(p in url_lower for p in suspicious_paths):
        risk += 20


    # ---------------------------
    # Typosquatting Detection
    # ---------------------------

    if typo_check(url):
        risk += 40


    # ---------------------------
    # Suspicious TLDs
    # ---------------------------

    suspicious_tlds = [
        ".xyz",".top",".tk",".ml",".ga",".cf",
        ".gq",".work",".click",".zip",".link",".gg"
    ]

    if any(tld in url_lower for tld in suspicious_tlds):
        risk += 25


    # ---------------------------
    # URL Length Check
    # ---------------------------

    if len(url) > 75:
        risk += 20


    # ---------------------------
    # Too Many Hyphens
    # ---------------------------

    if url.count("-") >= 2:
        risk += 15


    # ---------------------------
    # Domain Age
    # ---------------------------

    age = domain_age(url)

    if age is not None:

        if age < 30:
            risk += 50

        elif age < 180:
            risk += 25


    # ---------------------------
    # Mirror / piracy detection
    # ---------------------------

    suspicious_patterns = [
        "mirror",
        "torrent",
        "download",
        "crack"
    ]

    if any(p in url_lower for p in suspicious_patterns):
        risk += 20


    # ---------------------------
    # Final Risk Score
    # ---------------------------

    risk = min(risk,100)


    if risk >= 60:
        status = "PHISHING"

    elif risk >= 30:
        status = "SUSPICIOUS"

    else:
        status = "SAFE"


    print("URL:", url)
    print("Risk Score:", risk)


    return {
        "url": url,
        "risk_score": risk,
        "status": status,
        "confidence": round(prob,2)
    }


# -----------------------------
# Test Loop
# -----------------------------

while True:

    url = input("\nEnter URL (or type exit): ")

    if url.lower() == "exit":
        break


    result = detect_url(url)

    print("\nResult:", result["status"])
    print("Risk Score:", result["risk_score"])
    print("ML Confidence:", result["confidence"])