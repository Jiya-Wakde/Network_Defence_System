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


def ml_predict(url):

    vec = vectorizer.transform([url])

    pred = url_model.predict(vec)[0]

    prob = url_model.predict_proba(vec).max()

    return pred, prob


def typo_check(url):

    domain = url.split("//")[-1].split("/")[0]

    name = domain.split(".")[0]

    for brand in brands:

        distance = Levenshtein.distance(name, brand)

        if distance <= 2 and name != brand:
            return True

    return False


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


def detect_url(url):

    risk = 0

    pred, prob = ml_predict(url)

    url_lower = url.lower()

    keywords = [
        "login","verify","secure","account",
        "bank","confirm","update","signin","password"
    ]

    keyword_hits = sum(1 for k in keywords if k in url_lower)

    risk += keyword_hits * 20

    if pred == 1:
        risk += 40

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

    risk = min(risk,100)

    label = "PHISHING" if risk >= 60 else "SAFE"

    return label, risk, prob


while True:

    url = input("\nEnter URL (or exit): ")

    if url == "exit":
        break

    label, risk, prob = detect_url(url)

    print("\nResult:", label)
    print("Risk Score:", risk)
    print("ML Confidence:", round(prob,2))