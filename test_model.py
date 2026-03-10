import pickle
import re
import math
from difflib import SequenceMatcher
from urllib.parse import urlparse

# -----------------------------
# Load Models
# -----------------------------

sms_model = pickle.load(open("scam_model.pkl", "rb"))
vectorizer = pickle.load(open("vectorizer.pkl", "rb"))

url_model = pickle.load(open("url_model.pkl", "rb"))

print("Models loaded successfully.")


# -----------------------------
# Known brands
# -----------------------------

brands = [
    "google",
    "amazon",
    "facebook",
    "netflix",
    "paypal",
    "apple",
    "microsoft",
    "sbi",
    "paytm",
    "github"
]


# -----------------------------
# Extract domain
# -----------------------------

def get_domain(url):

    parsed = urlparse(url)

    domain = parsed.netloc

    if domain == "":
        domain = url

    return domain.lower()


# -----------------------------
# Brand similarity
# -----------------------------

def brand_similarity(url):

    domain = get_domain(url)

    highest = 0

    for brand in brands:

        ratio = SequenceMatcher(None, brand, domain).ratio()

        if ratio > highest:
            highest = ratio

    return highest


# -----------------------------
# Entropy calculation
# -----------------------------

def entropy(text):

    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]

    entropy_value = -sum([p * math.log2(p) for p in prob])

    return entropy_value


# -----------------------------
# URL Feature Extraction
# -----------------------------

def extract_features(url):

    url = url.lower()

    features = []

    features.append(len(url))
    features.append(url.count("."))
    features.append(url.count("-"))
    features.append(url.count("_"))
    features.append(url.count("/"))

    features.append(1 if "https" in url else 0)

    keywords = [
        "login",
        "verify",
        "account",
        "secure",
        "update",
        "bank",
        "confirm",
        "password"
    ]

    for k in keywords:
        features.append(1 if k in url else 0)

    bad_tlds = [
        ".xyz",
        ".top",
        ".ru",
        ".tk",
        ".ml",
        ".ga"
    ]

    for tld in bad_tlds:
        features.append(1 if url.endswith(tld) else 0)

    features.append(sum(c.isdigit() for c in url))

    features.append(brand_similarity(url))

    features.append(entropy(url))

    return features


# -----------------------------
# SMS Prediction
# -----------------------------

def predict_message(message):

    vector = vectorizer.transform([message])

    prediction = sms_model.predict(vector)[0]

    probability = sms_model.predict_proba(vector).max()

    return prediction, probability


# -----------------------------
# URL Prediction
# -----------------------------

def predict_url(url):

    features = extract_features(url)

    prediction = url_model.predict([features])[0]

    probability = url_model.predict_proba([features]).max()

    return prediction, probability


# -----------------------------
# Terminal Testing Loop
# -----------------------------

while True:

    print("\nChoose test type:")
    print("1 → Test Message")
    print("2 → Test URL")
    print("3 → Exit")

    choice = input("Enter choice: ").strip()

    if choice == "1":

        msg = input("\nEnter message: ")

        pred, prob = predict_message(msg)

        print("\nPrediction:", pred)
        print("Confidence:", round(prob, 2))

    elif choice == "2":

        url = input("\nEnter URL: ").strip()

        pred, prob = predict_url(url)

        print("\nPrediction:", "Phishing" if pred == 1 else "Safe")
        print("Confidence:", round(prob, 2))

    elif choice == "3":

        print("Exiting test.")

        break

    else:

        print("Invalid choice.")