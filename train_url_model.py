import pandas as pd
import pickle
import re

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from difflib import SequenceMatcher

# -----------------------------
# Known Brands (for spoofing detection)
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
# Brand Similarity Detection
# -----------------------------

def brand_similarity(url):

    highest = 0

    for brand in brands:

        ratio = SequenceMatcher(None, brand, url).ratio()

        if ratio > highest:
            highest = ratio

    return highest


# -----------------------------
# Feature Extraction
# -----------------------------

def extract_features(url):

    url = url.lower()

    features = []

    # length features
    features.append(len(url))

    # structural features
    features.append(url.count("."))
    features.append(url.count("-"))
    features.append(url.count("_"))
    features.append(url.count("/"))

    # https
    features.append(1 if "https" in url else 0)

    # suspicious keywords
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

    # suspicious domain endings
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

    # number of digits
    features.append(sum(c.isdigit() for c in url))

    # brand similarity
    features.append(brand_similarity(url))

    return features


# -----------------------------
# Load Dataset
# -----------------------------

data = pd.read_csv("url_spam_classification.csv")

# dataset columns
X = data["url"].apply(extract_features).tolist()
y = data["is_spam"]

# -----------------------------
# Train/Test Split
# -----------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

# -----------------------------
# Train Model
# -----------------------------

model = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    random_state=42
)

model.fit(X_train, y_train)

accuracy = model.score(X_test, y_test)

print("\nURL Model Accuracy:", accuracy)

# -----------------------------
# Save Model
# -----------------------------

pickle.dump(model, open("url_model.pkl", "wb"))

print("URL model saved successfully.")