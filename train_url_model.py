import pandas as pd
import pickle
import re
import math

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from difflib import SequenceMatcher
from urllib.parse import urlparse


# -----------------------------------
# Known brands for phishing detection
# -----------------------------------

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


# -----------------------------------
# Extract domain from URL
# -----------------------------------

def get_domain(url):

    try:
        parsed = urlparse(url)

        domain = parsed.netloc

        if domain == "":
            domain = url

        return domain.lower()

    except:
        return url.lower()


# -----------------------------------
# Brand similarity detection
# -----------------------------------

def brand_similarity(url):

    domain = get_domain(url)

    highest = 0

    for brand in brands:

        ratio = SequenceMatcher(None, brand, domain).ratio()

        if ratio > highest:
            highest = ratio

    return highest


# -----------------------------------
# Entropy calculation
# -----------------------------------

def entropy(text):

    if len(text) == 0:
        return 0

    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]

    entropy_value = -sum([p * math.log2(p) for p in prob])

    return entropy_value


# -----------------------------------
# Feature extraction
# -----------------------------------

def extract_features(url):

    url = str(url).lower()

    features = []

    # URL length
    features.append(len(url))

    # structure counts
    features.append(url.count("."))
    features.append(url.count("-"))
    features.append(url.count("_"))
    features.append(url.count("/"))

    # https presence
    features.append(1 if url.startswith("https") else 0)

    # phishing keywords
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

    # entropy of URL
    features.append(entropy(url))

    return features


# -----------------------------------
# Load dataset
# -----------------------------------

print("\nLoading dataset...")

data = pd.read_csv("url_spam_classification.csv")

# convert True/False → 1/0
data["is_spam"] = data["is_spam"].astype(int)

print("Dataset size:", len(data))
print("\nClass distribution:")
print(data["is_spam"].value_counts())


# -----------------------------------
# Generate features
# -----------------------------------

print("\nExtracting features...")

X = data["url"].apply(extract_features).tolist()

y = data["is_spam"]


# -----------------------------------
# Train / Test split
# -----------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)


# -----------------------------------
# Train model
# -----------------------------------

print("\nTraining RandomForest model...")

model = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)


# -----------------------------------
# Evaluate model
# -----------------------------------

accuracy = model.score(X_test, y_test)

print("\nURL Model Accuracy:", round(accuracy, 4))


# -----------------------------------
# Save model
# -----------------------------------

pickle.dump(model, open("url_model.pkl", "wb"))

print("\nURL model saved successfully.")