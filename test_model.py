import re
from difflib import SequenceMatcher

brands = [
    "google","amazon","facebook","netflix","paypal",
    "apple","microsoft","sbi","paytm","github"
]

def brand_similarity(url):

    highest = 0

    for brand in brands:
        ratio = SequenceMatcher(None, brand, url).ratio()
        if ratio > highest:
            highest = ratio

    return highest


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
        "login","verify","account","secure",
        "update","bank","confirm","password"
    ]

    for k in keywords:
        features.append(1 if k in url else 0)

    bad_tlds = [".xyz",".top",".ru",".tk",".ml",".ga"]

    for tld in bad_tlds:
        features.append(1 if url.endswith(tld) else 0)

    features.append(sum(c.isdigit() for c in url))

    features.append(brand_similarity(url))

    return features