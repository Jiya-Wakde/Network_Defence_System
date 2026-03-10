import pandas as pd
import pickle

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression


print("Loading dataset...")

data = pd.read_csv("url_spam_classification.csv")

data["is_spam"] = data["is_spam"].astype(int)

X = data["url"]
y = data["is_spam"]

vectorizer = TfidfVectorizer(
    analyzer="char",
    ngram_range=(3,5),
    max_features=50000
)

X_vec = vectorizer.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(
    X_vec, y, test_size=0.2, random_state=42
)

model = LogisticRegression(max_iter=200)

print("Training model...")

model.fit(X_train, y_train)

accuracy = model.score(X_test, y_test)

print("Model accuracy:", accuracy)

pickle.dump(model, open("url_model.pkl","wb"))
pickle.dump(vectorizer, open("url_vectorizer.pkl","wb"))

print("Model saved.")