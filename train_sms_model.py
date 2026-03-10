import pandas as pd
import pickle

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

# Load dataset
data = pd.read_csv("spam.csv", encoding="latin-1")

# Rename columns (dataset usually has v1 and v2)
data = data.rename(columns={
    "v1": "label",
    "v2": "message"
})

# Keep only required columns
data = data[["label", "message"]]

X = data["message"]
y = data["label"]

# Convert text → numerical vectors
vectorizer = TfidfVectorizer(stop_words="english")

X_vector = vectorizer.fit_transform(X)

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(
    X_vector,
    y,
    test_size=0.2,
    random_state=42
)

# Train model
model = LogisticRegression()

model.fit(X_train, y_train)

# Check accuracy
accuracy = model.score(X_test, y_test)

print("Model Accuracy:", accuracy)

# Save model
pickle.dump(model, open("scam_model.pkl", "wb"))
pickle.dump(vectorizer, open("vectorizer.pkl", "wb"))

print("Model and vectorizer saved.")