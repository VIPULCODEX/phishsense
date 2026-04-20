import os
import pickle
import time

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from utils.preprocessing import preprocess_text

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(BASE_DIR, "data", "dataset.csv")
MODEL_PATH = os.path.join(BASE_DIR, "model", "model.pkl")


def train() -> None:
    start = time.time()

    df = pd.read_csv(DATA_PATH)
    df = df.dropna(subset=["text", "label"]).copy()

    X_train, X_test, y_train, y_test = train_test_split(
        df["text"],
        df["label"],
        test_size=0.2,
        random_state=42,
        stratify=df["label"],
    )

    pipeline = Pipeline(
        steps=[
            (
                "vectorizer",
                TfidfVectorizer(
                    preprocessor=preprocess_text,
                    ngram_range=(1, 2),
                    max_features=5000,
                    min_df=1,
                    sublinear_tf=True,
                ),
            ),
            (
                "classifier",
                LogisticRegression(
                    max_iter=500,
                    solver="liblinear",
                    class_weight="balanced",
                    random_state=42,
                ),
            ),
        ]
    )

    pipeline.fit(X_train, y_train)

    predictions = pipeline.predict(X_test)
    acc = accuracy_score(y_test, predictions)
    report = classification_report(y_test, predictions, digits=3)

    os.makedirs(os.path.join(BASE_DIR, "model"), exist_ok=True)
    with open(MODEL_PATH, "wb") as f:
        pickle.dump({"pipeline": pipeline}, f)

    elapsed = time.time() - start
    print("Training complete.")
    print(f"Samples: {len(df)}")
    print(f"Accuracy: {acc:.4f}")
    print(f"Saved model: {MODEL_PATH}")
    print(f"Elapsed: {elapsed:.2f}s")
    print("\nClassification Report:\n")
    print(report)


if __name__ == "__main__":
    train()
