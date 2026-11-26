
"""Evaluation module for the message phishing detection model.

Uses a stratified train/test split and reports standard
classification metrics. Evaluation data is currently small
and manually created, so results are preliminary.
"""

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from ai_engine.message_detector import TRAINING_DATA


def evaluate_model():
    """Train an evaluation model and report its performance."""

    texts = [item[0] for item in TRAINING_DATA]
    labels = [item[1] for item in TRAINING_DATA]

    X_train, X_test, y_train, y_test = train_test_split(
        texts,
        labels,
        test_size=0.25,
        random_state=42,
        stratify=labels,
    )

    model = Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                ngram_range=(1, 2),
                lowercase=True,
                sublinear_tf=True,
            ),
        ),
        (
            "classifier",
            LogisticRegression(
                max_iter=1000,
                class_weight="balanced",
            ),
        ),
    ])

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    results = {
        "accuracy": round(
            accuracy_score(y_test, predictions) * 100, 2
        ),
        "precision": round(
            precision_score(
                y_test, predictions, zero_division=0
            ) * 100, 2
        ),
        "recall": round(
            recall_score(
                y_test, predictions, zero_division=0
            ) * 100, 2
        ),
        "f1_score": round(
            f1_score(
                y_test, predictions, zero_division=0
            ) * 100, 2
        ),
        "confusion_matrix": confusion_matrix(
            y_test, predictions
        ).tolist(),
        "classification_report": classification_report(
            y_test,
            predictions,
            target_names=["Legitimate", "Suspicious"],
            zero_division=0,
        ),
        "training_examples": len(X_train),
        "testing_examples": len(X_test),
    }

    # Identify incorrectly classified messages.
    incorrect_predictions = []

    for message, actual, predicted in zip(
        X_test, y_test, predictions
    ):
        if actual != predicted:
            incorrect_predictions.append({
                "message": message,
                "actual": (
                    "Suspicious" if actual == 1 else "Legitimate"
                ),
                "predicted": (
                    "Suspicious" if predicted == 1 else "Legitimate"
                ),
            })

    results["incorrect_predictions"] = incorrect_predictions

    return results


if __name__ == "__main__":

    evaluation = evaluate_model()

    print("\n========== MESSAGE DETECTOR EVALUATION ==========")

    print("Training examples:", evaluation["training_examples"])
    print("Testing examples:", evaluation["testing_examples"])

    print("\nAccuracy:", evaluation["accuracy"], "%")
    print("Precision:", evaluation["precision"], "%")
    print("Recall:", evaluation["recall"], "%")
    print("F1 Score:", evaluation["f1_score"], "%")

    print("\nConfusion Matrix:")
    print(evaluation["confusion_matrix"])

    print("\nClassification Report:")
    print(evaluation["classification_report"])

    print("\nIncorrect Predictions:")

    if evaluation["incorrect_predictions"]:
        for item in evaluation["incorrect_predictions"]:
            print("\nMessage:", item["message"])
            print("Actual:", item["actual"])
            print("Predicted:", item["predicted"])
    else:
        print("No incorrect predictions.")
