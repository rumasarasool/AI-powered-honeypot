import os
import joblib
import numpy as np
import pandas as pd
from imblearn.over_sampling import RandomOverSampler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import cross_val_score, train_test_split

# Features to use for training
FEATURE_COLUMNS = [
    "Flow Duration",
    "Total Fwd Packet",
    "Total Bwd packets",
    "Total Length of Fwd Packet",
    "Fwd Packet Length Max",
    "Packet Length Mean",
    "Flow Bytes/s",
    "Flow Packets/s",
]

# Label names for display
LABEL_NAMES = {
    0: "Bot",
    1: "Script Kiddie",
    2: "Skilled Human",
    3: "Normal",
}

def map_label(label_value):
    # Map raw CICIDS labels to attacker type numbers
    label_text = str(label_value).lower()
    if "ftp-patator" in label_text or "ssh-patator" in label_text:
        return 0  # Bot
    if "botnet" in label_text:
        return 1  # Script Kiddie
    if "web attack" in label_text:
        return 2  # Skilled Human
    if "benign" in label_text:
        return 3  # Normal
    return None  # Unknown — will be dropped

def prepare_features(df):
    # Select only the required feature columns
    features = df.reindex(columns=FEATURE_COLUMNS, fill_value=0)
    # Replace infinite values with 0
    features = features.replace([np.inf, -np.inf], 0)
    # Fill any remaining missing values with 0
    return features.fillna(0)

def main():
    # Step 1 — Load combined attacks dataset
    print("Loading data/combined_attacks.csv...")
    if not os.path.exists("data/combined_attacks.csv"):
        raise FileNotFoundError("data/combined_attacks.csv not found. Run log_parser.py first.")
    
    df = pd.read_csv("data/combined_attacks.csv")
    print(f"Total rows loaded: {len(df)}")

    # Step 2 — Map labels to numbers
    df["target"] = df["Label"].apply(map_label)
    df = df[df["target"].notna()].copy()
    df["target"] = df["target"].astype(int)
    print(f"Rows after label mapping: {len(df)}")
    print("Label distribution:")
    print(df["target"].map(LABEL_NAMES).value_counts())

    # Step 3 — Prepare features and labels
    X = prepare_features(df)
    y = df["target"]

    # Step 4 — Split FIRST before any oversampling
    # stratify=y ensures every class appears in both train and test
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )
    print(f"Training samples: {len(X_train)}, Test samples: {len(X_test)}")

    # Step 5 — Oversample ONLY the training data
    # Never touch X_test — it must stay as real distribution
    print("Applying RandomOverSampler to training data only...")
    ros = RandomOverSampler(random_state=42)
    X_train_balanced, y_train_balanced = ros.fit_resample(X_train, y_train)
    print(f"Training samples after oversampling: {len(X_train_balanced)}")

    # Step 6 — Train RandomForest classifier
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        min_samples_leaf=5,
        class_weight="balanced",
        random_state=42,
    )

    # Step 7 — Cross-validation on original (non-oversampled) data
    print("Running 5-fold cross-validation...")
    cv_scores = cross_val_score(model, X, y, cv=5)
    print(f"Cross-validation accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")

    # Step 8 — Train on oversampled training data
    print("Training classifier...")
    model.fit(X_train_balanced, y_train_balanced)

    # Step 9 — Evaluate on untouched test data
    predictions = model.predict(X_test)
    print("\nClassification Report:")
    print(classification_report(
        y_test,
        predictions,
        labels=[0, 1, 2, 3],
        target_names=[LABEL_NAMES[i] for i in [0, 1, 2, 3]],
        zero_division=0
    ))

    # Step 10 — Save the trained model
    os.makedirs("models", exist_ok=True)
    joblib.dump(model, "models/classifier.pkl")
    print("Model saved to models/classifier.pkl")

if __name__ == "__main__":
    main()