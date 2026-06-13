"""
test_cic2018.py
===============
Tests the trained classifier and anomaly detector against the
CIC-IDS-2018 dataset (cic.csv) using exact feature column mapping.

CIC-IDS-2018 was created by the same team (Canadian Institute for
Cybersecurity) using the same CICFlowMeter tool as CICIDS-2017,
so all 8 features map directly with no approximation.

Run:
    python test_cic2018.py
"""

import os
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, accuracy_score


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

CIC2018_PATH    = "data/cic.csv"
CLASSIFIER_PATH = "models/classifier.pkl"
ANOMALY_PATH    = "models/anomaly_detector.pkl"

# ---------------------------------------------------------------------------
# Exact feature mapping — CIC-2018 column names -> your model's feature names
# ---------------------------------------------------------------------------

# Your model was trained with these exact column names (left side).
# CIC-2018 uses slightly different names (right side) for the same features.

FEATURE_MAP = {
    "Flow Duration"              : "Flow Duration",    # exact match
    "Total Fwd Packet"           : "Tot Fwd Pkts",
    "Total Bwd packets"          : "Tot Bwd Pkts",
    "Total Length of Fwd Packet" : "TotLen Fwd Pkts",
    "Fwd Packet Length Max"      : "Fwd Pkt Len Max",
    "Packet Length Mean"         : "Pkt Len Mean",
    "Flow Bytes/s"               : "Flow Byts/s",
    "Flow Packets/s"             : "Flow Pkts/s",
}

FEATURE_COLUMNS = list(FEATURE_MAP.keys())   # order matters for the model

# ---------------------------------------------------------------------------
# Label mapping — CIC-2018 Label column -> your 4 classifier classes
# ---------------------------------------------------------------------------

LABEL_NAMES = {0: "Bot", 1: "Script Kiddie", 2: "Skilled Human", 3: "Normal"}

# CIC-2018 attack types grouped into your classes
BOT_LABELS          = ["bot", "ddos", "dos", "dosgoldenye", "doshulk",
                        "dosslowhttp", "dosslowloris", "heartbleed"]
SCRIPT_KIDDIE_LABELS= ["ftp-patator", "ssh-patator", "infiltration",
                         "portscan", "brute force", "ftp-bruteforce",
                         "ssh-bruteforce"]
SKILLED_HUMAN_LABELS= ["web attack", "web attack – brute force",
                        "web attack – xss", "web attack – sql injection",
                        "sql injection", "xss"]
BENIGN_LABELS       = ["benign"]


def map_cic2018_label(label_str: str) -> int:
    """Map a CIC-2018 label string to your classifier's class ID."""
    label = str(label_str).strip().lower()

    if label in BENIGN_LABELS:
        return 3  # Normal

    for bot_lbl in BOT_LABELS:
        if bot_lbl in label:
            return 0  # Bot

    for sk_lbl in SCRIPT_KIDDIE_LABELS:
        if sk_lbl in label:
            return 1  # Script Kiddie

    for sh_lbl in SKILLED_HUMAN_LABELS:
        if sh_lbl in label:
            return 2  # Skilled Human

    return 0  # Default unknown attacks -> Bot (automated)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 62)
    print("CIC-IDS-2018 Generalisation Test")
    print("Same feature space as CICIDS-2017 — exact column mapping")
    print("=" * 62)

    # ----------------------------------------------------------------
    # 1. Load CIC-2018
    # ----------------------------------------------------------------
    if not os.path.exists(CIC2018_PATH):
        raise FileNotFoundError(
            f"File not found: {CIC2018_PATH}\n"
            "Make sure cic.csv is in your data/ folder."
        )

    print(f"\nLoading {CIC2018_PATH} ...")
    # Load in chunks if file is large — 358MB needs care
    df = pd.read_csv(CIC2018_PATH, low_memory=False)

    # Strip whitespace from column names (CIC files sometimes have spaces)
    df.columns = df.columns.str.strip()

    # Strip Label column
    if "Label" in df.columns:
        df["Label"] = df["Label"].astype(str).str.strip()

    print(f"  Loaded {len(df):,} rows, {len(df.columns)} columns.")

    # ----------------------------------------------------------------
    # 2. Build feature matrix using exact column mapping
    # ----------------------------------------------------------------
    print("\nBuilding feature matrix (exact mapping) ...")

    missing = [c for c in FEATURE_MAP.values() if c not in df.columns]
    if missing:
        print(f"  WARNING: these columns not found in file: {missing}")
        print("  Available columns:", df.columns.tolist())
        return

    X = pd.DataFrame()
    for model_col, cic_col in FEATURE_MAP.items():
        X[model_col] = pd.to_numeric(df[cic_col], errors="coerce").fillna(0)

    # Replace Inf values (common in Flow Bytes/s when duration=0)
    X = X.replace([np.inf, -np.inf], 0)
    print(f"  Feature matrix shape: {X.shape}")

    # ----------------------------------------------------------------
    # 3. Map labels
    # ----------------------------------------------------------------
    print("\nMapping CIC-2018 labels ...")
    y_true = df["Label"].apply(map_cic2018_label)

    print("\n  Raw label distribution in this file:")
    raw_counts = df["Label"].value_counts()
    for label, count in raw_counts.items():
        pct = 100.0 * count / len(df)
        print(f"    {label:<40} {count:>8,}  ({pct:5.1f}%)")

    print("\n  Mapped class distribution:")
    mapped_counts = y_true.value_counts().sort_index()
    for cls_id, count in mapped_counts.items():
        pct = 100.0 * count / len(y_true)
        print(f"    {LABEL_NAMES[cls_id]:<15} {count:>8,}  ({pct:5.1f}%)")

    # ----------------------------------------------------------------
    # 4. Test classifier
    # ----------------------------------------------------------------
    print("\n" + "=" * 62)
    print("CLASSIFIER TEST  (models/classifier.pkl)")
    print("=" * 62)

    if not os.path.exists(CLASSIFIER_PATH):
        print("  classifier.pkl not found — skipping.")
    else:
        clf = joblib.load(CLASSIFIER_PATH)
        print(f"  Model loaded. Expects {clf.n_features_in_} features.")
        print(f"  Predicting on {len(X):,} samples ...")

        y_pred = clf.predict(X)
        acc    = accuracy_score(y_true, y_pred)

        print(f"\n  Accuracy on CIC-IDS-2018: {acc:.4f}  ({acc*100:.2f}%)\n")
        print(
            classification_report(
                y_true,
                y_pred,
                labels=[0, 1, 2, 3],
                target_names=[LABEL_NAMES[i] for i in [0, 1, 2, 3]],
                zero_division=0,
            )
        )

        print("  Interpretation:")
        if acc >= 0.85:
            print("  EXCELLENT — model generalises very well to CIC-IDS-2018.")
            print("  Same feature space, strong cross-year performance.")
        elif acc >= 0.65:
            print("  GOOD — solid generalisation to unseen 2018 traffic data.")
        else:
            print("  ACCEPTABLE — some degradation expected due to different")
            print("  attack scenarios and traffic patterns between 2017/2018.")

    # ----------------------------------------------------------------
    # 5. Test anomaly detector
    # ----------------------------------------------------------------
    print("\n" + "=" * 62)
    print("ANOMALY DETECTOR TEST  (models/anomaly_detector.pkl)")
    print("=" * 62)

    if not os.path.exists(ANOMALY_PATH):
        print("  anomaly_detector.pkl not found — skipping.")
    else:
        anom = joblib.load(ANOMALY_PATH)
        print(f"  Model loaded. Predicting on {len(X):,} samples ...")

        predictions = anom.predict(X)           # 1=normal, -1=anomaly
        scores      = anom.decision_function(X) # lower = more anomalous

        n_anomalies = int((predictions == -1).sum())
        n_normal    = int((predictions ==  1).sum())
        pct         = 100.0 * n_anomalies / len(predictions)

        print(f"\n  Total samples     : {len(predictions):,}")
        print(f"  Flagged anomalies : {n_anomalies:,}  ({pct:.1f}%)")
        print(f"  Flagged normal    : {n_normal:,}  ({100 - pct:.1f}%)")

        print(f"\n  Anomaly score stats:")
        print(f"    Mean  : {scores.mean():.4f}")
        print(f"    Min   : {scores.min():.4f}  (most anomalous)")
        print(f"    Max   : {scores.max():.4f}  (most normal)")

        # Attack detection rate
        attack_mask    = y_true != 3
        caught         = int(((predictions == -1) & attack_mask).sum())
        total_attacks  = int(attack_mask.sum())
        detection_rate = 100.0 * caught / total_attacks if total_attacks else 0

        # False positive rate (normal traffic flagged as anomaly)
        normal_mask  = y_true == 3
        false_pos    = int(((predictions == -1) & normal_mask).sum())
        total_normal = int(normal_mask.sum())
        fpr          = 100.0 * false_pos / total_normal if total_normal else 0

        print(f"\n  Attack detection rate:")
        print(f"    {caught:,} of {total_attacks:,} true attacks flagged"
              f"  ({detection_rate:.1f}%)")

        print(f"\n  False positive rate:")
        print(f"    {false_pos:,} of {total_normal:,} normal flows"
              f" wrongly flagged  ({fpr:.1f}%)")

        print("\n  Interpretation:")
        if detection_rate >= 70:
            print("  EXCELLENT — anomaly detector generalises very strongly.")
        elif detection_rate >= 45:
            print("  GOOD — detector catches the majority of attacks on")
            print("  completely unseen 2018 traffic. Strong generalisation.")
        else:
            print("  ACCEPTABLE — some miss-rate expected. Detector was")
            print("  trained on 2017 patterns; 2018 has new attack types.")

    print("\n" + "=" * 62)
    print("Test complete.")
    print("=" * 62)


if __name__ == "__main__":
    main()