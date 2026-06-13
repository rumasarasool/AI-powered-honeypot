import os

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest


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


def load_csv(path):
	# Load the combined dataset and fail fast if it is missing.
	if not os.path.exists(path):
		raise FileNotFoundError(f"Missing required file: {path}")
	return pd.read_csv(path)


def prepare_features(df):
	# Select the shared feature columns and replace invalid values.
	features = df.reindex(columns=FEATURE_COLUMNS, fill_value=0)
	features = features.replace([np.inf, -np.inf], 0)
	return features.fillna(0)


def main():
	# Load the cleaned attack dataset and train an unsupervised detector.
	df = load_csv("data/combined_attacks.csv")
	X = prepare_features(df)

	model = IsolationForest(
		n_estimators=200,
		contamination="auto",
		random_state=42,
		n_jobs=-1,
	)
	predictions = model.fit_predict(X)
	anomaly_count = int((predictions == -1).sum())

	# Save the trained detector for later inference.
	os.makedirs("models", exist_ok=True)
	joblib.dump(model, "models/anomaly_detector.pkl")

	print(f"Anomalies flagged: {anomaly_count}")
	print("Model saved to models/anomaly_detector.pkl")


if __name__ == "__main__":
	main()