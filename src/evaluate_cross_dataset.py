import pandas as pd
import joblib
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix

MODEL_PATH = "models/rf_dos_model.pkl"
DATA_PATH = "data/ml_ready_ddos2019.csv"

print("Loading trained model...")
model = joblib.load(MODEL_PATH)

print("Loading CIC-DDoS2019 dataset...")
df = pd.read_csv(DATA_PATH)

X = df.drop(columns=["label"])
y = df["label"]


X = X.replace([np.inf, -np.inf], np.nan)
X = X.fillna(0)

print("Running cross-dataset evaluation...")
y_pred = model.predict(X)

print("\nClassification Report (Train: CICIDS2017 → Test: CIC-DDoS2019):")
print(classification_report(y, y_pred))

print("Confusion Matrix:")
print(confusion_matrix(y, y_pred))

