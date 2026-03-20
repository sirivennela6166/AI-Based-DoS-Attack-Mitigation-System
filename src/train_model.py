import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import joblib

DATA_PATH = "data/ml_ready_dataset.csv"
MODEL_PATH = "models/rf_dos_model.pkl"

CHUNK_SIZE = 200_000
MAX_PER_CLASS = 200_000  # total ~400k rows

normal_samples = []
attack_samples = []

print("Collecting balanced samples...")

for chunk in pd.read_csv(DATA_PATH, chunksize=CHUNK_SIZE):
    normal = chunk[chunk["label"] == 0]
    attack = chunk[chunk["label"] == 1]

    if len(normal_samples) < MAX_PER_CLASS:
        normal_samples.append(normal)

    if len(attack_samples) < MAX_PER_CLASS:
        attack_samples.append(attack)

    if len(pd.concat(normal_samples)) >= MAX_PER_CLASS and \
       len(pd.concat(attack_samples)) >= MAX_PER_CLASS:
        break

df = pd.concat(normal_samples + attack_samples)

print("Final balanced dataset shape:", df.shape)
print("Label distribution:")
print(df["label"].value_counts())

X = df.drop(columns=["label"])
y = df["label"]

print("Splitting train/test...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print("Training Random Forest...")
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    n_jobs=-1,
    random_state=42
)

model.fit(X_train, y_train)

print("Evaluating model...")
y_pred = model.predict(X_test)

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

print("Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))

print("Saving model...")
joblib.dump(model, MODEL_PATH)

print("Done. Model saved to:", MODEL_PATH)

