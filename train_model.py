import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import pickle
import os

print("Loading dataset...")
csv_files = [f for f in os.listdir('.') if f.endswith('.csv')]
df = pd.read_csv(csv_files[0])
print(f"Dataset loaded: {df.shape[0]} URLs")

# Prepare features
df = df.dropna()
df['status'] = df['status'].map({'legitimate': 0, 'phishing': 1})
df = df.dropna(subset=['status'])

# Use numeric columns only
X = df.select_dtypes(include=['number']).drop(columns=['status'], errors='ignore')
y = df['status']

print(f"Training on {len(X)} URLs with {len(X.columns)} features")

# Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
print("Training Random Forest model...")
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Test accuracy
predictions = model.predict(X_test)
accuracy = accuracy_score(y_test, predictions)
print(f"\nModel Accuracy: {accuracy * 100:.2f}%")
print(f"\nDetailed Report:")
print(classification_report(y_test, predictions, target_names=['Legitimate', 'Phishing']))

# Save model and feature names
with open('model.pkl', 'wb') as f:
    pickle.dump(model, f)

with open('features.pkl', 'wb') as f:
    pickle.dump(X.columns.tolist(), f)

print("\nModel saved successfully!")
print(f"Features used: {X.columns.tolist()[:10]}... and {len(X.columns)} total")