# PhishNet - AI Phishing Detector
# Step 1: Train our AI model

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import pickle

# Sample training data (URL features)
    data = {
    'url_length': [20, 100, 25, 150, 30, 200, 22, 180, 15, 120, 28, 160, 35, 190, 18, 170, 24, 140, 32, 210],
    'has_https': [1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0],
    'has_ip': [0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1],
    'num_dots': [1, 5, 2, 8, 1, 7, 2, 6, 1, 9, 2, 7, 1, 8, 2, 6, 1, 7, 2, 9],
    'label': [0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1]
}
# 0 = Safe, 1 = Phishing

df = pd.DataFrame(data)

X = df.drop('label', axis=1)
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

model = RandomForestClassifier()
model.fit(X_train, y_train)

accuracy = accuracy_score(y_test, model.predict(X_test))
print(f"Model Accuracy: {accuracy * 100}%")

# Save the model
with open('model.pkl', 'wb') as f:
    pickle.dump(model, f)

print("Model saved successfully!")