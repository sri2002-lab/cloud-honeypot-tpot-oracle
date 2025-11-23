import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score
import json

print("🤖 Building ML Attack Prediction Model...")

# Load data
df = pd.read_csv(r'C:\Users\sri🍳\Documents\Network security\honeypot_analysis.csv')

# Clean and convert port to numeric (remove '-' and non-numeric)
df['port_clean'] = pd.to_numeric(df['DestPort (dest_port)'], errors='coerce')
df = df[df['port_clean'].notna()]  # Remove rows with invalid ports

# Parse timestamp
df['@timestamp'] = pd.to_datetime(df['@timestamp'], format='%b %d, %Y @ %H:%M:%S.%f', errors='coerce')
df['hour'] = df['@timestamp'].dt.hour
df['day_of_week'] = df['@timestamp'].dt.dayofweek

# Encode categorical
le_country = LabelEncoder()
le_proto = LabelEncoder()
le_event = LabelEncoder()

df['country_encoded'] = le_country.fit_transform(df['geoip.country_name'].fillna('Unknown'))
df['proto_encoded'] = le_proto.fit_transform(df['proto'].fillna('tcp'))

# Create attack category based on port
def categorize_attack(port):
    if port in [22, 2222]:
        return 'SSH'
    elif port in [5900, 5901]:
        return 'VNC'
    elif port == 5060:
        return 'SIP'
    elif port in [80, 443, 8080]:
        return 'Web'
    elif port in [21, 20]:
        return 'FTP'
    else:
        return 'Other'

df['attack_category'] = df['port_clean'].apply(categorize_attack)
df['attack_encoded'] = le_event.fit_transform(df['attack_category'])

# Features and target
features = ['port_clean', 'country_encoded', 'proto_encoded', 'hour', 'day_of_week']
X = df[features].fillna(0)
y = df['attack_encoded']

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Train model
rf = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=10)
rf.fit(X_train, y_train)

# Predictions
y_pred = rf.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print(f"\n✅ Model Accuracy: {accuracy*100:.1f}%")
print(f"   Training samples: {len(X_train)}")
print(f"   Test samples: {len(X_test)}")

# Feature importance
importance_df = pd.DataFrame({
    'Feature': features,
    'Importance': rf.feature_importances_
}).sort_values('Importance', ascending=False)

print("\n🎯 Feature Importance:")
for _, row in importance_df.iterrows():
    print(f"   {row['Feature']:20} : {row['Importance']:.3f}")

# Attack category distribution
print("\n📊 Attack Categories Detected:")
for cat in df['attack_category'].unique():
    count = len(df[df['attack_category'] == cat])
    print(f"   {cat:10} : {count:3} attacks")

# Save results
results = {
    'accuracy': float(accuracy),
    'total_samples': int(len(df)),
    'unique_ips': int(df['src_ip'].nunique()),
    'attack_categories': df['attack_category'].value_counts().to_dict(),
    'feature_importance': importance_df.to_dict('records')
}

with open(r'C:\Users\sri🍳\Documents\Network security\ml_results.json', 'w') as f:
    json.dump(results, f, indent=2)

print("\n✅ ML results saved!")
