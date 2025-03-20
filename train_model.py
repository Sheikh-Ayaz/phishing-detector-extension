import re
from urllib.parse import urlparse
import tldextract
from math import log2
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib

# Define the extract_features function
def extract_features(url):
    features = {}
    parsed = urlparse(url)
    domain = parsed.netloc
    tld_info = tldextract.extract(url)
    
    # URL-based features
    features['length'] = len(url)
    features['https'] = int(parsed.scheme == 'https')
    features['ip_address'] = int(bool(re.match(r"\d+\.\d+\.\d+\.\d+", domain)))
    features['subdomain_count'] = len(tld_info.subdomain.split('.')) if tld_info.subdomain else 0
    features['has_at'] = int('@' in url)
    features['has_hyphen'] = int('-' in domain)
    features['num_directories'] = parsed.path.count('/')
    features['shortener'] = int(domain in ['bit.ly', 'goo.gl', 'tinyurl.com'])
    features['suspicious_tld'] = int(tld_info.suffix in ['exe', 'zip', 'php', 'js'])
    
    # Entropy calculation
    def entropy(s):
        prob = [float(s.count(c))/len(s) for c in set(s)]
        return -sum(p * log2(p) for p in prob)
    features['entropy'] = entropy(url)
    
    return features

# Load data
data = pd.read_csv('urls.csv')
data['features'] = data['url'].apply(extract_features)
feature_df = pd.json_normalize(data['features'])
feature_df['label'] = data['label']

# Split data
X = feature_df.drop('label', axis=1)
y = feature_df['label']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

# Train model
model = RandomForestClassifier(n_estimators=100)
model.fit(X_train, y_train)

# Save model
joblib.dump(model, 'phishing_model.pkl')
print("Model trained and saved!")