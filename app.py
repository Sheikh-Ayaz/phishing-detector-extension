from flask import Flask, request, jsonify
from flask_cors import CORS  # Import CORS
import joblib
import pandas as pd
import re
from urllib.parse import urlparse
import tldextract
from math import log2

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

# Initialize Flask app
app = Flask(__name__)
CORS(app, resources={r"/predict": {"origins": "*"}})  # Allow all origins for /predict

# Load the trained model
model = joblib.load('phishing_model.pkl')

@app.route('/predict', methods=['POST'])
def predict():
    data = request.json
    url = data.get('url', '')
    features = extract_features(url)
    prediction = model.predict(pd.DataFrame([features]))
    return jsonify({'phishing': int(prediction[0])})

if __name__ == '__main__':
    app.run(debug=True, port=5000)