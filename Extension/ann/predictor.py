import joblib
import pandas as pd
import numpy as np
import re
import os
from urllib.parse import urlparse

# Get the directory of this script
script_dir = os.path.dirname(os.path.abspath(__file__))

# Load model & scaler with full paths
try:
    model_path = os.path.join(script_dir, "optimized_ann_90_9acc.h5")
    scaler_path = os.path.join(script_dir, "scaler.pkl")
    
    # Try to import tensorflow
    try:
        from tensorflow.keras.models import load_model
        model = load_model(model_path)
        print(f"Loaded Keras model from {model_path}")
    except ImportError:
        print("TensorFlow not available, trying to load as joblib...")
        model = joblib.load(model_path.replace('.h5', '.pkl'))
    
    scaler = joblib.load(scaler_path)
    print(f"Loaded scaler from {scaler_path}")
    MODEL_LOADED = True
except Exception as e:
    print(f"Error loading model: {e}")
    model = None
    scaler = None
    MODEL_LOADED = False

# Feature extraction
def extract_features(urls):
    data = []
    for url in urls:
        parsed = urlparse(url)
        domain = parsed.netloc
        subdomains = domain.split(".")[:-2] if len(domain.split(".")) > 2 else []

        url_length = len(url)
        avg_sub_len = np.mean([len(sd) for sd in subdomains]) if subdomains else 0
        entropy_url = -sum([p * np.log2(p) for p in [url.count(c)/len(url) for c in set(url)]])
        entropy_domain = -sum([p * np.log2(p) for p in [domain.count(c)/len(domain) for c in set(domain)]])
        domain_length = len(domain)
        num_subdomains = len(subdomains)
        num_special_chars = len(re.findall(r'[@_!#$%^&*()<>?/\|}{~:]', url))
        num_digits_url = len(re.findall(r'\d', url))
        num_digits_domain = len(re.findall(r'\d', domain))
        num_slash = url.count('/')

        data.append([
            url_length, avg_sub_len, entropy_url, entropy_domain,
            domain_length, num_subdomains, num_special_chars,
            num_digits_url, num_digits_domain, num_slash
        ])

    feature_names = [
        'url_length',
        'average_subdomain_length',
        'entropy_of_url',
        'entropy_of_domain',
        'domain_length',
        'number_of_subdomains',
        'number_of_special_char_in_url',
        'number_of_digits_in_url',
        'number_of_digits_in_domain',
        'number_of_slash_in_url'
    ]
    return pd.DataFrame(data, columns=feature_names)

# Prediction function
def predict_url(url):
    """Predict URL safety using the loaded model"""
    print(f"🔍 ANN Model analyzing URL: {url}")
    
    if not MODEL_LOADED or model is None or scaler is None:
        print("❌ Model not loaded, using fallback")
        # Fallback prediction if model not loaded
        return fallback_predict_url(url)
    
    try:
        X_new = extract_features([url])
        X_new_scaled = scaler.transform(X_new)
        prob = model.predict(X_new_scaled)[0][0]
        
        print(f"📊 Raw probability from model: {prob}")
        print(f"📊 Features extracted: {X_new.iloc[0].to_dict()}")

        # More conservative thresholds to reduce false positives
        if prob >= 0.75:  # Increased from 0.55 to 0.75
            result = ("Malicious", float(prob))
            print(f"🚨 Result: {result[0]} (prob: {result[1]:.3f})")
            return result
        elif prob <= 0.35:  # Decreased from 0.45 to 0.35 
            result = ("Legitimate", float(prob))
            print(f"✅ Result: {result[0]} (prob: {result[1]:.3f})")
            return result
        else:
            result = ("Suspicious", float(prob))
            print(f"⚠️ Result: {result[0]} (prob: {result[1]:.3f})")
            return result
    except Exception as e:
        print(f"❌ Error in ANN prediction: {e}")
        return fallback_predict_url(url)

def fallback_predict_url(url):
    """Fallback prediction when model is not available"""
    try:
        features = extract_features([url]).iloc[0]
        
        # Simple rule-based scoring
        score = 0.0
        
        # URL length
        if features['url_length'] > 100:
            score += 0.3
        if features['url_length'] > 200:
            score += 0.2
            
        # Domain features
        if features['domain_length'] > 30:
            score += 0.2
        if features['number_of_subdomains'] > 3:
            score += 0.3
            
        # Special characters and digits
        if features['number_of_special_char_in_url'] > 10:
            score += 0.2
        if features['number_of_digits_in_url'] > 15:
            score += 0.3
            
        # Entropy
        if features['entropy_of_url'] > 4.5:
            score += 0.2
            
        probability = min(score, 1.0)
        
        if probability >= 0.7:
            return "Malicious", probability
        elif probability >= 0.4:
            return "Suspicious", probability
        else:
            return "Legitimate", probability
            
    except Exception as e:
        print(f"Error in fallback prediction: {e}")
        return "Suspicious", 0.5

# Main script
if __name__ == "__main__":
    user_url = input("Enter a URL to check: ").strip()
    label, probability = predict_url(user_url)
    print(f"\nURL: {user_url}")
    print(f"Prediction: {label}")
    print(f"Confidence: {probability:.4f}")
