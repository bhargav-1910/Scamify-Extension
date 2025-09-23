#!/usr/bin/env python3
"""
AI Phishing Detection Backend
Flask application serving the ANN model and providing API endpoints
"""

import os
import sqlite3
import json
import hashlib
import secrets
import sys
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, List, Optional, Tuple

from flask import Flask, request, jsonify, g
from flask_cors import CORS
import numpy as np
import joblib
import pandas as pd
import re
from urllib.parse import urlparse
import urllib.parse
from sklearn.feature_extraction.text import TfidfVectorizer

# Add the ann directory to the path to import the predictor
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'ann'))
sys.path.append(os.path.join(os.path.dirname(__file__), 'models'))

try:
    import sys
    import os
    # Add the ann folder to the Python path
    ann_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'ann')
    sys.path.append(ann_path)
    from predictor import predict_url as predict_url_ann, extract_features as extract_features_ann
    ANN_MODEL_AVAILABLE = True
    print("ANN model imported successfully")
except ImportError as e:
    print(f"Could not import ANN model: {e}")
    ANN_MODEL_AVAILABLE = False
    BACKEND_MODEL_AVAILABLE = False

try:
	import requests as http_requests
except Exception:
	http_requests = None

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')
app.config['DATABASE'] = 'database.db'

# Enable CORS (permissive to support chrome-extension origins)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

# Global variables
MODEL_PATH = 'models/ann_model.pkl'
vectorizer = None
ann_model = None
ann_scaler = None

def column_exists(cursor: sqlite3.Cursor, table: str, column: str) -> bool:
    try:
        cursor.execute(f"PRAGMA table_info({table})")
        cols = [row[1] for row in cursor.fetchall()]
        return column in cols
    except Exception:
        return False

def init_database():
    """Initialize or migrate the SQLite database with required tables/columns"""
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        
        # Create users table if missing (baseline)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Ensure missing columns exist on users (migration)
        if not column_exists(cursor, 'users', 'last_login'):
            cursor.execute('ALTER TABLE users ADD COLUMN last_login TIMESTAMP')
        if not column_exists(cursor, 'users', 'is_active'):
            cursor.execute('ALTER TABLE users ADD COLUMN is_active BOOLEAN DEFAULT TRUE')
        
        # Auth tokens table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS auth_tokens (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Create flagged_urls table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS flagged_urls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                url TEXT NOT NULL,
                prediction TEXT NOT NULL,
                probability REAL NOT NULL,
                flagged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                notes TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Create url_scans table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS url_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                url TEXT NOT NULL,
                prediction TEXT NOT NULL,
                probability REAL NOT NULL,
                scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                scan_source TEXT DEFAULT 'manual',
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Add scan_source column if it doesn't exist
        if not column_exists(cursor, 'url_scans', 'scan_source'):
            cursor.execute('ALTER TABLE url_scans ADD COLUMN scan_source TEXT DEFAULT "manual"')
        
        # Make user_id nullable if not already
        # SQLite doesn't support ALTER COLUMN, so this is handled by the new table creation
        
        # Create extension_settings table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS extension_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                extension_enabled BOOLEAN DEFAULT TRUE,
                download_protection BOOLEAN DEFAULT TRUE,
                hover_detection BOOLEAN DEFAULT TRUE,
                notifications_enabled BOOLEAN DEFAULT TRUE,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Create global_statistics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS global_statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                total_urls_scanned INTEGER DEFAULT 0,
                total_phishing_detected INTEGER DEFAULT 0,
                total_safe_urls INTEGER DEFAULT 0,
                total_suspicious_urls INTEGER DEFAULT 0,
                total_users INTEGER DEFAULT 0,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Seed global statistics row if empty
        cursor.execute('SELECT COUNT(*) FROM global_statistics')
        if cursor.fetchone()[0] == 0:
            cursor.execute('''
                INSERT INTO global_statistics (total_urls_scanned, total_phishing_detected, total_safe_urls, total_suspicious_urls, total_users)
                VALUES (0, 0, 0, 0, 0)
            ''')
        
        db.commit()
        print("Database initialized/migrated successfully")

def get_db():
    """Get database connection"""
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error):
    """Close database connection"""
    if hasattr(g, 'db'):
        g.db.close()

def load_ai_model():
    """Load the pre-trained ANN model and vectorizer"""
    global vectorizer, ann_model
    
    try:
        if os.path.exists(MODEL_PATH):
            # Load the model
            model_data = joblib.load(MODEL_PATH)
            ann_model = model_data['model']
            vectorizer = model_data['vectorizer']
            print("AI model loaded successfully")
        else:
            print("Model file not found, using fallback model")
            # Create a simple fallback model
            create_fallback_model()
    except Exception as e:
        print(f"Error loading AI model: {e}")
        create_fallback_model()

def create_fallback_model():
    """Create a simple fallback model for testing"""
    global vectorizer, ann_model
    
    # Simple TF-IDF vectorizer
    vectorizer = TfidfVectorizer(
        max_features=1000,
        stop_words='english',
        ngram_range=(1, 3)
    )
    
    # Simple rule-based model (fallback)
    class FallbackModel:
        def predict_proba(self, X):
            predictions = []
            for features in X:
                if hasattr(features, 'toarray'):
                    features = features.toarray()[0]
                score = np.random.random() * 0.3 + 0.1
                predictions.append([1 - score, score])
            return np.array(predictions)
    
    ann_model = FallbackModel()
    print("Fallback model created")

def extract_url_features(url: str) -> List[float]:
    """Extract features from URL for phishing detection"""
    features = []
    try:
        parsed = urllib.parse.urlparse(url)
        features.extend([
            len(url),
            len(parsed.netloc),
            len(parsed.path),
            len(parsed.query),
            url.count('.'),
            url.count('-'),
            url.count('_'),
            url.count('/'),
            url.count('='),
            url.count('?'),
            url.count('&'),
            url.count('%'),
        ])
        domain = parsed.netloc.lower()
        features.extend([
            domain.count('www'),
            domain.count('secure'),
            domain.count('login'),
            domain.count('signin'),
            domain.count('bank'),
            domain.count('paypal'),
            domain.count('amazon'),
            domain.count('google'),
            domain.count('facebook'),
            domain.count('twitter'),
        ])
        suspicious_patterns = [
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
            r'bit\.ly|goo\.gl|tinyurl\.com',
            r'[a-zA-Z0-9]{20,}',
            r'[0-9]{10,}',
        ]
        for pattern in suspicious_patterns:
            features.append(1.0 if re.search(pattern, url) else 0.0)
        features.append(1.0 if parsed.scheme == 'https' else 0.0)
        features = [float(f) for f in features]
        target_length = 50
        if len(features) < target_length:
            features.extend([0.0] * (target_length - len(features)))
        else:
            features = features[:target_length]
        return features
    except Exception as e:
        print(f"Error extracting features: {e}")
        return [0.0] * 50

def predict_phishing(url: str) -> Tuple[str, float]:
    """Predict if a URL is phishing using the AI model"""
    try:
        # Try the original ANN model first
        if ANN_MODEL_AVAILABLE:
            prediction, probability = predict_url_ann(url)
            
            # Convert numpy float32/float64 to Python float for JSON serialization
            if hasattr(probability, 'item'):
                probability = float(probability.item())
            else:
                probability = float(probability)
            
            # Map the prediction format to match content script expectations
            if prediction == "Malicious":
                return "Phishing", probability
            elif prediction == "Suspicious":
                return "Suspicious", probability
            else:  # Legitimate
                return "Safe", probability
        
        # Fallback to advanced prediction if ANN model fails
        else:
            return fallback_advanced_prediction(url)
            
    except Exception as e:
        print(f"Error in prediction: {e}")
        return fallback_prediction(url)

def predict_url_safety_ann_format(url: str) -> Tuple[str, float]:
    """Predict using exact same feature extraction as ANN model"""
    try:
        # Use EXACT same feature extraction as ann/predictor.py
        features = extract_features_ann_format([url])
        
        # Simple scoring based on actual ANN features
        feature_row = features.iloc[0]
        
        risk_score = 0.0
        
        # URL length risk (similar to training data patterns)
        if feature_row['url_length'] > 75:
            risk_score += 0.3
        if feature_row['url_length'] > 150:
            risk_score += 0.3
            
        # Domain length risk
        if feature_row['domain_length'] > 20:
            risk_score += 0.2
        if feature_row['domain_length'] > 40:
            risk_score += 0.3
            
        # Subdomain analysis
        if feature_row['number_of_subdomains'] > 2:
            risk_score += 0.3
        if feature_row['number_of_subdomains'] > 4:
            risk_score += 0.4
            
        # Character analysis
        if feature_row['number_of_special_char_in_url'] > 8:
            risk_score += 0.2
        if feature_row['number_of_digits_in_url'] > 10:
            risk_score += 0.2
        if feature_row['number_of_digits_in_domain'] > 3:
            risk_score += 0.3
            
        # Entropy analysis (high entropy can indicate obfuscation)
        if feature_row['entropy_of_url'] > 4.0:
            risk_score += 0.2
        if feature_row['entropy_of_domain'] > 3.0:
            risk_score += 0.2
            
        # Path complexity
        if feature_row['number_of_slash_in_url'] > 6:
            risk_score += 0.1
            
        # Subdomain length analysis
        if feature_row['average_subdomain_length'] > 15:
            risk_score += 0.2
            
        # Normalize score
        probability = min(risk_score, 1.0)
        
        # Apply thresholds similar to ANN model
        if probability >= 0.55:
            return "Phishing", probability
        elif probability >= 0.35:
            return "Suspicious", probability
        else:
            return "Safe", probability
            
    except Exception as e:
        print(f"Error in ANN format prediction: {e}")
        return fallback_prediction(url)

def extract_features_ann_format(urls):
    """Extract features using EXACT same method as ann/predictor.py"""
    import pandas as pd
    
    data = []
    for url in urls:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            subdomains = domain.split(".")[:-2] if len(domain.split(".")) > 2 else []

            url_length = len(url)
            avg_sub_len = np.mean([len(sd) for sd in subdomains]) if subdomains else 0
            
            # Calculate entropy exactly like ANN model
            entropy_url = 0
            if url:
                char_counts = [url.count(c)/len(url) for c in set(url)]
                entropy_url = -sum([p * np.log2(p) for p in char_counts if p > 0])
            
            entropy_domain = 0
            if domain:
                char_counts = [domain.count(c)/len(domain) for c in set(domain)]
                entropy_domain = -sum([p * np.log2(p) for p in char_counts if p > 0])
            
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
        except Exception as e:
            print(f"Error extracting features for {url}: {e}")
            # Add default values if extraction fails
            data.append([0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

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

def fallback_advanced_prediction(url: str) -> Tuple[str, float]:
    """Advanced fallback prediction using custom feature extraction"""
    try:
        features = extract_advanced_url_features(url)
        
        # Simple weighted scoring based on features
        score = 0.0
        
        # URL length scoring
        if features['url_length'] > 100:
            score += 0.3
        if features['url_length'] > 200:
            score += 0.2
            
        # Domain features
        if features['domain_length'] > 30:
            score += 0.2
        if features['number_of_subdomains'] > 3:
            score += 0.3
            
        # Suspicious characters
        if features['number_of_special_char_in_url'] > 10:
            score += 0.2
        if features['number_of_digits_in_url'] > 15:
            score += 0.3
            
        # Entropy (complexity) scoring
        if features['entropy_of_url'] > 4.5:
            score += 0.2
        if features['entropy_of_domain'] > 3.5:
            score += 0.2
            
        # Normalize score
        probability = min(score, 1.0)
        
        if probability >= 0.7:
            return "Phishing", probability
        elif probability >= 0.4:
            return "Suspicious", probability
        else:
            return "Safe", probability
            
    except Exception as e:
        print(f"Error in advanced fallback prediction: {e}")
        return fallback_prediction(url)

def extract_advanced_url_features(url: str) -> Dict[str, float]:
    """Extract advanced features from URL similar to the ANN model"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        subdomains = domain.split(".")[:-2] if len(domain.split(".")) > 2 else []
        
        # Calculate entropy
        def calculate_entropy(text):
            if not text:
                return 0
            entropy = 0
            for char in set(text):
                p = text.count(char) / len(text)
                if p > 0:
                    entropy -= p * np.log2(p)
            return entropy
        
        features = {
            'url_length': len(url),
            'average_subdomain_length': np.mean([len(sd) for sd in subdomains]) if subdomains else 0,
            'entropy_of_url': calculate_entropy(url),
            'entropy_of_domain': calculate_entropy(domain),
            'domain_length': len(domain),
            'number_of_subdomains': len(subdomains),
            'number_of_special_char_in_url': len(re.findall(r'[@_!#$%^&*()<>?/\|}{~:]', url)),
            'number_of_digits_in_url': len(re.findall(r'\d', url)),
            'number_of_digits_in_domain': len(re.findall(r'\d', domain)),
            'number_of_slash_in_url': url.count('/')
        }
        
        return features
        
    except Exception as e:
        print(f"Error extracting advanced features: {e}")
        return {
            'url_length': len(url),
            'average_subdomain_length': 0,
            'entropy_of_url': 0,
            'entropy_of_domain': 0,
            'domain_length': 0,
            'number_of_subdomains': 0,
            'number_of_special_char_in_url': 0,
            'number_of_digits_in_url': 0,
            'number_of_digits_in_domain': 0,
            'number_of_slash_in_url': 0
        }

def fallback_prediction(url: str) -> Tuple[str, float]:
    try:
        url_lower = url.lower()
        suspicious_indicators = 0
        total_indicators = 0
        patterns = [
            (r'bit\.ly|goo\.gl|tinyurl\.com', 0.8),
            (r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 0.7),
            (r'login|signin|secure', 0.3),
            (r'bank|paypal|credit', 0.4),
            (r'[a-zA-Z0-9]{20,}', 0.6),
            (r'[0-9]{10,}', 0.5),
        ]
        for pattern, weight in patterns:
            if re.search(pattern, url_lower):
                suspicious_indicators += weight
            total_indicators += weight
        probability = suspicious_indicators / total_indicators if total_indicators > 0 else 0.1
        if probability < 0.3:
            prediction = "Safe"
        elif probability < 0.6:
            prediction = "Suspicious"
        else:
            prediction = "Phishing"
        return prediction, probability
    except Exception as e:
        print(f"Error in fallback prediction: {e}")
        return "Unknown", 0.5

# Authentication decorator
def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'No token provided'}), 401
        if not token.startswith('Bearer '):
            return jsonify({'error': 'Invalid token format'}), 401
        token = token.split(' ')[1]
        user_id = verify_token(token)
        if user_id is None:
            return jsonify({'error': 'Invalid or expired token'}), 401
        request.user_id = user_id
        return f(*args, **kwargs)
    return decorated_function

def verify_token(token: str) -> Optional[int]:
    """Verify authentication token against auth_tokens table"""
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            'SELECT user_id FROM auth_tokens WHERE token = ? AND expires_at > CURRENT_TIMESTAMP',
            (token,)
        )
        row = cursor.fetchone()
        if row:
            return row['user_id']
        return None
    except Exception as e:
        print(f"Error verifying token: {e}")
        return None

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def generate_token() -> str:
    return secrets.token_urlsafe(32)

def update_global_statistics():
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT COUNT(*) FROM users WHERE is_active = TRUE')
        total_users = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM url_scans')
        total_urls_scanned = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM url_scans WHERE prediction = "Phishing"')
        total_phishing = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM url_scans WHERE prediction = "Safe"')
        total_safe = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM url_scans WHERE prediction = "Suspicious"')
        total_suspicious = cursor.fetchone()[0]
        cursor.execute('''
            UPDATE global_statistics 
            SET total_urls_scanned = ?, total_phishing_detected = ?, 
                total_safe_urls = ?, total_suspicious_urls = ?, 
                total_users = ?, last_updated = CURRENT_TIMESTAMP
        ''', (total_urls_scanned, total_phishing, total_safe, total_suspicious, total_users))
        db.commit()
    except Exception as e:
        print(f"Error updating global statistics: {e}")

def normalize_url_for_store(url: str) -> str:
	"""Normalize URL for consistent DB storage/matching."""
	try:
		if not url:
			return ''
		parsed = urllib.parse.urlparse(url)
		scheme = parsed.scheme or 'http'
		netloc = parsed.netloc.lower()
		path = parsed.path or '/'
		# Remove trailing slash except root
		if len(path) > 1 and path.endswith('/'):
			path = path[:-1]
		query = f"?{parsed.query}" if parsed.query else ''
		return f"{scheme}://{netloc}{path}{query}"
	except Exception:
		return url

def log_url_scan(user_id: int, url: str, prediction: str, probability: float):
    """Log URL scan to database"""
    try:
        db = get_db()
        cursor = db.cursor()
        
        normalized_url = normalize_url_for_store(url)
        
        cursor.execute('''
            INSERT INTO url_scans (user_id, url, prediction, probability)
            VALUES (?, ?, ?, ?)
        ''', (user_id, normalized_url, prediction, probability))
        
        db.commit()
        update_global_statistics()
        
    except Exception as e:
        print(f"Error logging URL scan: {e}")

# API Routes

@app.route('/', methods=['GET'])
def root():
    """Root endpoint for health checks"""
    return jsonify({
        'message': 'AI Phishing Detection Backend',
        'status': 'running',
        'endpoints': ['/health', '/predict_url', '/analyze_url'],
        'model_loaded': ann_model is not None
    })

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'model_loaded': ann_model is not None
    })

@app.after_request
def add_cors_headers(response):
    # Ensure CORS headers present for all responses
    response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', '*')
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    return response

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json(silent=True) or {}
        if 'username' not in data or 'email' not in data or 'password' not in data:
            return jsonify({'error': 'Missing required fields', 'message': 'Missing required fields'}), 400
        username = (data.get('username') or '').strip()
        email = (data.get('email') or '').strip().lower()
        password = data.get('password') or ''
        if len(username) < 3 or len(password) < 6:
            return jsonify({'error': 'Invalid input', 'message': 'Username must be ≥3 and password ≥6 chars'}), 400
        password_hash = hash_password(password)
        db = get_db()
        cursor = db.cursor()
        try:
            cursor.execute(
                'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                (username, email, password_hash)
            )
            user_id = cursor.lastrowid
            cursor.execute('''
                INSERT INTO extension_settings (user_id, extension_enabled, download_protection, hover_detection, notifications_enabled)
                VALUES (?, TRUE, TRUE, TRUE, TRUE)
            ''', (user_id,))
            db.commit()
            update_global_statistics()
            return jsonify({
                'message': 'User registered successfully',
                'user': {
                    'id': user_id,
                    'username': username,
                    'email': email
                }
            }), 201
        except sqlite3.IntegrityError:
            return jsonify({'error': 'Conflict', 'message': 'Username or email already exists'}), 409
    except Exception as e:
        print(f"Error in registration: {e}")
        return jsonify({'error': 'Internal server error', 'message': 'Internal server error'}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json(silent=True) or {}
        if 'password' not in data:
            return jsonify({'error': 'Missing password', 'message': 'Missing password'}), 400
        if 'email' not in data and 'username' not in data:
            return jsonify({'error': 'Missing email or username', 'message': 'Missing email or username'}), 400
        password = data.get('password') or ''
        email = (data.get('email') or '').strip().lower()
        username = (data.get('username') or '').strip()
        password_hash = hash_password(password)
        db = get_db()
        cursor = db.cursor()
        if email:
            cursor.execute(
                'SELECT id, username, email FROM users WHERE email = ? AND password_hash = ? AND is_active = TRUE',
                (email, password_hash)
            )
        else:
            cursor.execute(
                'SELECT id, username, email FROM users WHERE username = ? AND password_hash = ? AND is_active = TRUE',
                (username, password_hash)
            )
        user = cursor.fetchone()
        if not user:
            return jsonify({'error': 'Invalid credentials', 'message': 'Invalid credentials'}), 401
        # Generate and store token with 7-day expiry
        token = generate_token()
        expires_at = (datetime.utcnow() + timedelta(days=7)).isoformat(sep=' ')
        cursor.execute(
            'INSERT INTO auth_tokens (token, user_id, expires_at) VALUES (?, ?, ?)',
            (token, user['id'], expires_at)
        )
        cursor.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user['id'],))
        db.commit()
        return jsonify({
            'message': 'Login successful',
            'token': token,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'email': user['email']
            }
        }), 200
    except Exception as e:
        print(f"Error in login: {e}")
        return jsonify({'error': 'Internal server error', 'message': 'Internal server error'}), 500

@app.route('/predict_url', methods=['POST'])
def predict_url():
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400
        url = data['url']
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        prediction, probability = predict_phishing(url)
        
        # Convert numpy float32/float64 to Python float for JSON serialization
        if hasattr(probability, 'item'):
            probability = float(probability.item())
        else:
            probability = float(probability)
            
        user_id = None
        if 'Authorization' in request.headers:
            try:
                token = request.headers['Authorization'].split(' ')[1]
                user_id = verify_token(token)
            except Exception:
                user_id = None
        if user_id:
            log_url_scan(user_id, url, prediction, probability)
        return jsonify({
            'url': url,
            'prediction': prediction,
            'probability': probability,
            'timestamp': datetime.now().isoformat()
        }), 200
    except Exception as e:
        print(f"Error in URL prediction: {e}")
        return jsonify({'error': 'Error processing URL'}), 500


@app.route('/check', methods=['POST'])
def check_url():
    """Lightweight endpoint used by extension content script.
    Expects JSON { "url": "..." } and returns { prediction, probability }.
    Adds simple stdout logging so user sees activity in terminal.
    """
    try:
        data = request.get_json(silent=True) or {}
        raw_url = data.get('url') or ''
        if not raw_url:
            return jsonify({'error': 'URL is required'}), 400
        url = raw_url
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        start_ts = datetime.utcnow().isoformat(timespec='seconds')
        print(f"[CHECK][START] {start_ts} url={url}")
        prediction, probability = predict_phishing(url)
        if hasattr(probability, 'item'):
            probability = float(probability.item())
        else:
            probability = float(probability)
        end_ts = datetime.utcnow().isoformat(timespec='seconds')
        print(f"[CHECK][RESULT] {end_ts} url={url} prediction={prediction} probability={probability:.4f}")
        return jsonify({
            'url': url,
            'prediction': prediction,
            'probability': probability,
            'timestamp': end_ts
        }), 200
    except Exception as e:
        err_ts = datetime.utcnow().isoformat(timespec='seconds')
        print(f"[CHECK][ERROR] {err_ts} error={e}")
        return jsonify({'error': 'Internal error'}), 500



@app.route('/analyze_url', methods=['POST'])
def analyze_url():
    """Detailed URL analysis endpoint"""
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400
        
        url = data['url']
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Get detailed analysis using ANN model
        if ANN_MODEL_AVAILABLE:
            try:
                prediction, probability = predict_phishing(url)
                
                # Convert numpy float32/float64 to Python float for JSON serialization
                if hasattr(probability, 'item'):
                    probability = float(probability.item())
                else:
                    probability = float(probability)
                    
                analysis = {
                    'url': url,
                    'prediction': prediction,
                    'confidence': probability,
                    'risk_level': 'high' if prediction == 'phishing' and probability > 0.7 else 'medium' if prediction == 'phishing' else 'low'
                }
            except Exception as e:
                print(f"Error in ANN analysis: {e}")
                analysis = {
                    'url': url,
                    'prediction': 'safe',
                    'confidence': 0.5,
                    'risk_level': 'unknown'
                }
        else:
            # Basic analysis
            prediction, probability = predict_phishing(url)
            
            # Convert numpy float32/float64 to Python float for JSON serialization
            if hasattr(probability, 'item'):
                probability = float(probability.item())
            else:
                probability = float(probability)
                
            analysis = {
                'url': url,
                'prediction': prediction,
                'confidence': probability,
                'features': {},
                'risk_factors': []
            }
        
        # Log scan if user is authenticated
        user_id = None
        if 'Authorization' in request.headers:
            try:
                token = request.headers['Authorization'].split(' ')[1]
                user_id = verify_token(token)
            except Exception:
                user_id = None
        
        if user_id:
            log_url_scan(user_id, url, analysis['prediction'], analysis['confidence'])
        
        analysis['timestamp'] = datetime.now().isoformat()
        return jsonify(analysis), 200
        
    except Exception as e:
        print(f"Error in URL analysis: {e}")
        return jsonify({'error': 'Error analyzing URL'}), 500

@app.route('/is_url_flagged', methods=['GET'])
@require_auth
def is_url_flagged():
	"""Return whether the given URL is flagged by current user."""
	try:
		user_id = request.user_id
		url = request.args.get('url', '')
		if not url:
			return jsonify({'flagged': False}), 200
		norm = normalize_url_for_store(url)
		db = get_db()
		cursor = db.cursor()
		cursor.execute('SELECT 1 FROM flagged_urls WHERE user_id = ? AND url = ? LIMIT 1', (user_id, norm))
		row = cursor.fetchone()
		return jsonify({'flagged': bool(row)}), 200
	except Exception as e:
		print(f"Error checking flag status: {e}")
		return jsonify({'flagged': False}), 200

@app.route('/unflag_url', methods=['POST'])
@require_auth
def unflag_url():
	"""Remove a flagged URL for current user."""
	try:
		data = request.get_json(silent=True) or {}
		url = data.get('url') or ''
		if not url:
			return jsonify({'error': 'URL is required', 'message': 'URL is required'}), 400
		norm = normalize_url_for_store(url)
		db = get_db()
		cursor = db.cursor()
		cursor.execute('DELETE FROM flagged_urls WHERE user_id = ? AND url = ?', (request.user_id, norm))
		db.commit()
		return jsonify({'message': 'URL unflagged'}), 200
	except Exception as e:
		print(f"Error unflagging URL: {e}")
		return jsonify({'error': 'Error unflagging URL'}), 500

# Update existing flag_url to store normalized URL
# (redefine flag_url to ensure normalization)
@app.route('/flag_url', methods=['POST'])
@require_auth
def flag_url():
	"""Flag a URL as suspicious"""
	try:
		data = request.get_json(silent=True) or {}
		user_id = request.user_id
		if 'url' not in data:
			return jsonify({'error': 'URL is required', 'message': 'URL is required'}), 400
		url = normalize_url_for_store(data.get('url') or '')
		prediction = data.get('prediction', 'Flagged')
		probability = float(data.get('probability', 1.0) or 1.0)
		notes = data.get('notes', '')
		db = get_db()
		cursor = db.cursor()
		# Upsert-like: avoid duplicates for same user+url
		cursor.execute('SELECT id FROM flagged_urls WHERE user_id = ? AND url = ?', (user_id, url))
		exists = cursor.fetchone()
		if exists:
			return jsonify({'message': 'Already flagged', 'url': url}), 200
		cursor.execute('''
			INSERT INTO flagged_urls (user_id, url, prediction, probability, notes)
			VALUES (?, ?, ?, ?, ?)
		''', (user_id, url, prediction, probability, notes))
		db.commit()
		return jsonify({'message': 'URL flagged successfully', 'url': url}), 200
	except Exception as e:
		print(f"Error flagging URL: {e}")
		return jsonify({'error': 'Error flagging URL'}), 500







@app.route('/update_extension_settings', methods=['POST'])
@require_auth
def update_extension_settings():
    try:
        data = request.get_json()
        user_id = request.user_id
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            UPDATE extension_settings 
            SET extension_enabled = ?, download_protection = ?, 
                hover_detection = ?, notifications_enabled = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE user_id = ?
        ''', (
            data.get('extension_enabled', True),
            data.get('download_protection', True),
            data.get('hover_detection', True),
            data.get('notifications_enabled', True),
            user_id
        ))
        db.commit()
        return jsonify({'message': 'Settings updated successfully'}), 200
    except Exception as e:
        print(f"Error updating extension settings: {e}")
        return jsonify({'error': 'Error updating settings'}), 500

@app.route('/get_extension_settings', methods=['GET'])
@require_auth
def get_extension_settings():
    try:
        user_id = request.user_id
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT * FROM extension_settings WHERE user_id = ?', (user_id,))
        settings = cursor.fetchone()
        if not settings:
            cursor.execute('''
                INSERT INTO extension_settings (user_id, extension_enabled, download_protection, hover_detection, notifications_enabled)
                VALUES (?, TRUE, TRUE, TRUE, TRUE)
            ''', (user_id,))
            db.commit()
            cursor.execute('SELECT * FROM extension_settings WHERE user_id = ?', (user_id,))
            settings = cursor.fetchone()
        return jsonify(dict(settings)), 200
    except Exception as e:
        print(f"Error getting extension settings: {e}")
        return jsonify({'error': 'Error retrieving settings'}), 500





# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    print("Starting AI Phishing Detection Backend...")
    
    # Initialize database
    with app.app_context():
        init_database()
    
    # Load AI model
    load_ai_model()
    
    print(f"ANN Model Available: {ANN_MODEL_AVAILABLE}")
    print("Server starting on http://127.0.0.1:5000")
    
    app.run(
        host='127.0.0.1',
        port=5000,
        debug=True
    ) 