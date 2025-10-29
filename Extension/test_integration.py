"""
Quick Test Script for Ultra-Enhanced ANN Integration
Tests the backend API and model loading
"""

import requests
import json
import sys
import os

# Add backend to path
backend_path = os.path.join(os.path.dirname(__file__), 'backend')
sys.path.insert(0, backend_path)

print("="*70)
print("ULTRA-ENHANCED ANN INTEGRATION TEST")
print("="*70)

# Test 1: Check if model predictor can be imported
print("\n📦 Test 1: Importing Ultra-Enhanced predictor...")
try:
    from backend.models.ultra_ann_predictor import get_ultra_predictor, predict_url_ultra
    predictor = get_ultra_predictor()
    
    if predictor.model_loaded:
        print(f"✅ Model loaded successfully!")
        print(f"   Features: {len(predictor.feature_names)}")
        print(f"   Expected: 53")
    else:
        print("❌ Model not loaded")
        sys.exit(1)
except Exception as e:
    print(f"❌ Import failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Test 2: Test direct prediction
print("\n🧪 Test 2: Direct prediction (without API)...")
test_urls = [
    ("https://www.google.com", "Safe"),
    ("https://accounts.google.com", "Safe"),
    ("http://paypal-secure-login.xyz", "Phishing"),
    ("http://g00gle.com", "Phishing"),
]

for url, expected in test_urls:
    try:
        prediction, probability = predict_url_ultra(url)
        status = "✅" if expected.lower() in prediction.lower() else "❌"
        print(f"{status} {url}")
        print(f"   Expected: {expected}, Got: {prediction} ({probability:.2%})")
    except Exception as e:
        print(f"❌ Error: {e}")

# Test 3: Test backend API
print("\n🌐 Test 3: Testing /check API endpoint...")
print("   Make sure backend is running on http://127.0.0.1:5000")

backend_running = False
try:
    response = requests.get("http://127.0.0.1:5000/health", timeout=2)
    if response.ok:
        backend_running = True
        print("✅ Backend is running")
    else:
        print("⚠️ Backend responded but not healthy")
except Exception as e:
    print(f"❌ Backend not reachable: {e}")
    print("   Start backend with: cd backend && python app.py")

if backend_running:
    print("\n   Testing /check endpoint with sample URLs...")
    
    for url, expected in test_urls[:2]:  # Test first 2 URLs
        try:
            response = requests.post(
                "http://127.0.0.1:5000/check",
                json={"url": url},
                timeout=5
            )
            
            if response.ok:
                data = response.json()
                model_used = data.get('model', 'unknown')
                prediction = data.get('prediction', 'unknown')
                probability = data.get('probability', 0)
                
                status = "✅" if model_used == 'ultra_enhanced_ann' else "⚠️"
                print(f"{status} {url}")
                print(f"   Model: {model_used}")
                print(f"   Prediction: {prediction} ({probability:.2%})")
                
                if model_used != 'ultra_enhanced_ann':
                    print("   ⚠️ WARNING: Not using Ultra-Enhanced model!")
            else:
                print(f"❌ API error: {response.status_code}")
        except Exception as e:
            print(f"❌ Request failed: {e}")

# Summary
print("\n" + "="*70)
print("TEST SUMMARY")
print("="*70)
print("\n✅ Integration successful if:")
print("   1. Model imports without errors")
print("   2. Feature count is 53")
print("   3. Predictions are accurate")
print("   4. API returns 'ultra_enhanced_ann' as model")
print("\n❌ If any tests failed:")
print("   - Check if model files exist in ANN-model/")
print("   - Install dependencies: pip install -r backend/requirements.txt")
print("   - Start backend: cd backend && python app.py")
print("\n📚 See INTEGRATION_GUIDE.md for detailed setup instructions")
print("="*70)
