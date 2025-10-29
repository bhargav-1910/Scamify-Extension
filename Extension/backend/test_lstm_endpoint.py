#!/usr/bin/env python3
"""
Test script to verify LSTM behavioral analysis endpoint works correctly
"""
import requests
import json
import time

def test_behavioral_endpoint():
    """Test the /analyze_behavioral endpoint"""
    url = "http://127.0.0.1:5000/analyze_behavioral"
    
    test_cases = [
        {
            "name": "Safe URL Test",
            "url": "https://example.com",
            "expected_models": {"lstm_sandbox", "lstm"}
        },
        {
            "name": "Suspicious URL Test", 
            "url": "https://phishing-test-site.com",
            "expected_models": {"lstm_sandbox", "lstm"}
        },
        {
            "name": "Google Test",
            "url": "https://google.com",
            "expected_models": {"lstm_sandbox", "lstm"}
        }
    ]
    
    print("🧪 Testing LSTM Behavioral Analysis Endpoint")
    print("=" * 50)
    
    for i, test in enumerate(test_cases, 1):
        print(f"\n{i}. {test['name']}")
        print(f"   URL: {test['url']}")
        
        try:
            # Send POST request
            data = {"url": test['url']}
            response = requests.post(url, json=data, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                print(f"   ✅ Status: {response.status_code}")
                print(f"   📊 Model Used: {result.get('model_used', 'unknown')}")
                print(f"   🎯 Prediction: {result.get('prediction', 'unknown')}")
                print(f"   📈 Probability: {result.get('probability', 'unknown'):.3f}")
                print(f"   ⏱️ Extraction Time: {result.get('extraction_time', 0):.2f}s")
                print(f"   🔍 Features Count: {len(result.get('behavioral_features', [])) if result.get('behavioral_features') else 'None'}")
                
                # Check if LSTM model was used
                if result.get('model_used') in test.get('expected_models', set()):
                    print(f"   🎉 SUCCESS: LSTM sandbox model used correctly!")
                elif result.get('model_used') == 'ann_fallback':
                    print(f"   ⚠️  WARNING: Fell back to ANN model")
                else:
                    print(f"   ❌ ERROR: Unexpected model: {result.get('model_used')}")
                    
            else:
                print(f"   ❌ ERROR: Status {response.status_code}")
                print(f"   Response: {response.text}")
                
        except requests.exceptions.ConnectionError:
            print(f"   ❌ ERROR: Cannot connect to server. Is it running?")
        except requests.exceptions.Timeout:
            print(f"   ⏰ TIMEOUT: Request took too long")
        except Exception as e:
            print(f"   ❌ ERROR: {e}")
    
    print("\n" + "=" * 50)
    print("🏁 Test Complete!")

if __name__ == "__main__":
    test_behavioral_endpoint()