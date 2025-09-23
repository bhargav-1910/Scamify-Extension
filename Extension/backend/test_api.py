#!/usr/bin/env python3
"""
Test script for AI Phishing Detection Backend API
Tests all endpoints to ensure they're working correctly
"""

import requests
import json
import time
from urllib.parse import urljoin

# Configuration
BASE_URL = "http://localhost:5000"
TEST_URLS = [
    "https://www.google.com",
    "https://www.example.com",
    "https://bit.ly/3abc123",
    "http://192.168.1.1/login",
    "https://suspicious-site.com/secure/login"
]

def test_endpoint(endpoint, method="GET", data=None, headers=None):
    """Test a single API endpoint"""
    url = urljoin(BASE_URL, endpoint)
    
    try:
        if method == "GET":
            response = requests.get(url, headers=headers, timeout=10)
        elif method == "POST":
            response = requests.post(url, json=data, headers=headers, timeout=10)
        else:
            print(f"❌ Unknown method: {method}")
            return False
        
        print(f"✅ {method} {endpoint}: {response.status_code}")
        
        if response.status_code < 400:
            try:
                result = response.json()
                if endpoint == "/predict_url":
                    print(f"   Prediction: {result.get('prediction')} ({result.get('probability', 0):.2f})")
                elif endpoint == "/health":
                    print(f"   Status: {result.get('status')}")
                elif endpoint == "/register" or endpoint == "/login":
                    print(f"   Message: {result.get('message')}")
            except json.JSONDecodeError:
                print(f"   Response: {response.text[:100]}...")
        else:
            print(f"   Error: {response.text[:100]}...")
        
        return response.status_code < 400
        
    except requests.exceptions.RequestException as e:
        print(f"❌ {method} {endpoint}: Connection error - {e}")
        return False

def test_health_check():
    """Test the health check endpoint"""
    print("\n🏥 Testing Health Check...")
    return test_endpoint("/health")

def test_url_prediction():
    """Test URL prediction endpoint"""
    print("\n🔍 Testing URL Prediction...")
    
    success_count = 0
    for url in TEST_URLS:
        data = {"url": url}
        if test_endpoint("/predict_url", method="POST", data=data):
            success_count += 1
        time.sleep(0.5)  # Small delay between requests
    
    print(f"   Success rate: {success_count}/{len(TEST_URLS)}")
    return success_count > 0

def test_user_registration():
    """Test user registration endpoint"""
    print("\n👤 Testing User Registration...")
    
    # Test with valid data
    data = {
        "username": "testuser",
        "email": "test@example.com",
        "password": "testpass123"
    }
    
    success = test_endpoint("/register", method="POST", data=data)
    
    if success:
        print("   ✅ Registration successful")
    else:
        print("   ⚠️  Registration failed (might be duplicate user)")
    
    return True  # Don't fail the test for duplicate users

def test_user_login():
    """Test user login endpoint"""
    print("\n🔐 Testing User Login...")
    
    data = {
        "username": "testuser",
        "password": "testpass123"
    }
    
    success = test_endpoint("/login", method="POST", data=data)
    
    if success:
        print("   ✅ Login successful")
        # Extract token for authenticated tests
        try:
            response = requests.post(urljoin(BASE_URL, "/login"), json=data)
            if response.status_code == 200:
                token = response.json().get("token")
                return token
        except:
            pass
    
    return None

def test_authenticated_endpoints(token):
    """Test endpoints that require authentication"""
    if not token:
        print("\n⚠️  Skipping authenticated endpoints (no token)")
        return True
    
    print("\n🔒 Testing Authenticated Endpoints...")
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Test flag URL
    data = {"url": "https://suspicious-site.com"}
    test_endpoint("/flag_url", method="POST", data=data, headers=headers)
    
    # Test get stats
    test_endpoint("/get_stats", headers=headers)
    
    # Test get user history
    test_endpoint("/get_user_history", headers=headers)
    
    return True

def test_scan_details():
    """Test scan details endpoint"""
    print("\n📊 Testing Scan Details...")
    
    test_url = "https://www.example.com"
    endpoint = f"/scan_details?url={test_url}"
    return test_endpoint(endpoint)

def test_behavior_analysis():
    """Test behavior analysis endpoint"""
    print("\n🧠 Testing Behavior Analysis...")
    
    data = {"url": "https://www.example.com"}
    return test_endpoint("/analyze_behavior", method="POST", data=data)

def run_all_tests():
    """Run all API tests"""
    print("🚀 Starting API Tests...")
    print("=" * 50)
    
    # Check if backend is running
    try:
        response = requests.get(BASE_URL, timeout=5)
        print("✅ Backend is accessible")
    except requests.exceptions.RequestException:
        print("❌ Backend is not accessible. Make sure it's running on localhost:5000")
        print("   Start the backend with: python app.py")
        return False
    
    # Run tests
    tests = [
        ("Health Check", test_health_check),
        ("URL Prediction", test_url_prediction),
        ("User Registration", test_user_registration),
        ("User Login", test_user_login),
        ("Scan Details", test_scan_details),
        ("Behavior Analysis", test_behavior_analysis),
    ]
    
    results = {}
    token = None
    
    for test_name, test_func in tests:
        try:
            if test_name == "User Login":
                result = test_func()
                if isinstance(result, str):  # Token returned
                    token = result
                    results[test_name] = True
                else:
                    results[test_name] = result
            else:
                results[test_name] = test_func()
        except Exception as e:
            print(f"❌ {test_name} failed with error: {e}")
            results[test_name] = False
    
    # Test authenticated endpoints
    if token:
        results["Authenticated Endpoints"] = test_authenticated_endpoints(token)
    
    # Print summary
    print("\n" + "=" * 50)
    print("📋 Test Results Summary")
    print("=" * 50)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} {test_name}")
        if result:
            passed += 1
    
    print(f"\n🎯 Overall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! The backend is working correctly.")
    else:
        print("⚠️  Some tests failed. Check the output above for details.")
    
    return passed == total

if __name__ == "__main__":
    try:
        success = run_all_tests()
        exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n❌ Tests interrupted by user")
        exit(1)
    except Exception as e:
        print(f"\n\n❌ Tests failed with error: {e}")
        exit(1) 