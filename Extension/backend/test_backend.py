#!/usr/bin/env python3
"""
Test script for backend endpoints
"""

import requests
import json
import time

BASE_URL = 'http://127.0.0.1:5000'

def test_health():
    """Test health check endpoint"""
    print("Testing health check...")
    try:
        response = requests.get(f'{BASE_URL}/health')
        print(f"Status: {response.status_code}")
        print(f"Response: {response.json()}")
        return response.status_code == 200
    except Exception as e:
        print(f"Error: {e}")
        return False

def test_register():
    """Test user registration"""
    print("\nTesting user registration...")
    
    data = {
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'testpass123'
    }
    
    try:
        response = requests.post(f'{BASE_URL}/register', json=data)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.json()}")
        return response.status_code == 201
    except Exception as e:
        print(f"Error: {e}")
        return False

def test_login():
    """Test user login"""
    print("\nTesting user login...")
    
    data = {
        'email': 'test@example.com',
        'password': 'testpass123'
    }
    
    try:
        response = requests.post(f'{BASE_URL}/login', json=data)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.json()}")
        
        if response.status_code == 200:
            return response.json().get('token')
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None

def test_url_prediction(token):
    """Test URL prediction endpoint"""
    print("\nTesting URL prediction...")
    
    test_urls = [
        'https://www.google.com',
        'https://bit.ly/suspicious',
        'https://www.example.com'
    ]
    
    headers = {
        'Authorization': f'Bearer {token}'
    }
    
    for url in test_urls:
        try:
            response = requests.post(f'{BASE_URL}/predict_url', 
                                  json={'url': url}, 
                                  headers=headers)
            print(f"URL: {url}")
            print(f"Status: {response.status_code}")
            if response.ok:
                result = response.json()
                print(f"Prediction: {result['prediction']}, Confidence: {result['probability']:.2f}")
            else:
                print(f"Error: {response.json()}")
            print()
        except Exception as e:
            print(f"Error testing {url}: {e}")

def test_global_stats():
    """Test global statistics endpoint"""
    print("\nTesting global statistics...")
    
    try:
        response = requests.get(f'{BASE_URL}/get_global_stats')
        print(f"Status: {response.status_code}")
        if response.ok:
            stats = response.json()
            print(f"Total URLs: {stats['total_urls_scanned']}")
            print(f"Phishing Detected: {stats['total_phishing_detected']}")
            print(f"Safe URLs: {stats['total_safe_urls']}")
        else:
            print(f"Error: {response.json()}")
        return response.status_code == 200
    except Exception as e:
        print(f"Error: {e}")
        return False

def test_extension_settings(token):
    """Test extension settings endpoints"""
    print("\nTesting extension settings...")
    
    headers = {
        'Authorization': f'Bearer {token}'
    }
    
    # Get current settings
    try:
        response = requests.get(f'{BASE_URL}/get_extension_settings', headers=headers)
        print(f"Get settings status: {response.status_code}")
        if response.ok:
            settings = response.json()
            print(f"Current settings: {settings}")
        else:
            print(f"Error: {response.json()}")
            return False
    except Exception as e:
        print(f"Error getting settings: {e}")
        return False
    
    # Update settings
    new_settings = {
        'extension_enabled': True,
        'download_protection': False,
        'hover_detection': True,
        'notifications_enabled': False
    }
    
    try:
        response = requests.post(f'{BASE_URL}/update_extension_settings', 
                              json=new_settings, 
                              headers=headers)
        print(f"Update settings status: {response.status_code}")
        if response.ok:
            print("Settings updated successfully")
        else:
            print(f"Error: {response.json()}")
            return False
    except Exception as e:
        print(f"Error updating settings: {e}")
        return False
    
    return True

def main():
    """Run all tests"""
    print("=== Backend Test Suite ===\n")
    
    # Test health check
    if not test_health():
        print("❌ Health check failed")
        return
    
    print("✅ Health check passed")
    
    # Test registration
    if test_register():
        print("✅ Registration successful")
    else:
        print("❌ Registration failed")
        return
    
    # Test login
    token = test_login()
    if token:
        print("✅ Login successful")
    else:
        print("❌ Login failed")
        return
    
    # Test URL prediction
    test_url_prediction(token)
    
    # Test global statistics
    if test_global_stats():
        print("✅ Global statistics working")
    else:
        print("❌ Global statistics failed")
    
    # Test extension settings
    if test_extension_settings(token):
        print("✅ Extension settings working")
    else:
        print("❌ Extension settings failed")
    
    print("\n=== Test Suite Complete ===")

if __name__ == '__main__':
    main() 