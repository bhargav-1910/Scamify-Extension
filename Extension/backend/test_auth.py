#!/usr/bin/env python3
"""
Test script for authentication endpoints
"""

import requests
import json

BASE_URL = 'http://127.0.0.1:5000'

def test_register():
    """Test user registration"""
    print("Testing user registration...")
    
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

def test_protected_endpoint(token):
    """Test a protected endpoint with token"""
    print(f"\nTesting protected endpoint with token...")
    
    headers = {
        'Authorization': f'Bearer {token}'
    }
    
    try:
        response = requests.get(f'{BASE_URL}/get_stats', headers=headers)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.json()}")
        return response.status_code == 200
    except Exception as e:
        print(f"Error: {e}")
        return False

def main():
    """Run all tests"""
    print("=== Authentication Test Suite ===\n")
    
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
    
    # Test protected endpoint
    if test_protected_endpoint(token):
        print("✅ Protected endpoint access successful")
    else:
        print("❌ Protected endpoint access failed")

if __name__ == '__main__':
    main() 