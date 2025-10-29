#!/usr/bin/env python3
"""
Comprehensive Testing Suite for ScamiFy LSTM Integration
Tests all components of the dual-model phishing detection system
"""

import os
import sys
import time
import asyncio
import requests
import json
from urllib.parse import urljoin
import concurrent.futures

# Test Configuration
BASE_URL = "http://127.0.0.1:5000"
TEST_TIMEOUT = 30

# Test URLs covering various scenarios
TEST_URLS = {
    'legitimate': [
        'https://www.google.com',
        'https://www.github.com',
        'https://www.microsoft.com',
        'https://www.stackoverflow.com'
    ],
    'suspicious': [
        'http://bit.ly/suspicious-link',
        'https://example.com/login',
        'http://192.168.1.1/secure',
        'https://tinyurl.com/phish-test'
    ],
    'test_sites': [
        'https://httpbin.org/html',
        'https://httpbin.org/forms/post',
        'https://httpbin.org/redirect/3'
    ]
}

class ScamifyTester:
    """Comprehensive testing suite for ScamiFy integration"""
    
    def __init__(self):
        self.results = {
            'ann_tests': [],
            'lstm_tests': [],
            'integration_tests': [],
            'performance_tests': [],
            'error_tests': []
        }
        self.start_time = time.time()
        
    def log(self, message, level='INFO'):
        """Log test messages with timestamp"""
        timestamp = time.strftime('%H:%M:%S')
        print(f"[{timestamp}] [{level}] {message}")
    
    def test_backend_health(self):
        """Test backend service availability"""
        self.log("Testing backend health...")
        
        try:
            response = requests.get(f"{BASE_URL}/health", timeout=5)
            if response.status_code == 200:
                data = response.json()
                self.log(f"✅ Backend healthy - Model loaded: {data.get('model_loaded', False)}")
                return True
            else:
                self.log(f"❌ Backend unhealthy - Status: {response.status_code}", 'ERROR')
                return False
        except Exception as e:
            self.log(f"❌ Backend connection failed: {e}", 'ERROR')
            return False
    
    def test_lstm_health(self):
        """Test LSTM components health"""
        self.log("Testing LSTM health...")
        
        try:
            response = requests.get(f"{BASE_URL}/lstm_health", timeout=5)
            if response.status_code == 200:
                data = response.json()
                self.log(f"✅ LSTM Health Check:")
                self.log(f"   - LSTM Available: {data.get('lstm_available', False)}")
                self.log(f"   - Model Loaded: {data.get('lstm_model_loaded', False)}")
                self.log(f"   - Extractor Available: {data.get('behavioral_extractor_available', False)}")
                return data.get('lstm_available', False)
            else:
                self.log(f"❌ LSTM health check failed - Status: {response.status_code}", 'ERROR')
                return False
        except Exception as e:
            self.log(f"❌ LSTM health check error: {e}", 'ERROR')
            return False
    
    def test_ann_model(self, url_category='legitimate'):
        """Test ANN model endpoint"""
        self.log(f"Testing ANN model with {url_category} URLs...")
        
        results = []
        urls = TEST_URLS.get(url_category, TEST_URLS['legitimate'][:2])
        
        for url in urls:
            try:
                start_time = time.time()
                response = requests.post(
                    f"{BASE_URL}/check",
                    json={'url': url},
                    timeout=10
                )
                response_time = time.time() - start_time
                
                if response.status_code == 200:
                    data = response.json()
                    result = {
                        'url': url,
                        'prediction': data.get('prediction', 'unknown'),
                        'probability': data.get('probability', 0),
                        'response_time': response_time,
                        'status': 'success'
                    }
                    
                    self.log(f"   ✅ {url}: {result['prediction']} ({result['probability']:.2f}) - {response_time:.2f}s")
                else:
                    result = {
                        'url': url,
                        'status': 'failed',
                        'error': f"HTTP {response.status_code}",
                        'response_time': response_time
                    }
                    self.log(f"   ❌ {url}: HTTP {response.status_code}", 'ERROR')
                
                results.append(result)
                time.sleep(0.5)  # Rate limiting
                
            except Exception as e:
                result = {
                    'url': url,
                    'status': 'error',
                    'error': str(e),
                    'response_time': 0
                }
                results.append(result)
                self.log(f"   ❌ {url}: {e}", 'ERROR')
        
        self.results['ann_tests'].extend(results)
        return results
    
    def test_lstm_model(self, url_category='test_sites'):
        """Test LSTM behavioral analysis endpoint"""
        self.log(f"Testing LSTM model with {url_category} URLs...")
        
        results = []
        urls = TEST_URLS.get(url_category, TEST_URLS['test_sites'])
        
        # Limit to 2 URLs for LSTM testing due to time constraints
        test_urls = urls[:2]
        
        for url in test_urls:
            try:
                self.log(f"   Analyzing: {url}")
                start_time = time.time()
                
                response = requests.post(
                    f"{BASE_URL}/analyze_behavioral",
                    json={'url': url},
                    timeout=45  # Longer timeout for behavioral analysis
                )
                
                response_time = time.time() - start_time
                
                if response.status_code == 200:
                    data = response.json()
                    result = {
                        'url': url,
                        'prediction': data.get('prediction', 'unknown'),
                        'probability': data.get('probability', 0),
                        'recommendation': data.get('recommendation', 'unknown'),
                        'model_used': data.get('model_used', 'unknown'),
                        'extraction_time': data.get('extraction_time', 0),
                        'response_time': response_time,
                        'behavioral_features': data.get('behavioral_features'),
                        'status': 'success'
                    }
                    
                    self.log(f"   ✅ {url}:")
                    self.log(f"      Prediction: {result['prediction']} ({result['probability']:.2f})")
                    self.log(f"      Recommendation: {result['recommendation']}")
                    self.log(f"      Model: {result['model_used']}")
                    self.log(f"      Times: Extract {result['extraction_time']:.1f}s, Total {response_time:.1f}s")
                    
                    if result['behavioral_features']:
                        features = result['behavioral_features']
                        self.log(f"      Features: SSL={features.get('ssl_valid', 0)}, "
                               f"Forms={features.get('forms', 0)}, "
                               f"Suspicious={features.get('suspicious_keywords', 0)}")
                
                else:
                    result = {
                        'url': url,
                        'status': 'failed',
                        'error': f"HTTP {response.status_code}",
                        'response_time': response_time
                    }
                    self.log(f"   ❌ {url}: HTTP {response.status_code}", 'ERROR')
                
                results.append(result)
                time.sleep(1)  # Rate limiting between LSTM requests
                
            except Exception as e:
                result = {
                    'url': url,
                    'status': 'error',
                    'error': str(e),
                    'response_time': 0
                }
                results.append(result)
                self.log(f"   ❌ {url}: {e}", 'ERROR')
        
        self.results['lstm_tests'].extend(results)
        return results
    
    def test_performance_benchmarks(self):
        """Test performance benchmarks for both models"""
        self.log("Running performance benchmarks...")
        
        # ANN Performance Test
        ann_times = []
        test_url = 'https://www.example.com'
        
        self.log("   Testing ANN model performance...")
        for i in range(5):
            try:
                start_time = time.time()
                response = requests.post(f"{BASE_URL}/check", json={'url': test_url}, timeout=5)
                response_time = time.time() - start_time
                
                if response.status_code == 200:
                    ann_times.append(response_time)
                    self.log(f"     Run {i+1}: {response_time:.3f}s")
                
                time.sleep(0.1)
            except Exception as e:
                self.log(f"     Run {i+1}: Failed - {e}", 'ERROR')
        
        if ann_times:
            avg_ann = sum(ann_times) / len(ann_times)
            self.log(f"   ANN Average Response Time: {avg_ann:.3f}s")
            
            performance_result = {
                'model': 'ann',
                'average_time': avg_ann,
                'min_time': min(ann_times),
                'max_time': max(ann_times),
                'success_rate': len(ann_times) / 5
            }
            self.results['performance_tests'].append(performance_result)
    
    def test_error_handling(self):
        """Test error handling and fallback mechanisms"""
        self.log("Testing error handling...")
        
        error_tests = [
            {
                'name': 'Invalid URL',
                'endpoint': '/check',
                'data': {'url': 'not-a-url'},
                'expected_status': 400
            },
            {
                'name': 'Missing URL',
                'endpoint': '/check',
                'data': {},
                'expected_status': 400
            },
            {
                'name': 'Malformed JSON',
                'endpoint': '/analyze_behavioral',
                'data': 'invalid-json',
                'expected_status': 400
            }
        ]
        
        for test in error_tests:
            try:
                if isinstance(test['data'], dict):
                    response = requests.post(
                        f"{BASE_URL}{test['endpoint']}",
                        json=test['data'],
                        timeout=5
                    )
                else:
                    response = requests.post(
                        f"{BASE_URL}{test['endpoint']}",
                        data=test['data'],
                        timeout=5
                    )
                
                if response.status_code == test['expected_status']:
                    self.log(f"   ✅ {test['name']}: Correct error handling")
                    result = {'test': test['name'], 'status': 'passed'}
                else:
                    self.log(f"   ❌ {test['name']}: Expected {test['expected_status']}, got {response.status_code}", 'ERROR')
                    result = {'test': test['name'], 'status': 'failed'}
                
                self.results['error_tests'].append(result)
                
            except Exception as e:
                self.log(f"   ❌ {test['name']}: Exception - {e}", 'ERROR')
                result = {'test': test['name'], 'status': 'error', 'error': str(e)}
                self.results['error_tests'].append(result)
    
    def test_integration_workflow(self):
        """Test the complete integration workflow"""
        self.log("Testing integration workflow...")
        
        test_url = 'https://httpbin.org/html'
        workflow_results = {}
        
        # Step 1: ANN Analysis (hover simulation)
        try:
            self.log("   Step 1: ANN Analysis (hover simulation)")
            ann_response = requests.post(f"{BASE_URL}/check", json={'url': test_url}, timeout=10)
            
            if ann_response.status_code == 200:
                ann_data = ann_response.json()
                workflow_results['ann'] = {
                    'success': True,
                    'prediction': ann_data.get('prediction'),
                    'probability': ann_data.get('probability')
                }
                self.log(f"      ✅ ANN: {ann_data.get('prediction')} ({ann_data.get('probability', 0):.2f})")
            else:
                workflow_results['ann'] = {'success': False, 'error': f"HTTP {ann_response.status_code}"}
                self.log(f"      ❌ ANN failed: HTTP {ann_response.status_code}", 'ERROR')
        
        except Exception as e:
            workflow_results['ann'] = {'success': False, 'error': str(e)}
            self.log(f"      ❌ ANN error: {e}", 'ERROR')
        
        # Step 2: LSTM Behavioral Analysis (click simulation)
        try:
            self.log("   Step 2: LSTM Behavioral Analysis (click simulation)")
            lstm_response = requests.post(f"{BASE_URL}/analyze_behavioral", json={'url': test_url}, timeout=30)
            
            if lstm_response.status_code == 200:
                lstm_data = lstm_response.json()
                workflow_results['lstm'] = {
                    'success': True,
                    'prediction': lstm_data.get('prediction'),
                    'probability': lstm_data.get('probability'),
                    'recommendation': lstm_data.get('recommendation'),
                    'model_used': lstm_data.get('model_used')
                }
                self.log(f"      ✅ LSTM: {lstm_data.get('prediction')} ({lstm_data.get('probability', 0):.2f})")
                self.log(f"         Recommendation: {lstm_data.get('recommendation')}")
            else:
                workflow_results['lstm'] = {'success': False, 'error': f"HTTP {lstm_response.status_code}"}
                self.log(f"      ❌ LSTM failed: HTTP {lstm_response.status_code}", 'ERROR')
        
        except Exception as e:
            workflow_results['lstm'] = {'success': False, 'error': str(e)}
            self.log(f"      ❌ LSTM error: {e}", 'ERROR')
        
        # Step 3: Integration Analysis
        integration_success = workflow_results.get('ann', {}).get('success', False) and \
                             workflow_results.get('lstm', {}).get('success', False)
        
        if integration_success:
            self.log("   ✅ Integration workflow completed successfully")
        else:
            self.log("   ❌ Integration workflow failed", 'ERROR')
        
        workflow_results['integration_success'] = integration_success
        self.results['integration_tests'].append(workflow_results)
        
        return workflow_results
    
    def generate_report(self):
        """Generate comprehensive test report"""
        total_time = time.time() - self.start_time
        
        self.log("=" * 60)
        self.log("SCAMIFY LSTM INTEGRATION TEST REPORT")
        self.log("=" * 60)
        
        # Summary Statistics
        total_tests = (len(self.results['ann_tests']) + 
                      len(self.results['lstm_tests']) + 
                      len(self.results['integration_tests']) + 
                      len(self.results['error_tests']))
        
        self.log(f"Total Test Duration: {total_time:.1f} seconds")
        self.log(f"Total Tests Executed: {total_tests}")
        
        # ANN Test Results
        if self.results['ann_tests']:
            ann_success = len([t for t in self.results['ann_tests'] if t.get('status') == 'success'])
            ann_avg_time = sum([t.get('response_time', 0) for t in self.results['ann_tests']]) / len(self.results['ann_tests'])
            
            self.log(f"\n🧠 ANN Model Tests:")
            self.log(f"   Success Rate: {ann_success}/{len(self.results['ann_tests'])} ({ann_success/len(self.results['ann_tests'])*100:.1f}%)")
            self.log(f"   Average Response Time: {ann_avg_time:.3f}s")
        
        # LSTM Test Results
        if self.results['lstm_tests']:
            lstm_success = len([t for t in self.results['lstm_tests'] if t.get('status') == 'success'])
            lstm_avg_time = sum([t.get('response_time', 0) for t in self.results['lstm_tests']]) / len(self.results['lstm_tests'])
            
            self.log(f"\n🔬 LSTM Model Tests:")
            self.log(f"   Success Rate: {lstm_success}/{len(self.results['lstm_tests'])} ({lstm_success/len(self.results['lstm_tests'])*100:.1f}%)")
            self.log(f"   Average Response Time: {lstm_avg_time:.1f}s")
            
            # Model usage breakdown
            models_used = [t.get('model_used', 'unknown') for t in self.results['lstm_tests'] if t.get('status') == 'success']
            model_counts = {}
            for model in models_used:
                model_counts[model] = model_counts.get(model, 0) + 1
            
            self.log(f"   Models Used: {dict(model_counts)}")
        
        # Integration Test Results
        if self.results['integration_tests']:
            integration_success = len([t for t in self.results['integration_tests'] if t.get('integration_success')])
            self.log(f"\n🔗 Integration Tests:")
            self.log(f"   Success Rate: {integration_success}/{len(self.results['integration_tests'])} ({integration_success/len(self.results['integration_tests'])*100:.1f}%)")
        
        # Error Handling Results
        if self.results['error_tests']:
            error_success = len([t for t in self.results['error_tests'] if t.get('status') == 'passed'])
            self.log(f"\n🛡️ Error Handling Tests:")
            self.log(f"   Success Rate: {error_success}/{len(self.results['error_tests'])} ({error_success/len(self.results['error_tests'])*100:.1f}%)")
        
        # Performance Results
        if self.results['performance_tests']:
            self.log(f"\n⚡ Performance Tests:")
            for perf in self.results['performance_tests']:
                self.log(f"   {perf['model'].upper()} Model:")
                self.log(f"     Average: {perf['average_time']:.3f}s")
                self.log(f"     Range: {perf['min_time']:.3f}s - {perf['max_time']:.3f}s")
                self.log(f"     Success Rate: {perf['success_rate']*100:.1f}%")
        
        # Recommendations
        self.log(f"\n📋 RECOMMENDATIONS:")
        
        if self.results['ann_tests']:
            avg_ann_time = sum([t.get('response_time', 0) for t in self.results['ann_tests']]) / len(self.results['ann_tests'])
            if avg_ann_time > 0.5:
                self.log(f"   ⚠️  ANN response time high ({avg_ann_time:.3f}s) - Consider optimization")
            else:
                self.log(f"   ✅ ANN response time excellent ({avg_ann_time:.3f}s)")
        
        if self.results['lstm_tests']:
            lstm_failures = len([t for t in self.results['lstm_tests'] if t.get('status') != 'success'])
            if lstm_failures > 0:
                self.log(f"   ⚠️  LSTM has {lstm_failures} failures - Check model and extractor setup")
            else:
                self.log(f"   ✅ LSTM model performing well")
        
        self.log("=" * 60)
        
        # Save detailed results to file
        report_file = f"scamify_test_report_{int(time.time())}.json"
        try:
            with open(report_file, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
            self.log(f"📄 Detailed results saved to: {report_file}")
        except Exception as e:
            self.log(f"❌ Could not save report file: {e}", 'ERROR')

def main():
    """Run comprehensive test suite"""
    tester = ScamifyTester()
    
    print("🧪 ScamiFy LSTM Integration Test Suite")
    print("=" * 50)
    
    # Step 1: Health Checks
    backend_healthy = tester.test_backend_health()
    if not backend_healthy:
        print("\n❌ Backend not healthy. Please start the backend service first:")
        print("   cd Extension/backend")
        print("   python app.py")
        return False
    
    lstm_healthy = tester.test_lstm_health()
    
    # Step 2: Model Tests
    tester.test_ann_model('legitimate')
    tester.test_ann_model('suspicious')
    
    if lstm_healthy:
        tester.test_lstm_model('test_sites')
    else:
        tester.log("Skipping LSTM tests - components not healthy", 'WARNING')
    
    # Step 3: Integration Tests
    tester.test_integration_workflow()
    
    # Step 4: Performance Tests
    tester.test_performance_benchmarks()
    
    # Step 5: Error Handling Tests
    tester.test_error_handling()
    
    # Step 6: Generate Report
    tester.generate_report()
    
    return True

if __name__ == "__main__":
    success = main()
    exit_code = 0 if success else 1
    sys.exit(exit_code)