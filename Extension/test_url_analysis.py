"""
Comprehensive URL Analysis Tester
Tests Ultra-Enhanced ANN model and shows which features impact the prediction
"""

import sys
import os
from typing import Dict, List, Tuple
from datetime import datetime

# Add paths
backend_path = os.path.join(os.path.dirname(__file__), 'backend')
ann_model_path = os.path.join(os.path.dirname(__file__), 'ANN-model')
sys.path.insert(0, backend_path)
sys.path.insert(0, ann_model_path)

# Import Ultra-Enhanced predictor - Use the exact model from backend
try:
    from backend.models.ultra_ann_predictor import get_ultra_predictor, predict_url_ultra_detailed
    from ultra_enhanced_features import extract_ultra_enhanced_features, get_ultra_feature_names
    print("✅ Successfully imported Ultra-Enhanced ANN model")
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("   Make sure backend/models/ultra_ann_predictor.py exists")
    print("   and ANN-model/ultra_enhanced_features.py exists")
    sys.exit(1)

# Colors for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_header(text: str):
    """Print formatted header"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{text:^80}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*80}{Colors.END}\n")

def print_subheader(text: str):
    """Print formatted subheader"""
    print(f"\n{Colors.CYAN}{Colors.BOLD}{text}{Colors.END}")
    print(f"{Colors.CYAN}{'-'*80}{Colors.END}")

def print_result(label: str, value: str, color: str = Colors.END):
    """Print formatted result"""
    print(f"   {Colors.BOLD}{label:.<30}{Colors.END} {color}{value}{Colors.END}")

def analyze_url_detailed(url: str) -> Dict:
    """Analyze URL and show detailed feature breakdown"""
    
    print_header(f"ANALYZING: {url}")
    
    # Get predictor
    predictor = get_ultra_predictor()
    
    if not predictor.model_loaded:
        print(f"{Colors.RED}❌ Ultra-Enhanced ANN model not loaded!{Colors.END}")
        return None
    
    # Get prediction
    result = predict_url_ultra_detailed(url)
    
    # Get raw features
    features = extract_ultra_enhanced_features(url)
    feature_names = get_ultra_feature_names()
    
    # === PREDICTION RESULT ===
    print_subheader("🎯 PREDICTION RESULT")
    
    prediction_color = Colors.GREEN if result['prediction'] == 'Safe' else Colors.RED if result['prediction'] == 'Phishing' else Colors.YELLOW
    print_result("Prediction", result['prediction'], prediction_color)
    print_result("Probability", f"{result['probability']:.2%}", prediction_color)
    print_result("Confidence", f"{result['confidence']:.2%}", prediction_color)
    print_result("Model", result['model'], Colors.CYAN)
    
    # === KEY FEATURES ===
    print_subheader("🔍 KEY SECURITY FEATURES")
    
    # Whitelist status
    if features.get('is_whitelisted', 0) == 1:
        print_result("Whitelist Status", "✅ WHITELISTED (Trusted Domain)", Colors.GREEN)
    else:
        print_result("Whitelist Status", "❌ Not whitelisted", Colors.YELLOW)
    
    if features.get('has_trusted_subdomain', 0) == 1:
        print_result("Subdomain Trust", "✅ TRUSTED SUBDOMAIN", Colors.GREEN)
    else:
        print_result("Subdomain Trust", "❌ Not in trusted list", Colors.YELLOW)
    
    # HTTPS
    if features.get('has_https', 0) == 1:
        print_result("HTTPS", "✅ Secure (HTTPS)", Colors.GREEN)
    else:
        print_result("HTTPS", "❌ Insecure (HTTP)", Colors.RED)
    
    # Typosquatting
    min_distance = features.get('min_domain_distance', 1.0)
    if features.get('is_suspicious_similarity', 0) == 1:
        print_result("Typosquatting", f"🚨 DETECTED (distance: {min_distance:.3f})", Colors.RED)
    else:
        print_result("Typosquatting", f"✅ Clean (distance: {min_distance:.3f})", Colors.GREEN)
    
    # Leet speak
    leet_count = features.get('leet_speak_count', 0)
    if leet_count > 0:
        print_result("Leet Speak", f"🚨 DETECTED ({leet_count} substitutions)", Colors.RED)
    else:
        print_result("Leet Speak", "✅ None detected", Colors.GREEN)
    
    # Unicode/Homograph
    if features.get('has_unicode', 0) == 1:
        print_result("Unicode", "⚠️ Contains non-ASCII", Colors.YELLOW)
    else:
        print_result("Unicode", "✅ ASCII only", Colors.GREEN)
    
    if features.get('has_cyrillic', 0) == 1:
        print_result("Cyrillic", "🚨 CYRILLIC DETECTED", Colors.RED)
    else:
        print_result("Cyrillic", "✅ No Cyrillic", Colors.GREEN)
    
    if features.get('has_mixed_scripts', 0) == 1:
        print_result("Mixed Scripts", "🚨 HOMOGRAPH ATTACK", Colors.RED)
    else:
        print_result("Mixed Scripts", "✅ Single script", Colors.GREEN)
    
    # === URL CHARACTERISTICS ===
    print_subheader("📐 URL CHARACTERISTICS")
    
    print_result("URL Length", f"{features.get('url_length', 0)} chars", Colors.END)
    print_result("Domain Length", f"{features.get('domain_length', 0)} chars", Colors.END)
    print_result("Path Length", f"{features.get('path_length', 0)} chars", Colors.END)
    print_result("Subdomains", str(features.get('num_subdomains', 0)), Colors.END)
    print_result("Dots", str(features.get('num_dots', 0)), Colors.END)
    print_result("Hyphens", str(features.get('num_hyphens', 0)), Colors.END)
    print_result("Digits", str(features.get('num_digits', 0)), Colors.END)
    print_result("Special Chars", str(features.get('special_characters_count', 0)), Colors.END)
    
    # === ENTROPY ANALYSIS ===
    print_subheader("🔬 ENTROPY & COMPLEXITY")
    
    url_entropy = features.get('url_entropy', 0)
    domain_entropy = features.get('domain_entropy', 0)
    path_entropy = features.get('path_entropy', 0)
    
    print_result("URL Entropy", f"{url_entropy:.3f} {'⚠️ High' if url_entropy > 4.5 else '✅ Normal'}", 
                Colors.YELLOW if url_entropy > 4.5 else Colors.GREEN)
    print_result("Domain Entropy", f"{domain_entropy:.3f} {'⚠️ High' if domain_entropy > 3.5 else '✅ Normal'}", 
                Colors.YELLOW if domain_entropy > 3.5 else Colors.GREEN)
    print_result("Path Entropy", f"{path_entropy:.3f}", Colors.END)
    
    # === SUSPICIOUS PATTERNS ===
    print_subheader("⚠️  SUSPICIOUS PATTERNS")
    
    suspicious_found = False
    
    if features.get('is_ip_in_url', 0) == 1:
        print_result("IP Address", "🚨 DETECTED", Colors.RED)
        suspicious_found = True
    
    if features.get('has_at_symbol', 0) == 1:
        print_result("@ Symbol", "🚨 DETECTED", Colors.RED)
        suspicious_found = True
    
    if features.get('is_url_shortener', 0) == 1:
        print_result("URL Shortener", "⚠️ DETECTED", Colors.YELLOW)
        suspicious_found = True
    
    if features.get('has_suspicious_tld', 0) == 1:
        print_result("Suspicious TLD", "⚠️ DETECTED (.tk, .ml, etc.)", Colors.YELLOW)
        suspicious_found = True
    
    if features.get('suspicious_keywords_count', 0) > 0:
        print_result("Suspicious Keywords", f"⚠️ {features['suspicious_keywords_count']} found", Colors.YELLOW)
        suspicious_found = True
    
    if features.get('has_brand_keyword', 0) > 0:
        print_result("Brand Keywords", f"⚠️ {features['has_brand_keyword']} found", Colors.YELLOW)
        suspicious_found = True
    
    if not suspicious_found:
        print_result("Status", "✅ No suspicious patterns", Colors.GREEN)
    
    # === TRUST INDICATORS ===
    print_subheader("✅ TRUST INDICATORS")
    
    trust_found = False
    
    if features.get('is_educational', 0) == 1:
        print_result("Educational", "✅ .edu domain", Colors.GREEN)
        trust_found = True
    
    if features.get('is_government', 0) == 1:
        print_result("Government", "✅ .gov domain", Colors.GREEN)
        trust_found = True
    
    if not trust_found and not features.get('is_whitelisted', 0):
        print_result("Status", "ℹ️  No special trust indicators", Colors.END)
    
    # === TOP RISK FACTORS ===
    print_subheader("🎯 TOP RISK FACTORS")
    
    risk_factors = []
    
    # Calculate risk contributions
    if features.get('is_suspicious_similarity', 0) == 1:
        risk_factors.append(("Typosquatting Detection", 0.9, Colors.RED))
    
    if features.get('has_cyrillic', 0) == 1:
        risk_factors.append(("Cyrillic Characters", 0.85, Colors.RED))
    
    if features.get('has_mixed_scripts', 0) == 1:
        risk_factors.append(("Mixed Character Scripts", 0.85, Colors.RED))
    
    if features.get('leet_speak_count', 0) > 0:
        risk_factors.append((f"Leet Speak ({features['leet_speak_count']} subs)", 0.7, Colors.RED))
    
    if features.get('is_ip_in_url', 0) == 1:
        risk_factors.append(("IP Address in URL", 0.7, Colors.RED))
    
    if features.get('has_https', 0) == 0:
        risk_factors.append(("No HTTPS", 0.3, Colors.YELLOW))
    
    if features.get('url_length', 0) > 150:
        risk_factors.append((f"Very Long URL ({features['url_length']} chars)", 0.3, Colors.YELLOW))
    
    if features.get('num_subdomains', 0) > 3:
        risk_factors.append((f"Many Subdomains ({features['num_subdomains']})", 0.3, Colors.YELLOW))
    
    if domain_entropy > 4.0:
        risk_factors.append((f"High Domain Entropy ({domain_entropy:.2f})", 0.3, Colors.YELLOW))
    
    # Sort by risk score
    risk_factors.sort(key=lambda x: x[1], reverse=True)
    
    if risk_factors:
        for i, (factor, score, color) in enumerate(risk_factors[:5], 1):
            print(f"   {i}. {color}{factor:.<50} Risk: {score:.0%}{Colors.END}")
    else:
        print_result("Status", "✅ No significant risk factors", Colors.GREEN)
    
    # === FEATURE SUMMARY ===
    print_subheader("📊 FEATURE SUMMARY (All 53 Features)")
    
    # Group features by category
    categories = {
        "Structural (18)": [
            'url_length', 'num_dots', 'num_hyphens', 'num_at_symbols', 'has_https',
            'num_digits', 'special_characters_count', 'is_ip_in_url', 'num_subdomains',
            'top_level_domain_length', 'num_slashes', 'num_underscores', 'num_question_marks',
            'num_equals', 'suspicious_keywords_count', 'domain_length', 'path_length', 'has_port'
        ],
        "Character Analysis (7)": [
            'min_domain_distance', 'is_suspicious_similarity', 'leet_speak_count',
            'max_consecutive_consonants', 'vowel_to_consonant_ratio', 'digit_to_letter_ratio',
            'domain_entropy'
        ],
        "Security (3)": [
            'has_unicode', 'has_cyrillic', 'has_mixed_scripts'
        ],
        "Trust System (4)": [
            'is_whitelisted', 'has_trusted_subdomain', 'allows_long_urls', 'is_educational'
        ],
        "Advanced (21)": [
            'is_url_shortener', 'has_suspicious_tld', 'path_to_domain_ratio',
            'query_length', 'num_parameters', 'domain_age_days', 'is_new_domain',
            'is_very_new_domain', 'has_valid_ssl', 'ssl_days_until_expiry',
            'has_multiple_hyphens_in_domain', 'has_excessive_subdomains', 'url_entropy',
            'path_entropy', 'has_ip_and_domain', 'has_port_and_ip', 'has_at_symbol',
            'is_government', 'has_brand_keyword', 'is_extremely_long', 'has_long_path'
        ]
    }
    
    for category, feature_list in categories.items():
        print(f"\n   {Colors.BOLD}{category}{Colors.END}")
        for feature in feature_list:
            if feature in features:
                value = features[feature]
                # Format value based on type
                if isinstance(value, float):
                    if value < 0.01:
                        formatted_value = f"{value:.4f}"
                    elif value < 1:
                        formatted_value = f"{value:.3f}"
                    else:
                        formatted_value = f"{value:.2f}"
                else:
                    formatted_value = str(value)
                
                # Highlight non-zero/suspicious values
                if value > 0 and feature in ['is_suspicious_similarity', 'leet_speak_count', 'has_unicode', 
                                              'has_cyrillic', 'has_mixed_scripts', 'is_url_shortener',
                                              'has_suspicious_tld', 'is_ip_in_url', 'has_at_symbol']:
                    print(f"      {Colors.YELLOW}{feature:.<40}{formatted_value:>10}{Colors.END}")
                else:
                    print(f"      {feature:.<40}{formatted_value:>10}")
    
    print("\n")
    return result


def run_test_suite():
    """Run comprehensive test suite"""
    
    print_header("ULTRA-ENHANCED ANN - URL ANALYSIS TEST SUITE")
    
    test_urls = [
        # Safe URLs
        ("https://www.google.com", "Safe - Major Search Engine"),
        ("https://mail.google.com", "Safe - Trusted Subdomain"),
        ("https://github.com", "Safe - Developer Platform"),
        ("https://www.microsoft.com", "Safe - Tech Giant"),
        ("https://www.stanford.edu", "Safe - Educational"),
        
        # Phishing URLs - Typosquatting
        ("http://g00gle.com", "Phishing - Leet Speak Typosquatting"),
        ("http://paypa1.com", "Phishing - Leet Speak"),
        ("http://faceb00k.com", "Phishing - Leet Speak"),
        
        # Phishing URLs - Homograph
        ("https://аpple.com", "Phishing - Cyrillic Homograph"),
        
        # Phishing URLs - Subdomain Spoofing
        ("http://paypal.secure-login.xyz", "Phishing - Subdomain Spoofing"),
        ("http://login.paypal.verify-account.ru", "Phishing - Multi-level Spoofing"),
        
        # Suspicious URLs
        ("http://bit.ly/abc123", "Suspicious - URL Shortener"),
        ("http://192.168.1.1", "Suspicious - IP Address"),
        ("http://secure-login-verify-account-update.com", "Suspicious - Keyword Stuffing"),
    ]
    
    results = []
    
    for i, (url, description) in enumerate(test_urls, 1):
        print(f"\n{Colors.BOLD}Test {i}/{len(test_urls)}: {description}{Colors.END}")
        result = analyze_url_detailed(url)
        if result:
            results.append((url, description, result))
        
        if i < len(test_urls):
            input(f"\n{Colors.CYAN}Press Enter to continue to next test...{Colors.END}")
    
    # Summary
    print_header("TEST SUMMARY")
    
    print(f"\n{Colors.BOLD}Results Overview:{Colors.END}\n")
    for i, (url, desc, result) in enumerate(results, 1):
        prediction_color = Colors.GREEN if result['prediction'] == 'Safe' else Colors.RED if result['prediction'] == 'Phishing' else Colors.YELLOW
        print(f"{i:2}. {desc:.<50} {prediction_color}{result['prediction']:>15}{Colors.END} ({result['probability']:.1%})")
    
    print("\n")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Analyze URLs with Ultra-Enhanced ANN")
    parser.add_argument('url', nargs='?', help='URL to analyze')
    parser.add_argument('--suite', action='store_true', help='Run full test suite')
    
    args = parser.parse_args()
    
    try:
        if args.suite:
            run_test_suite()
        elif args.url:
            analyze_url_detailed(args.url)
        else:
            # Interactive mode
            print_header("ULTRA-ENHANCED ANN - INTERACTIVE URL ANALYZER")
            print(f"{Colors.CYAN}Enter a URL to analyze (or 'quit' to exit):{Colors.END}\n")
            
            while True:
                url = input(f"{Colors.BOLD}URL > {Colors.END}").strip()
                
                if url.lower() in ['quit', 'exit', 'q']:
                    print(f"\n{Colors.GREEN}Goodbye!{Colors.END}\n")
                    break
                
                if url.lower() == 'suite':
                    run_test_suite()
                    continue
                
                if url:
                    analyze_url_detailed(url)
                    print("\n")
    
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Interrupted by user{Colors.END}\n")
    except Exception as e:
        print(f"\n{Colors.RED}Error: {e}{Colors.END}\n")
        import traceback
        traceback.print_exc()
