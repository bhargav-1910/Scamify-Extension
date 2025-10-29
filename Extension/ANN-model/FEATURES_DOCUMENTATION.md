# Ultra-Enhanced Phishing URL Detection - Feature Documentation

## 🎯 Complete Feature List (53 Features)

This ultra-enhanced model uses **53 advanced features** without WHOIS lookups for optimal performance.

---

## 📋 Feature Categories

### **Category 1: Original Structural Features (18 features)**

These are the baseline URL structure features:

1. **url_length** - Total length of the URL
2. **num_dots** - Count of dots in URL
3. **num_hyphens** - Count of hyphens
4. **num_at_symbols** - Count of @ symbols (suspicious in URLs)
5. **has_https** - Binary: 1 if HTTPS, 0 if HTTP
6. **num_digits** - Count of numeric digits
7. **special_characters_count** - Count of special characters (!#$%&*+=?^_`{|}~)
8. **is_ip_in_url** - Binary: 1 if IP address detected
9. **num_subdomains** - Number of subdomains
10. **top_level_domain_length** - Length of TLD (.com = 3, .co.uk = 5)
11. **num_slashes** - Count of forward slashes
12. **num_underscores** - Count of underscores
13. **num_question_marks** - Count of question marks
14. **num_equals** - Count of equal signs
15. **suspicious_keywords_count** - Count of phishing keywords (login, verify, secure, etc.)
16. **domain_length** - Length of domain name
17. **path_length** - Length of URL path
18. **has_port** - Binary: 1 if non-standard port specified

---

### **Category 2: Character-Level Analysis (7 features)**

Advanced character pattern detection:

19. **min_domain_distance** - Minimum Levenshtein distance to 133 known legitimate domains
    - Range: 0.0 (exact match) to 1.0 (completely different)
    - **Key for typosquatting detection**

20. **is_suspicious_similarity** - Binary: 1 if distance < 0.3 (very similar to known domain)
    - Flags `g00gle.com` (distance 0.200), `paypa1.com` (distance 0.100)

21. **leet_speak_count** - Count of leet speak substitutions
    - Detects: 0→o, 1→l, 3→e, 4→a, 5→s, 7→t, 8→b, @→a, $→s
    - Examples: `faceb00k` (2), `paypa1` (1), `g00gle` (2)

22. **max_consecutive_consonants** - Longest sequence of consonants
    - Helps identify unpronounceable/suspicious domains

23. **vowel_to_consonant_ratio** - Ratio of vowels to consonants
    - Normal English words: ~0.4-0.6
    - Random strings: often abnormal ratios

24. **digit_to_letter_ratio** - Ratio of digits to letters in domain
    - High ratio suggests suspicious patterns

25. **domain_entropy** - Shannon entropy of domain name
    - Higher entropy = more random/suspicious
    - Regular words: lower entropy

---

### **Category 3: Unicode/Homograph Detection (3 features)**

Detects internationalized domain name attacks:

26. **has_unicode** - Binary: 1 if non-ASCII characters present
    - Detects: `аpple.com` (Cyrillic а)

27. **has_cyrillic** - Binary: 1 if Cyrillic script detected
    - Critical for homograph attack detection

28. **has_mixed_scripts** - Binary: 1 if multiple character scripts mixed
    - Detects: Latin + Cyrillic combinations (homograph attacks)

---

### **Category 4: Whitelist & Trust System (4 features)**

Expanded whitelist with 133+ legitimate domains:

29. **is_whitelisted** - Binary: 1 if domain is in whitelist
    - **133 trusted domains** including:
      - Tech: Google, Facebook, Microsoft, Apple, Amazon
      - Social: Twitter, Instagram, LinkedIn, Reddit, TikTok
      - Dev: GitHub, StackOverflow, npm, Docker
      - Education: MIT, Stanford, Harvard, Khan Academy, Coursera
      - AI/Modern: OpenAI, Anthropic, Hugging Face
      - Y Combinator: Airbnb, Stripe, Coinbase
      - **Full list in ultra_enhanced_features.py**

30. **allows_long_urls** - Binary: 1 if whitelisted (trusts long paths)
    - Prevents false positives on legitimate long URLs

31. **has_trusted_subdomain** - Binary: 1 if subdomain is explicitly trusted
    - **Trusted subdomains**:
      - Google: accounts, mail, drive, docs, scholar, maps, etc.
      - Microsoft: login, account, outlook, office, azure, etc.
      - Apple: support, icloud, appleid, developer, store
      - Amazon: aws, smile, music, prime, video
      - **Fixes false positive on accounts.google.com**

32. **is_url_shortener** - Binary: 1 if known URL shortener
    - Detects: bit.ly, t.co, tinyurl.com, goo.gl, ow.ly (15 services)

---

### **Category 5: TLD & Domain Patterns (2 features)**

33. **has_suspicious_tld** - Binary: 1 if TLD is commonly used for phishing
    - Suspicious TLDs: .tk, .ml, .ga, .cf, .gq, .xyz, .top, .work, .click, etc.

34. **is_educational** - Binary: 1 if educational domain
    - TLDs: .edu, .ac.uk, .ac.jp, .edu.au, .edu.cn

---

### **Category 6: Domain Age & Trust (DISABLED for training) (3 features)**

**Note:** WHOIS lookups are **disabled during training** for performance. They can be **enabled for real-time testing**.

35. **domain_age_days** - Age of domain in days (via WHOIS)
    - Value: -1 (unknown/disabled), or actual days
    - New domains (<180 days) are higher phishing risk
    - **Disabled by default** to avoid slow WHOIS lookups

36. **is_new_domain** - Binary: 1 if domain < 6 months old
    - Based on domain_age_days

37. **is_very_new_domain** - Binary: 1 if domain < 1 month old
    - Based on domain_age_days

---

### **Category 7: SSL Certificate Validation (DISABLED for training) (2 features)**

**Note:** SSL checks are **disabled during training** for performance. They can be **enabled for real-time testing**.

38. **has_valid_ssl** - Binary: 1 if valid SSL certificate
    - Checks certificate validity and expiration
    - **Disabled by default** for training speed

39. **ssl_days_until_expiry** - Days until SSL certificate expires
    - Short expiry (<30 days) can be suspicious
    - **Disabled by default**

---

### **Category 8: Advanced Pattern Detection (6 features)**

40. **has_multiple_hyphens_in_domain** - Binary: 1 if >2 hyphens in domain
    - Phishing often uses: `secure-login-paypal-verify.com`

41. **has_excessive_subdomains** - Binary: 1 if >3 subdomains
    - Example: `paypal.com.login.verify.session.ru` (4 subdomains)

42. **url_entropy** - Shannon entropy of entire URL
    - Complements domain_entropy

43. **path_entropy** - Shannon entropy of URL path
    - Random paths have higher entropy

44. **has_ip_and_domain** - Binary: 1 if both IP and domain present
    - Suspicious combination

45. **has_port_and_ip** - Binary: 1 if IP address with non-standard port
    - Example: `192.168.1.1:8080/login`

---

### **Category 9: Path & Query Analysis (3 features)**

46. **path_to_domain_ratio** - Ratio of path length to domain length
    - Extremely long paths relative to domain can be suspicious

47. **query_length** - Length of query string
    - Very long query strings can indicate obfuscation

48. **num_parameters** - Number of URL parameters
    - Excessive parameters can be suspicious

---

### **Category 10: High-Risk Indicators (5 features)**

49. **has_at_symbol** - Binary: 1 if @ present (phishing technique)
    - Example: `https://google.com@evil.com` (goes to evil.com)

50. **is_government** - Binary: 1 if government domain
    - Domains ending in .gov or containing .gov.

51. **has_brand_keyword** - Count of brand keywords in domain
    - Keywords: paypal, google, facebook, amazon, microsoft, apple, bank, secure, login, account
    - Phishing impersonation indicator

52. **is_extremely_long** - Binary: 1 if URL > 150 characters
    - Excessively long URLs often phishing

53. **has_long_path** - Binary: 1 if path > 100 characters
    - Very long paths can indicate obfuscation

---

## 🎯 Feature Usage Strategy

### **Always Active (43 features)**
- All structural, character-level, Unicode, whitelist, TLD, and pattern features
- **No network calls required** - fast and reliable
- Perfect for training and batch processing

### **Optional for Real-Time Testing (10 features)**
- Domain age (3 features) - Enable with `enable_whois=True`
- SSL validation (2 features) - Enable with `enable_ssl_check=True`
- Use when testing individual URLs for maximum accuracy
- Too slow for bulk dataset generation

---

## 📊 Feature Importance by Category

### **Critical for Phishing Detection:**
1. ✅ **is_whitelisted** - Instant legitimate domain recognition
2. ✅ **has_trusted_subdomain** - Fixes false positives on accounts.google.com
3. ✅ **min_domain_distance** - Catches typosquatting (g00gle, paypa1)
4. ✅ **is_suspicious_similarity** - Flags near-matches
5. ✅ **leet_speak_count** - Detects character substitutions
6. ✅ **has_unicode** / **has_cyrillic** / **has_mixed_scripts** - Homograph attacks
7. ✅ **has_https** - Basic security indicator
8. ✅ **suspicious_keywords_count** - Keyword-based phishing
9. ✅ **num_subdomains** - Subdomain spoofing
10. ✅ **has_excessive_subdomains** - Advanced subdomain spoofing

### **Important Supporting Features:**
- url_length, domain_length, path_length
- num_dots, num_hyphens, num_at_symbols
- domain_entropy, url_entropy
- has_suspicious_tld
- is_url_shortener

### **Nice-to-Have Features:**
- vowel_to_consonant_ratio
- max_consecutive_consonants
- path_to_domain_ratio
- is_educational, is_government
- has_brand_keyword

---

## 🚀 Usage Examples

### **Training (Fast - No Network Calls):**
```python
from ultra_enhanced_features import extract_ultra_enhanced_features

# Default: WHOIS and SSL disabled for speed
features = extract_ultra_enhanced_features("https://example.com")
# Returns 53 features instantly
```

### **Real-Time Testing (Maximum Accuracy):**
```python
# Enable all features including WHOIS and SSL
features = extract_ultra_enhanced_features(
    "https://suspicious-site.com",
    enable_whois=True,        # Check domain age
    enable_ssl_check=True     # Validate SSL certificate
)
# Returns 53 features with network-based checks
```

---

## 📈 Improvements Over Previous Versions

| Feature | Baseline (18) | Enhanced (35) | Ultra-Enhanced (53) |
|---------|--------------|---------------|---------------------|
| **Whitelist Size** | 40 domains | 40 domains | **133 domains** ✅ |
| **Trusted Subdomains** | ❌ No | ❌ No | ✅ **Yes** (fixes accounts.google.com) |
| **Domain Age** | ❌ No | ❌ No | ✅ **Optional** (WHOIS) |
| **SSL Validation** | ❌ No | ❌ No | ✅ **Optional** |
| **Character Entropy** | ❌ No | ✅ Domain only | ✅ **URL + Path** |
| **Brand Keywords** | ❌ No | ❌ No | ✅ **Yes** |
| **Government/Edu** | ❌ No | ❌ No | ✅ **Yes** |
| **Pattern Detection** | Basic | Advanced | **Ultra-Advanced** ✅ |

---

## 💡 Key Advantages

1. **No WHOIS Required for Training** ✅
   - WHOIS lookups disabled by default
   - Fast dataset generation (no network delays)
   - Optional for real-time testing only

2. **Expanded Whitelist (133+ domains)** ✅
   - Covers: Tech giants, social media, dev tools, education, AI companies
   - Includes: OpenAI, YCombinator, Khan Academy (fixes previous false positives)

3. **Trusted Subdomain System** ✅
   - Prevents false positives on `accounts.google.com`, `login.microsoft.com`
   - Explicit trust for common subdomains of major platforms

4. **Comprehensive Coverage** ✅
   - 53 features covering all phishing attack vectors
   - Character-level, structural, semantic, and behavioral analysis

5. **Production Ready** ✅
   - Fast enough for training (no slow network calls)
   - Accurate enough for deployment (optional WHOIS/SSL for max accuracy)

---

## 🎓 When to Enable Optional Features

### **Enable WHOIS (domain_age_days) when:**
- Testing individual suspicious URLs
- Real-time phishing detection
- Investigating new/unknown domains
- **Don't enable** during training (too slow)

### **Enable SSL Check (has_valid_ssl) when:**
- Validating HTTPS sites
- Corporate security scans
- Detailed threat analysis
- **Don't enable** during training (network calls)

---

**Total Features: 53**  
**Network Calls Required: 0 (training mode)**  
**Network Calls Optional: 2 (WHOIS + SSL for real-time testing)**  
**Performance: Optimized for both training and deployment** ✅
