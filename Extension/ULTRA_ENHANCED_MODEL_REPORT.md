# Ultra-Enhanced Phishing URL Detection — Detailed Report

Generated from the code and documentation in this workspace.

## Executive summary

This project implements an "ultra-enhanced" feature extractor and prediction wrapper for classifying URLs as Legitimate or Phishing. The pipeline computes 53 features that capture structural, character-level, script/homograph, whitelist/trust, TLD/domain-pattern, and advanced pattern signals. WHOIS (domain age) and SSL checks are available as optional network-backed features for real-time testing but are disabled by default for fast training and batch processing.

A trained Keras ANN (`ann_model_ultra_enhanced.h5`) and a saved scaler (`scaler_ultra_enhanced.pkl`) consume the ordered feature vector (returned by `get_ultra_feature_names()`) to produce a probability that the URL is legitimate. Deterministic guardrails (trusted subdomain and whitelist overrides) reduce false positives on well-known services.

## Contract (inputs, outputs, errors)

- Input: a URL string (e.g., `https://accounts.google.com/path?x=1`).
- Optional flags:
  - `enable_whois: bool` (default False) — if True, uses `python-whois` to fetch the domain creation date.
  - `enable_ssl_check: bool` (default False) — if True, attempts an SSL handshake to validate the certificate.
- Output (wrapper `predict` returns a dict):
  - `url`: original URL string
  - `probability_legitimate`: float in [0,1]
  - `prediction_label`: int (1 = Legitimate, 0 = Phishing)
  - `prediction`: string label
  - `confidence`: float (confidence in predicted label)
  - `override`: None or override reason (`trusted_subdomain` or `whitelist_override`)
  - `features`: a subset of key feature flags used for explanation
- Error modes: malformed URLs are parsed into safe defaults (empty hostname/path). WHOIS or SSL failures set sentinel values (domain_age_days = -1, has_valid_ssl = False) — these do not raise exceptions.

## Feature set (ordered)

The model expects the features in the exact order returned by `get_ultra_feature_names()`.

1. url_length
2. num_dots
3. num_hyphens
4. num_at_symbols
5. has_https
6. num_digits
7. special_characters_count
8. is_ip_in_url
9. num_subdomains
10. top_level_domain_length
11. num_slashes
12. num_underscores
13. num_question_marks
14. num_equals
15. suspicious_keywords_count
16. domain_length
17. path_length
18. has_port
19. min_domain_distance
20. is_suspicious_similarity
21. is_whitelisted
22. allows_long_urls
23. has_unicode
24. has_cyrillic
25. has_mixed_scripts
26. leet_speak_count
27. is_url_shortener
28. domain_entropy
29. digit_to_letter_ratio
30. has_suspicious_tld
31. path_to_domain_ratio
32. query_length
33. num_parameters
34. max_consecutive_consonants
35. vowel_to_consonant_ratio
36. has_trusted_subdomain
37. domain_age_days
38. is_new_domain
39. is_very_new_domain
40. has_valid_ssl
41. ssl_days_until_expiry
42. has_multiple_hyphens_in_domain
43. has_excessive_subdomains
44. url_entropy
45. path_entropy
46. has_ip_and_domain
47. has_port_and_ip
48. has_at_symbol
49. is_educational
50. is_government
51. has_brand_keyword
52. is_extremely_long
53. has_long_path

> Note: The feature ordering and exact names must match the scaler that was used during training. A mismatch will produce invalid predictions.

## Categories and short descriptions

- Structural (18 features): length, counts (dots, hyphens, slashes, digits, underscores), presence of IP, port, path length, query length.
- Character-level & similarity (17 features): Levenshtein distance to known legit domains (`min_domain_distance`), `is_suspicious_similarity` threshold, leet-speak count, entropy measures, vowel/consonant ratios, digit/letter ratio.
- Unicode/homograph (3 features): `has_unicode`, `has_cyrillic`, `has_mixed_scripts`.
- Whitelist & trust (4 features): `is_whitelisted`, `allows_long_urls`, `has_trusted_subdomain`, `is_url_shortener` detection.
- TLD & domain patterns (2 features): `has_suspicious_tld`, `is_educational`.
- Optional network-backed (5 features): WHOIS-derived `domain_age_days`, `is_new_domain`, `is_very_new_domain`, and SSL `has_valid_ssl`, `ssl_days_until_expiry`.
- Advanced patterns & high-risk indicators: entropy of URL/path, excessive subdomains, multiple hyphens, brand keywords, '@' usage, IP+domain combos, extremely long URLs.

## Feature calculation highlights & helper functions

- Levenshtein distance (`levenshtein_distance`) computes normalized edit distance between the domain and each known legitimate domain and returns the minimum normalized distance (`min_domain_distance`).
  - `is_suspicious_similarity` = 1 if `min_domain_distance < 0.3`.
- Whitelist membership (`is_domain_whitelisted`) checks `KNOWN_LEGITIMATE_DOMAINS` and `TRUSTED_SUBDOMAINS`, educational and government TLD heuristics.
- `detect_leet_speak` counts common leet substitutions (0→o, 1→l, 3→e, 4→a, 5→s, 7→t, 8→b, @→a, $→s).
- Entropy measures use Shannon entropy (`calculate_entropy`) to detect randomness in domain, path, and entire URL.
- Domain age uses `python-whois` (when available and enabled). If WHOIS is not installed or disabled, `domain_age_days = -1`.
- SSL validation performs a TLS handshake to retrieve certificate `notAfter` and computes `ssl_days_until_expiry`.

## Procedure: Full prediction flow

1. Parse URL via `urllib.parse.urlparse` and extract `hostname`, `path`, `query`, `port`, `scheme`.
2. Compute all 53 features in `extract_ultra_enhanced_features(url, enable_whois=False, enable_ssl_check=False)`.
3. Get ordered feature names via `get_ultra_feature_names()` and build a feature vector in that order.
4. Convert to numpy array `dtype=float32` and scale with `scaler.transform()` (loaded via joblib in `UltraEnhancedDetector`).
5. Feed scaled vector to the ANN model (`model.predict(...)[0][0]`) to obtain `probability_legitimate`.
6. Compute `prediction_label` with threshold 0.5.
7. Apply deterministic guardrails (override to Legitimate):
   - If `has_trusted_subdomain` is True: force Legitimate and set `probability_legitimate = max(probability_legitimate, 0.995)`.
   - Else if `is_whitelisted` and (not `is_suspicious_similarity` or `min_domain_distance <= 0.05`): force Legitimate and set `probability_legitimate = max(probability_legitimate, 0.99)`.
8. Return JSON-friendly result including a compact `features` subset for quick explanation.

## Important thresholds & constants

- Model decision threshold: 0.5 (probability ≥ 0.5 → Legitimate).
- Typosquat threshold: `is_suspicious_similarity` if `min_domain_distance < 0.3`.
- Strong whitelist tolerance: `min_domain_distance <= 0.05` will still allow a whitelist override.
- Trusted subdomain override sets a floor at 0.995 probability.
- Whitelist override sets a floor at 0.99 probability.
- New domain: `domain_age_days < 180` (is_new_domain).
- Very new domain: `domain_age_days < 30` (is_very_new_domain).
- Excessive subdomains: `num_subdomains > 3`.
- Multiple hyphens in domain: `domain.count('-') > 2`.
- Extremely long URL: `len(url) > 150`.
- Long path: `len(path) > 100`.

## Runtime & operational notes

- Training / bulk feature extraction: set `enable_whois=False` and `enable_ssl_check=False` (default). All required features remain available (43 network-free features).
- Real-time, per-URL testing: enabling WHOIS and SSL checks can improve accuracy at the cost of network latency and potential failures.
- The code detects if `whois` and `requests` are installed at import time. Missing optional libraries are warned about and the features gracefully fall back.
- Ensure the loaded scaler and the model were trained using the same feature order and preprocessing; otherwise predictions will be invalid.

## Sample usage

Programmatic:

```python
from test_ultra_enhanced_model import UltraEnhancedDetector

detector = UltraEnhancedDetector()
result = detector.predict("https://accounts.google.com")
print(result)
```

CLI (interactive):

```powershell
python predict_ultra_enhanced.py "https://example.com" --whois --ssl
```

## Reproducibility checklist

1. Confirm `ann_model_ultra_enhanced.h5` and `scaler_ultra_enhanced.pkl` are present in the project root.
2. Use Python environment with required packages:
   - `tensorflow`, `numpy`, `joblib` are required for inference.
   - Optional: `python-whois` and `requests` for WHOIS/SSL features.
3. Validate feature length:
   - Run a small script to call `get_ultra_feature_names()` and assert `len(...) == 53` and that the scaler's expected input shape matches.
4. Run `test_ultra_enhanced_model.evaluate_custom_urls()` to validate the curated suite and produce `custom_url_test_results_ultra.json`.

## Suggested small improvements (low-risk)

- Add a runtime check when loading the scaler: verify `scaler.n_features_in_ == len(get_ultra_feature_names())` and raise a clear error if mismatched.
- Add unit tests for `ultra_enhanced_features.extract_ultra_enhanced_features`:
  - assert the returned dict contains all names from `get_ultra_feature_names()` and length 53.
  - test known URLs for expected flags (whitelist, typosquat, unicode homograph).
- Add `requirements.txt` listing minimal packages used for inference and an optional section for WHOIS/SSL.
- Cache WHOIS and SSL results for repeated real-time checks to reduce latency and external load.
- Export a CSV mapping feature names to human-friendly descriptions for documentation and compliance audits.

## Quick "try it" commands (PowerShell)

```powershell
# start an interactive check
python predict_ultra_enhanced.py "https://accounts.google.com"

# run the test suite (inference + curated urls)
python test_ultra_enhanced_model.py
```

## Closing summary

This report documents the full feature set, exact ordering, extraction logic, thresholds, and prediction flow used by the ultra-enhanced phishing URL detector in this repository. The feature extractor emphasizes a no-network training mode with optional WHOIS/SSL checks for high-accuracy real-time testing. Deterministic whitelist and trusted-subdomain rules are applied to avoid false positives on major legitimate services.

---

If you want, I can also:
- Add `requirements.txt` and a small unit test that asserts feature-order and vector length.
- Add the CSV mapping features -> descriptions into the repo.
- Run a quick local test to validate the model/scaler load (if you want me to run it here).
