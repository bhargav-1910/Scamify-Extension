"""Interactive CLI for predicting phishing vs legitimate URLs with the ultra-enhanced ANN."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from test_ultra_enhanced_model import UltraEnhancedDetector


def format_probability(probability: float) -> str:
    return f"{probability * 100:.2f}%"


def summarize_result(result: dict[str, Any]) -> str:
    lines = []
    lines.append(f"URL: {result['url']}")
    lines.append(f"Prediction: {result['prediction']} (confidence {format_probability(result['confidence'])})")
    lines.append(f"Probability URL is legitimate: {format_probability(result['probability_legitimate'])}")

    override = result.get("override")
    if override == "trusted_subdomain":
        lines.append("Override: Trusted subdomain detected (whitelisted)")
    elif override == "whitelist_override":
        lines.append("Override: Exact whitelist domain match")

    feature_flags = result.get("features", {})
    highlight = []
    if feature_flags.get("has_trusted_subdomain"):
        highlight.append("✓ trusted subdomain")
    if feature_flags.get("is_whitelisted"):
        highlight.append("✓ whitelisted domain")
    if feature_flags.get("is_suspicious_similarity"):
        highlight.append(
            f"⚠ typosquat similarity (distance={feature_flags.get('min_domain_distance', 0):.3f})"
        )
    if feature_flags.get("leet_speak_count", 0) > 0:
        highlight.append(f"⚠ leet speak substitutions ({feature_flags['leet_speak_count']})")
    if not feature_flags.get("has_https"):
        highlight.append("⚠ missing HTTPS")
    if feature_flags.get("num_subdomains", 0) > 3:
        highlight.append(f"⚠ many subdomains ({feature_flags['num_subdomains']})")

    if highlight:
        lines.append("Indicators: " + ", ".join(highlight))

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Predict whether a URL is phishing or legitimate using the ultra-enhanced ANN.",
    )
    parser.add_argument("url", nargs="?", help="URL to classify")
    parser.add_argument(
        "--whois",
        action="store_true",
        help="Enable WHOIS domain-age lookup (slower; requires network)",
    )
    parser.add_argument(
        "--ssl",
        action="store_true",
        help="Enable SSL certificate validation (slower; requires network)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output full JSON result instead of formatted text",
    )

    args = parser.parse_args()

    url = args.url
    if not url:
        try:
            url = input("Enter URL to classify: ").strip()
        except KeyboardInterrupt:
            print("\nCancelled.")
            sys.exit(1)

    if not url:
        print("No URL provided. Exiting.")
        sys.exit(1)

    detector = UltraEnhancedDetector()
    result = detector.predict(
        url,
        enable_whois=args.whois,
        enable_ssl_check=args.ssl,
    )

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("\n" + summarize_result(result))


if __name__ == "__main__":
    main()
