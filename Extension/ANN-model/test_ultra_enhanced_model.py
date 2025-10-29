"""Evaluate the ultra-enhanced ANN on curated URL scenarios and full datasets."""

from __future__ import annotations

import json
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
from tensorflow import keras

from ultra_enhanced_features import (
    extract_ultra_enhanced_features,
    get_ultra_feature_names,
)


class UltraEnhancedDetector:
    """Wrapper around the ultra-enhanced ANN for quick predictions."""

    def __init__(
        self,
        model_path: str = "ann_model_ultra_enhanced.h5",
        scaler_path: str = "scaler_ultra_enhanced.pkl",
    ) -> None:
        print("\n🔧 Loading ultra-enhanced ANN model...")
        self.model = keras.models.load_model(model_path, compile=False)
        self.scaler = joblib.load(scaler_path)
        self.feature_names = get_ultra_feature_names()
        print("✅ Ultra-enhanced model loaded successfully!")
        print(f"   Feature count: {len(self.feature_names)}")
        print("   WHOIS + SSL disabled during inference (matches training dataset)\n")

    def _extract_features(
        self,
        url: str,
        *,
        enable_whois: bool = False,
        enable_ssl_check: bool = False,
    ) -> tuple[np.ndarray, dict]:
        features_dict = extract_ultra_enhanced_features(
            url,
            enable_whois=enable_whois,
            enable_ssl_check=enable_ssl_check,
        )

        feature_vector = [features_dict.get(name, 0.0) for name in self.feature_names]
        features_array = np.array([feature_vector], dtype="float32")
        return features_array, features_dict

    def predict(
        self,
        url: str,
        *,
        enable_whois: bool = False,
        enable_ssl_check: bool = False,
    ) -> dict:
        features_array, features_dict = self._extract_features(
            url,
            enable_whois=enable_whois,
            enable_ssl_check=enable_ssl_check,
        )
        features_scaled = self.scaler.transform(features_array)

        prob_legitimate = float(self.model.predict(features_scaled, verbose=0)[0][0])
        predicted_label = 1 if prob_legitimate >= 0.5 else 0
        override_reason = None

        # Deterministic guard-rails for trusted domains/subdomains
        is_whitelisted = bool(features_dict.get("is_whitelisted", 0))
        has_trusted_subdomain = bool(features_dict.get("has_trusted_subdomain", 0))
        suspicious_similarity = bool(features_dict.get("is_suspicious_similarity", 0))
        min_distance = float(features_dict.get("min_domain_distance", 1.0))

        if has_trusted_subdomain:
            predicted_label = 1
            prob_legitimate = max(prob_legitimate, 0.995)
            override_reason = "trusted_subdomain"
        elif is_whitelisted and (not suspicious_similarity or min_distance <= 0.05):
            predicted_label = 1
            prob_legitimate = max(prob_legitimate, 0.99)
            override_reason = "whitelist_override"

        confidence = prob_legitimate if predicted_label == 1 else 1.0 - prob_legitimate

        return {
            "url": url,
            "probability_legitimate": prob_legitimate,
            "prediction_label": predicted_label,
            "prediction": "Legitimate" if predicted_label == 1 else "Phishing",
            "confidence": confidence,
            "override": override_reason,
            "features": {
                "is_whitelisted": int(is_whitelisted),
                "has_trusted_subdomain": int(has_trusted_subdomain),
                "is_suspicious_similarity": int(suspicious_similarity),
                "min_domain_distance": float(min_distance),
                "has_unicode": int(features_dict.get("has_unicode", 0)),
                "leet_speak_count": int(features_dict.get("leet_speak_count", 0)),
                "has_https": int(features_dict.get("has_https", 0)),
                "num_subdomains": int(features_dict.get("num_subdomains", 0)),
                "url_length": int(features_dict.get("url_length", 0)),
            },
        }


def evaluate_custom_urls(detector: UltraEnhancedDetector) -> dict:
    """Run the curated 45-URL suite used throughout the project."""

    legitimate_urls = [
        "https://www.microsoft.com",
        "https://www.apple.com",
        "https://www.amazon.com",
        "https://www.nytimes.com",
        "https://accounts.google.com",
        "https://www.bbc.com/news/world",
        "https://openai.com",
        "https://www.coursera.org",
        "https://www.khanacademy.org",
        "https://developer.mozilla.org",
        "https://github.com/openai",
        "https://www.stackoverflow.com",
        "https://aws.amazon.com",
        "https://support.apple.com",
        "https://www.ibm.com/cloud/learn",
        "https://about.netflix.com",
        "https://shop.adidas.com",
        "https://news.ycombinator.com",
        "https://scholar.google.com",
        "https://www.tesla.com/solarpanels",
    ]

    phishing_urls = [
        "http://paypal.com.login.verify-session.account-update.ru",
        "https://secure-update.amazon.verify-user.info/login.php",
        "http://bankofamerica.secure-session-login.xyz/account",
        "https://microsoft-support-password-reset.com/login",
        "http://google.docs-login-authenticate.com/secure",
        "https://faceb00k-login-security-check.com/auth",
        "http://update-paypal-secure-session.com/login",
        "https://secure-chasebank.account-recover.co/signin",
        "http://secure-ebay-login-user-verification.net/auth",
        "https://dropbox-file-verification.com/login",
        "http://outlook-security-login-reset-password.net",
        "https://yahoo-mail-authenticate-verify.com/login",
        "http://netflix-login-reset-auth-user.com",
        "https://github-security-alert-verify-user.com/auth",
        "http://steamcommunity-secure-login.com/signin",
        "https://appleid-reset-security-authenticate.co/login",
        "http://secure-facebook-login-checkpoint.biz/auth",
        "http://bitc0in-wallet-access.com/login",
        "https://instagram-security-reverify.com/auth",
        "http://linkedin-authentication-update.com/login",
        "https://pypal-verify-account-secure.com/auth",
        "http://spotify-account-recovery-security.com/login",
        "https://adidas-official-promo-free-shoes.com/signup",
        "http://epicgames-secure-verification.com/auth",
        "https://twitter-login-security-checker.com/auth",
    ]

    def run_suite(urls: list[str], expected_label: int):
        results = []
        correct = 0
        for url in urls:
            result = detector.predict(url)
            is_correct = int(result["prediction_label"] == expected_label)
            correct += is_correct
            results.append(
                {
                    "url": url,
                    "prediction": result["prediction"],
                    "confidence": result["confidence"],
                    "probability_legitimate": result["probability_legitimate"],
                    "expected_label": expected_label,
                    "correct": bool(is_correct),
                    "override": result.get("override"),
                    "features": result.get("features", {}),
                }
            )
        accuracy = correct / len(urls)
        return results, accuracy

    legit_results, legit_accuracy = run_suite(legitimate_urls, expected_label=1)
    phishing_results, phishing_accuracy = run_suite(phishing_urls, expected_label=0)

    summary = {
        "timestamp": datetime.now().isoformat(),
        "legitimate": {
            "total": len(legitimate_urls),
            "correct": sum(r["correct"] for r in legit_results),
            "accuracy": legit_accuracy,
            "results": legit_results,
        },
        "phishing": {
            "total": len(phishing_urls),
            "correct": sum(r["correct"] for r in phishing_results),
            "accuracy": phishing_accuracy,
            "results": phishing_results,
        },
    }

    summary["overall_accuracy"] = (
        (summary["legitimate"]["correct"] + summary["phishing"]["correct"]) /
        (summary["legitimate"]["total"] + summary["phishing"]["total"])
    )

    output_file = "custom_url_test_results_ultra.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print("\n📊 Custom URL evaluation complete!")
    print(f"   • Legitimate accuracy: {legit_accuracy * 100:.2f}%")
    print(f"   • Phishing accuracy: {phishing_accuracy * 100:.2f}%")
    print(f"   • Overall accuracy: {summary['overall_accuracy'] * 100:.2f}%")
    print(f"💾 Detailed results saved to {output_file}\n")

    return summary


def evaluate_full_dataset(detector: UltraEnhancedDetector, dataset_path: str) -> dict:
    """Optional utility to evaluate an entire labelled CSV dataset."""

    df = pd.read_csv(dataset_path)
    feature_names = detector.feature_names
    required_columns = set(feature_names) | {"label"}

    if not required_columns.issubset(df.columns):
        missing = required_columns - set(df.columns)
        raise ValueError(
            f"Dataset is missing required columns for evaluation: {sorted(missing)}"
        )

    X = df[feature_names].values.astype("float32")
    y_true = df["label"].values.astype(int)

    X_scaled = detector.scaler.transform(X)
    probabilities = detector.model.predict(X_scaled, verbose=0).flatten()
    predictions = (probabilities >= 0.5).astype(int)

    accuracy = float(np.mean(predictions == y_true))
    false_positives = int(np.sum((predictions == 1) & (y_true == 0)))
    false_negatives = int(np.sum((predictions == 0) & (y_true == 1)))

    summary = {
        "timestamp": datetime.now().isoformat(),
        "total": int(len(df)),
        "accuracy": accuracy,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
    }

    print("\n📈 Full dataset evaluation:")
    print(f"   • Samples: {summary['total']:,}")
    print(f"   • Accuracy: {summary['accuracy'] * 100:.2f}%")
    print(f"   • False positives (legit → phishing): {summary['false_positives']:,}")
    print(f"   • False negatives (phishing → legit): {summary['false_negatives']:,}\n")

    return summary


def main() -> None:
    detector = UltraEnhancedDetector()
    evaluate_custom_urls(detector)


if __name__ == "__main__":
    print("╔" + "=" * 78 + "╗")
    print("║" + " " * 12 + "ULTRA-ENHANCED PHISHING URL DETECTION" + " " * 13 + "║")
    print("║" + " " * 22 + "Custom URL Test Suite" + " " * 22 + "║")
    print("╚" + "=" * 78 + "╝")
    main()
