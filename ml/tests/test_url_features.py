"""
Unit Tests for URL Feature Extraction Engine
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from features.url_features import extract_url_features, extract_features_vector, FEATURE_NAMES, calculate_entropy


def test_ip_address_detection():
    url = "http://192.168.1.100/login.php"
    feats = extract_url_features(url)
    assert feats["has_ip_address"] == 1
    assert feats["is_https"] == 0
    assert feats["path_depth"] == 1


def test_legitimate_https_url():
    url = "https://www.google.com/search?q=cybersecurity"
    feats = extract_url_features(url)
    assert feats["has_ip_address"] == 0
    assert feats["is_https"] == 1
    assert feats["subdomain_depth"] == 1  # 'www'
    assert feats["has_suspicious_tld"] == 0


def test_suspicious_tld_and_brand_tokens():
    url = "http://paypal-verification.security-alert.tk/login"
    feats = extract_url_features(url)
    assert feats["has_suspicious_tld"] == 1
    assert feats["suspicious_token_count"] >= 2  # 'paypal', 'security', 'login'
    assert feats["subdomain_depth"] >= 1


def test_empty_or_malformed_url():
    feats_empty = extract_url_features("")
    assert len(feats_empty) == len(FEATURE_NAMES)
    assert feats_empty["url_length"] == 0

    feats_none = extract_url_features(None)
    assert len(feats_none) == len(FEATURE_NAMES)


def test_entropy_calculation():
    # Fixed string entropy
    ent_low = calculate_entropy("aaaaaa")
    ent_high = calculate_entropy("a8!b9@c#d$")
    assert ent_low == 0.0
    assert ent_high > 3.0
