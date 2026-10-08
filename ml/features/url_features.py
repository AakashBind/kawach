"""
URL Feature Extraction Engine
Extracts 30+ lexical, structural, host, encoding, and token features from a raw URL.
Strictly deterministic, no network calls, safe against malformed inputs.
"""

import math
import re
from urllib.parse import urlparse, unquote

SUSPICIOUS_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'loan', 'click', 'link',
    'bid', 'stream', 'download', 'win', 'racing', 'accountant', 'date', 'faith',
    'review', 'party', 'trade', 'science', 'cricket', 'zip', 'mov'
}

SUSPICIOUS_TOKENS = [
    'login', 'signin', 'verify', 'verification', 'update', 'secure', 'security',
    'account', 'banking', 'bank', 'confirm', 'wallet', 'password', 'credential',
    'auth', 'ebay', 'paypal', 'apple', 'microsoft', 'google', 'netflix', 'amazon',
    'recover', 'support', 'service', 'billing', 'invoice', 'unlock', 'urgent',
    'suspend', 'kyc', 'bonus', 'free', 'gift', 'claim', 'crypto', 'binance'
]

IP_PATTERN = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
IPV6_PATTERN = re.compile(r'^\[?([a-fA-F0-9:]+)\]?$')

FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "num_dots",
    "num_hyphens",
    "num_underscores",
    "num_slashes",
    "num_questionmarks",
    "num_equal_signs",
    "num_at_symbols",
    "num_percent_encoded",
    "num_digits",
    "num_digits_hostname",
    "digit_ratio_url",
    "digit_ratio_hostname",
    "has_ip_address",
    "is_https",
    "subdomain_depth",
    "has_suspicious_tld",
    "suspicious_token_count",
    "suspicious_token_in_host",
    "suspicious_token_in_path",
    "url_entropy",
    "hostname_entropy",
    "has_non_standard_port",
    "path_depth",
    "has_double_slash_path",
    "has_at_symbol",
    "consecutive_consonants_max",
    "longest_token_length"
]


def calculate_entropy(text: str) -> float:
    """Computes Shannon entropy of a string."""
    if not text:
        return 0.0
    prob_dict = {}
    for char in text:
        prob_dict[char] = prob_dict.get(char, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in prob_dict.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_url_features(raw_url: str) -> dict:
    """
    Parses a URL and extracts a comprehensive, deterministic dictionary of features.
    """
    if not raw_url or not isinstance(raw_url, str):
        raw_url = ""

    url_str = raw_url.strip()
    if not url_str.startswith(('http://', 'https://')):
        parsed = urlparse('http://' + url_str)
        is_https = 0
    else:
        parsed = urlparse(url_str)
        is_https = 1 if parsed.scheme.lower() == 'https' else 0

    hostname = parsed.hostname or ''
    path = parsed.path or ''
    query = parsed.query or ''

    # Normalize hostname
    hostname_clean = hostname.lower()

    # IP address detection
    has_ip = 1 if (IP_PATTERN.match(hostname_clean) or IPV6_PATTERN.match(hostname_clean)) else 0

    # Subdomain depth
    host_parts = hostname_clean.split('.')
    if has_ip:
        subdomain_depth = 0
        tld = ''
    else:
        # e.g., 'a.b.example.com' -> depth 2 subdomains
        subdomain_depth = max(0, len(host_parts) - 2) if len(host_parts) > 1 else 0
        tld = host_parts[-1] if host_parts else ''

    has_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0

    # Counts
    num_dots = url_str.count('.')
    num_hyphens = url_str.count('-')
    num_underscores = url_str.count('_')
    num_slashes = url_str.count('/')
    num_questionmarks = url_str.count('?')
    num_equal_signs = url_str.count('=')
    num_at_symbols = url_str.count('@')
    num_percent = url_str.count('%')
    num_digits = sum(c.isdigit() for c in url_str)
    num_digits_host = sum(c.isdigit() for c in hostname_clean)

    url_len = len(url_str)
    host_len = len(hostname_clean)
    path_len = len(path)
    query_len = len(query)

    digit_ratio_url = round(num_digits / max(1, url_len), 4)
    digit_ratio_host = round(num_digits_host / max(1, host_len), 4)

    # Token-based signals
    url_lower = url_str.lower()
    path_lower = path.lower()

    tokens_found_total = sum(1 for token in SUSPICIOUS_TOKENS if token in url_lower)
    tokens_in_host = sum(1 for token in SUSPICIOUS_TOKENS if token in hostname_clean)
    tokens_in_path = sum(1 for token in SUSPICIOUS_TOKENS if token in path_lower)

    # Entropy
    url_entropy = calculate_entropy(url_str)
    host_entropy = calculate_entropy(hostname_clean)

    # Port
    has_non_standard_port = 0
    if parsed.port and parsed.port not in (80, 443):
        has_non_standard_port = 1

    # Path depth
    path_depth = len([seg for seg in path.split('/') if seg])

    # Obfuscation: '//' in path
    has_double_slash_path = 1 if '//' in path else 0

    # Consecutive consonants (random generation detection)
    consonants = "bcdfghjklmnpqrstvwxyz"
    max_consonants = 0
    current_consonants = 0
    for char in hostname_clean:
        if char in consonants:
            current_consonants += 1
            if current_consonants > max_consonants:
                max_consonants = current_consonants
        else:
            current_consonants = 0

    # Longest token length
    raw_tokens = re.split(r'[/.\-_?&=%]', url_str)
    longest_token = max((len(t) for t in raw_tokens), default=0)

    features = {
        "url_length": url_len,
        "hostname_length": host_len,
        "path_length": path_len,
        "query_length": query_len,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_underscores": num_underscores,
        "num_slashes": num_slashes,
        "num_questionmarks": num_questionmarks,
        "num_equal_signs": num_equal_signs,
        "num_at_symbols": num_at_symbols,
        "num_percent_encoded": num_percent,
        "num_digits": num_digits,
        "num_digits_hostname": num_digits_host,
        "digit_ratio_url": digit_ratio_url,
        "digit_ratio_hostname": digit_ratio_host,
        "has_ip_address": has_ip,
        "is_https": is_https,
        "subdomain_depth": subdomain_depth,
        "has_suspicious_tld": has_suspicious_tld,
        "suspicious_token_count": tokens_found_total,
        "suspicious_token_in_host": tokens_in_host,
        "suspicious_token_in_path": tokens_in_path,
        "url_entropy": url_entropy,
        "hostname_entropy": host_entropy,
        "has_non_standard_port": has_non_standard_port,
        "path_depth": path_depth,
        "has_double_slash_path": has_double_slash_path,
        "has_at_symbol": 1 if num_at_symbols > 0 else 0,
        "consecutive_consonants_max": max_consonants,
        "longest_token_length": longest_token
    }

    return features


def extract_features_vector(raw_url: str) -> list:
    """Returns the features as a flat list matching FEATURE_NAMES ordering."""
    feat_dict = extract_url_features(raw_url)
    return [feat_dict[name] for name in FEATURE_NAMES]
