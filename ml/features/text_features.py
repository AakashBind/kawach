"""
Text Feature Extraction & Normalization
"""

import re
from typing import Dict, Any


def normalize_message_text(text: str) -> str:
    """Safely normalizes whitespace and encoding while preserving security entities."""
    if not text:
        return ""
    # Replace multiple whitespaces with single space
    cleaned = re.sub(r'\s+', ' ', text).strip()
    return cleaned


def extract_text_meta_features(text: str) -> Dict[str, Any]:
    """Extracts meta statistics from message text."""
    normalized = normalize_message_text(text)
    char_len = len(normalized)
    words = normalized.split()
    word_count = len(words)
    uppercase_count = sum(1 for c in normalized if c.isupper())
    digits_count = sum(1 for c in normalized if c.isdigit())
    exclamation_count = normalized.count('!')
    dollar_count = normalized.count('$') + normalized.count('₹') + normalized.count('€')

    return {
        "char_length": char_len,
        "word_count": word_count,
        "uppercase_ratio": round(uppercase_count / max(1, char_len), 4),
        "digits_ratio": round(digits_count / max(1, char_len), 4),
        "exclamation_count": exclamation_count,
        "currency_symbol_count": dollar_count
    }
