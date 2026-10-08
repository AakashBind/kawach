"""
Unit Tests for Text Preprocessing and Entity Extraction
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from features.entity_extraction import extract_entities
from features.text_features import normalize_message_text, extract_text_meta_features


def test_entity_extraction_urgency_and_payment():
    msg = "URGENT: Your bank account will be closed in 24 hours unless you pay $500 via Bitcoin to 0x1234567890abcdef1234567890abcdef12345678"
    res = extract_entities(msg)

    assert len(res["monetary_amounts"]) > 0
    assert len(res["crypto_wallets"]) > 0
    assert res["intent_signals"]["has_urgency"] is True
    assert res["intent_signals"]["has_payment_request"] is True


def test_entity_extraction_embedded_urls_and_credentials():
    msg = "Please verify your password and login at http://fake-bank-login.xyz/auth immediately"
    res = extract_entities(msg)

    assert len(res["extracted_urls"]) == 1
    assert "fake-bank-login.xyz" in res["extracted_urls"][0]
    assert res["intent_signals"]["has_credential_request"] is True
    assert res["intent_signals"]["has_urgency"] is True


def test_text_normalization():
    raw = "  Hello   world! \n\n  Please   check this link   "
    clean = normalize_message_text(raw)
    assert clean == "Hello world! Please check this link"
