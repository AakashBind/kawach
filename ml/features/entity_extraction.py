"""
Entity Extraction & Social Engineering Signal Engine
Extracts entities (URLs, phone numbers, emails, crypto addresses, monetary sums)
and intent cues (urgency, credential harvesting, impersonation, fear/authority).
"""

import re
from typing import Dict, List, Any

URL_REGEX = re.compile(
    r'(?:https?:\/\/|www\.)[^\s<>"]+|(?:\b[a-zA-Z0-9.-]+\.(?:com|org|net|edu|gov|io|xyz|tk|ml|cf|gq|info|biz|top|me|co|app)\b[^\s<>"]*)',
    re.IGNORECASE
)
EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
PHONE_REGEX = re.compile(r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b')
MONEY_REGEX = re.compile(r'(?:\$|€|£|₹|Rs\.?|USD|INR|EUR|GBP)\s*[\d,]+(?:\.\d{2})?|\b[\d,]+(?:\.\d{2})?\s*(?:dollars|rupees|euros|pounds|bucks|credits)\b', re.IGNORECASE)
CRYPTO_REGEX = re.compile(r'\b(?:1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,39}|0x[a-fA-F0-9]{40})\b')

URGENCY_KEYWORDS = [
    'immediately', 'urgent', '24 hours', '48 hours', 'act now', 'expires',
    'suspended', 'suspension', 'locked', 'terminate', 'final warning', 'deadline',
    'instant', 'quick', 'hurry', 'limited time', 'right away', 'critical'
]

CREDENTIAL_PATTERNS = [
    r'\bpasswords?\b', r'\bpasscodes?\b', r'\bpin\b', r'\bcredentials?\b',
    r'\bssn\b', r'\bsocial security\b', r'\bkyc verification\b',
    r'\b(?:verify|unlock|confirm)\s+your\s+(?:account|identity|access)\b',
    r'\b(?:reply with|send|share|provide|enter|submit|give)\s+(?:the|your)?\s*(?:verification\s*code|code|otp|pin|password)\b',
    r'\bsecurity question\b', r'\blogin\b', r'\bsign in\b'
]

PAYMENT_KEYWORDS = [
    'bank account', 'credit card', 'debit card', 'cvv', 'wire transfer', 'western union',
    'gift card', 'itunes card', 'bitcoin', 'crypto', 'upi', 'paytm', 'gpay', 'phonepe',
    'refund', 'invoice', 'claim prize', 'lottery', 'winner', 'inheritance', 'tax rebate'
]

AUTHORITY_KEYWORDS = [
    'irs', 'fbi', 'police', 'customs', 'tax department', 'customer support',
    'security team', 'fraud prevention', 'bank manager', 'legal notice', 'court summons'
]


def extract_entities(text: str) -> Dict[str, Any]:
    """Extracts all structured entities and intent flags from unstructured message text."""
    if not text or not isinstance(text, str):
        text = ""

    urls = URL_REGEX.findall(text)
    emails = EMAIL_REGEX.findall(text)
    phones = PHONE_REGEX.findall(text)
    money_mentions = MONEY_REGEX.findall(text)
    crypto_wallets = CRYPTO_REGEX.findall(text)

    text_lower = text.lower()

    found_urgency = [w for w in URGENCY_KEYWORDS if re.search(r'\b' + re.escape(w) + r'\b', text_lower)]
    found_credentials = [p for p in CREDENTIAL_PATTERNS if re.search(p, text_lower)]
    found_payments = [w for w in PAYMENT_KEYWORDS if re.search(r'\b' + re.escape(w) + r'\b', text_lower)]
    found_authority = [w for w in AUTHORITY_KEYWORDS if re.search(r'\b' + re.escape(w) + r'\b', text_lower)]

    return {
        "extracted_urls": list(set(urls)),
        "extracted_emails": list(set(emails)),
        "extracted_phones": list(set(phones)),
        "monetary_amounts": list(set(money_mentions)),
        "crypto_wallets": list(set(crypto_wallets)),
        "intent_signals": {
            "has_urgency": len(found_urgency) > 0,
            "urgency_triggers": found_urgency,
            "has_credential_request": len(found_credentials) > 0,
            "credential_triggers": found_credentials,
            "has_payment_request": len(found_payments) > 0,
            "payment_triggers": found_payments,
            "has_authority_impersonation": len(found_authority) > 0,
            "authority_triggers": found_authority
        }
    }
