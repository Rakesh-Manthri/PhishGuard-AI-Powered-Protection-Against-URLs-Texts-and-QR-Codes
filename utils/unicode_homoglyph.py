"""Unicode homoglyph (IDN) detection utilities.

Deterministic detection focused on hostname visual-skeleton matching
against a small allow-list of brand names. Designed to avoid false
positives on legitimate internationalized domains by only flagging
cases where Latin is mixed with Cyrillic or Greek and a label's
visual skeleton exactly matches a known brand skeleton.

API:
  detect_homoglyph(url) -> (is_homoglyph_attack: bool, matched_brand: str|None)
  analyze_hostname(url) -> (original_hostname, normalized_hostname, skeleton)

Constraints: pure-Python, production-safe, explainable, no ML.
"""
from __future__ import annotations

import re
import unicodedata
from urllib.parse import urlparse
from typing import Optional, Tuple, List

# Small brand reference list and their official domains. This is NOT a
# whitelist; it's a concise mapping used to recognize target brands when
# computing skeleton matches.
BRAND_REFERENCE = {
    "paypal": {"domains": ["paypal.com"]},
    "google": {"domains": ["google.com"]},
    "microsoft": {"domains": ["microsoft.com"]},
    "apple": {"domains": ["apple.com"]},
    "amazon": {"domains": ["amazon.com"]},
    "leetcode": {"domains": ["leetcode.com"]},
}


# Common confusable mappings for Cyrillic and Greek -> Latin
# This table is intentionally small and conservative to avoid false positives.
CHAR_MAPPING = {
    # Cyrillic -> Latin
    "а": "a", "А": "a",
    "е": "e", "Е": "e",
    "о": "o", "О": "o",
    "р": "p", "Р": "p",
    "с": "c", "С": "c",
    "х": "x", "Х": "x",
    "у": "y", "У": "y",
    "к": "k", "К": "k",
    "м": "m", "М": "m",
    "т": "t", "Т": "t",
    # Note: mapping Cyrillic 'н' -> 'h' removed to reduce false positives.
    # Greek -> Latin
    "α": "a", "Α": "a",
    "β": "b", "Β": "b",
    "ο": "o", "Ο": "o",
    "ρ": "p", "Ρ": "p",
    "ι": "i", "Ι": "i",
    "τ": "t", "Τ": "t",
    "ν": "v", "Ν": "v",
    "σ": "s", "Σ": "s",
}


def _extract_hostname(url: str) -> str:
    """Return the hostname part of a URL. If the input is a bare hostname,
    this still works (we temporarily add a scheme for parsing)."""
    if not isinstance(url, str):
        return ""

    url = url.strip()
    if not url:
        return ""

    # Ensure parseable
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url_to_parse = "http://" + url
    else:
        url_to_parse = url

    parsed = urlparse(url_to_parse)
    hostname = parsed.hostname or ""

    # Strip potential trailing dot
    if hostname.endswith('.'):
        hostname = hostname[:-1]

    return hostname


def _decode_punycode_label(label: str) -> str:
    """Decode a single punycode label if it starts with 'xn--'."""
    try:
        if label.lower().startswith("xn--"):
            # idna decoding: label is ASCII
            return label.encode('ascii').decode('idna')
    except Exception:
        # On any failure, return original label
        return label
    return label


def _normalize_hostname(hostname: str) -> str:
    """Decode punycode per-label and apply Unicode NFKC normalization."""
    if not hostname:
        return ""

    labels = hostname.split('.')
    decoded_labels: List[str] = []
    for lbl in labels:
        lbl = _decode_punycode_label(lbl)
        # NFKC normal form
        lbl = unicodedata.normalize('NFKC', lbl)
        decoded_labels.append(lbl)

    return ".".join(decoded_labels)


def _map_fullwidth(ch: str) -> str:
    """Map full-width ASCII (FF01-FF5E) to ASCII by subtracting the offset.
    If not full-width, return original."""
    code = ord(ch)
    # Full-width ASCII range
    if 0xFF01 <= code <= 0xFF5E:
        return chr(code - 0xFEE0)
    return ch


def _char_to_skeleton(ch: str) -> str:
    """Map a character to its skeleton equivalent conservatively."""
    # First map full-width ASCII
    ch = _map_fullwidth(ch)

    # Direct table mapping
    mapped = CHAR_MAPPING.get(ch)
    if mapped:
        return mapped

    # Basic Latin letters and digits pass through (normalized to lower)
    if 'A' <= ch <= 'Z' or 'a' <= ch <= 'z' or ch.isdigit():
        return ch.lower()

    # For other characters leave as-is (do not aggressively map)
    return ch


def _label_skeleton(label: str) -> str:
    """Return the skeleton for a single domain label."""
    return ''.join(_char_to_skeleton(ch) for ch in label)


def _detect_scripts(text: str) -> dict:
    """Detect presence of Latin, Cyrillic, and Greek characters in text.
    Uses conservative Unicode block checks to avoid false positives."""
    latin = False
    cyrillic = False
    greek = False

    for ch in text:
        code = ord(ch)
        # ASCII/Latin range (basic + Latin-1 supplement + extended):
        if (0x0041 <= code <= 0x007A) or (0x00C0 <= code <= 0x024F):
            latin = True
        # Cyrillic blocks
        if (0x0400 <= code <= 0x04FF) or (0x0500 <= code <= 0x052F) or (0x2DE0 <= code <= 0x2DFF):
            cyrillic = True
        # Greek blocks
        if (0x0370 <= code <= 0x03FF) or (0x1F00 <= code <= 0x1FFF):
            greek = True

    return {"latin": latin, "cyrillic": cyrillic, "greek": greek}


def analyze_hostname(url: str) -> Tuple[str, str, str]:
    """Return (original_hostname, normalized_hostname, skeleton).

    The skeleton is the dot-joined skeleton of each label.
    """
    original = _extract_hostname(url)
    normalized = _normalize_hostname(original)
    labels = normalized.split('.') if normalized else []
    skeleton_labels = [_label_skeleton(lbl) for lbl in labels]
    skeleton = '.'.join(skeleton_labels)
    return original, normalized, skeleton


def detect_homoglyph(url: str) -> Tuple[bool, Optional[str]]:
    """Detect whether `url` contains a hostname that visually impersonates
    one of the brands in the allow-list using conservative, deterministic
    homoglyph logic.

    Returns (is_homoglyph_attack, matched_brand_or_None).
    """
    original, normalized, skeleton = analyze_hostname(url)

    if not normalized:
        return False, None

    # Mixed-script detection: only consider cases where Latin is mixed with
    # Cyrillic or Greek.
    scripts = _detect_scripts(normalized.replace('.', ''))
    latin_present = scripts['latin']
    cyr_or_grk = scripts['cyrillic'] or scripts['greek']

    if not (latin_present and cyr_or_grk):
        # Do not flag pure IDNs (e.g., CJK, Arabic) or pure single-script names.
        return False, None

    # Check per-label skeletons against brand skeletons.
    labels = normalized.split('.')
    for lbl in labels:
        lbl_skel = _label_skeleton(lbl)
        for brand, meta in BRAND_REFERENCE.items():
            if lbl_skel == brand:
                # If the hostname is the official brand domain (or subdomain), do not flag
                official_domains = meta.get('domains', [])
                lower_norm = normalized.lower()
                is_official = any(lower_norm == d or lower_norm.endswith('.' + d) for d in official_domains)
                if is_official:
                    return False, None
                return True, brand

    return False, None


if __name__ == '__main__':
    # Simple manual tests
    tests = [
        'https://раypal.com',  # mixed-script example (Cyrillic 'р' or 'а')
        'http://аррӏe.com',  # cyrillic-ish apple
        'https://google.com',
        'https://гoogIe.com',
    ]
    for t in tests:
        print(t, '->', detect_homoglyph(t))
