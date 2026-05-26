"""
Shared entropy utilities used across static_analyzer, c2_detector, and ml_service.
"""
import math
from typing import Union


def shannon_entropy(data: Union[str, bytes]) -> float:
    """
    Compute Shannon entropy of a string or bytes object.
    Returns value between 0.0 and 8.0 (for bytes) or ~4.7 (for ASCII strings).
    """
    if not data:
        return 0.0
    if isinstance(data, str):
        data = data.strip()
        if not data:
            return 0.0
    length = len(data)
    freq = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())
    return round(entropy, 4)


def is_high_entropy(text: str, threshold: float = 4.5) -> bool:
    """Check if a string has high entropy (likely encrypted/encoded)."""
    return shannon_entropy(text) >= threshold


def entropy_label(entropy: float) -> str:
    """
    Return a human-readable label for an entropy value.
    Used for report output and analysis results.
    """
    if entropy < 3.0:
        return "Normal"
    elif entropy < 4.0:
        return "Slightly Suspicious"
    elif entropy < 4.5:
        return "Suspicious"
    elif entropy < 5.5:
        return "Highly Suspicious"
    else:
        return "Critical"
