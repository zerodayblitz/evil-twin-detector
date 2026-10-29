"""

Compares two access points sharing an SSID and produces a verdict;
Which BSSID to trust, a confidence scor, and a per-signal breakdown

"""

from dataclasses import dataclass, field

TSF_MAX_POINTS = 30
TSF_SATURATION_DAYS = 7
MICROSECONDS_PER_DAY = 86_400_000_000

LA_BIT_POINTS = 10

@dataclass
class ScoreResult:
    trust_bssid: str
    avoid_bssid: str
    confidence: int
    suspicion_a: int
    suspicion_b: int
    breakdown: dict = field(default_factory=dict)

def score(ap_a, ap_b, ies_a, ies_b):
    suspicion_a = 0
    suspicion_b = 0
    breakdown = {}

    # TSF Signal
    tsf_points, tsf_suspect = score_tsf(ap.a,ap.b)
    if tsf_suspect == ap.a.bssid:
        suspicion_a += tsf_points
    else:
        suspicion_b += tsf_points
    breakdown["tsf"] = {"points": tsf_points, "against": tsf_suspect}

    if suspicion_a > suspicion_b:
        trust, avoid = ap_b.bssid, ap_a.bssid
    else:
        trust, avoid = ap_a.bssid, ap_b.bssid

    gap = abs(suspicion_a - suspicion_b)
    confidence = min(gap, 100)

    return ScoreResult(
        trust_bssid=trust,
        avoid_bssid=avoid,
        confidence=confidence,
        suspicion_a=suspicion_a
        suspicion_b=suspicion_b
        breakdown=breakdown
    )

# TSF Scoring
def score_tsf(ap_a, ap_b):
    gap_us = abs(ap_a.tsf - ap_b.tsf)
    gap_days = gap_us / MICROSECONDS_PER_DAY

    suspect = ap_a if ap_a.tsf < ap_b.tsf else ap_b

    ratio = min(gap_days / TSF_SATURATION_DAYS, 1.0)
    points = TSF_MAX_POINTS * (ratio ** 2)

    return round(points), suspect.bssid

def score_la_bit(ap_a, ap_b):
    bits = []
    for ap in (ap_a, ap_b):
        first_byte = int(ap.bssid[0:2], 16)
        bits.append((first_byte & 0b10) != 0)  # Is the result non zero 
                                               # Non zero BSSI first bit = software set
    a_set, b_set = bits 

    if a_set and not b_set:
        return LA_BIT_POINTS, ap_a.bssid
    if b_set and not a_set:
        return LA_BIT_POINTS, ap_b.bssid
    return 0, None