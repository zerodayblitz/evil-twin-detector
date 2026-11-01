import sys

sys.path.insert(0, "src")

from capture.windows import scan
from parser.ie_parser import parse_ies
from scorer.scorer import score

results = scan()
candidates = [ap for ap in results if ap.ssid == "B1841C_5G"]

if len(candidates) < 2:
    print(f"Only found {len(candidates)} AP(s) for that SSID. Need 2 to compare.")
else:
    ap_a, ap_b = candidates[0], candidates[1]

    ies_a, _ = parse_ies(ap_a.ie_bytes)
    ies_b, _ = parse_ies(ap_b.ie_bytes)

    result = score(ap_a, ap_b, ies_a, ies_b)

    print(f"Trust: {result.trust_bssid}")
    print(f"Avoid: {result.avoid_bssid}")
    print(f"Confidence: {result.confidence}/100")
    print(f"Suspicion A: {result.suspicion_a}  Suspicion B: {result.suspicion_b}")
    print("\nBreakdown:")
    for name, detail in result.breakdown.items():
        print(f"  {name}: {detail['points']} points, against {detail['against']}")
