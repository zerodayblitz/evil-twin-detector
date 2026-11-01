import sys

sys.path.insert(0, "src")

from capture.windows import scan
from parser.ie_parser import parse_ies
from scorer.scorer import score


def find_collisions(access_points):
    by_ssid = {}
    for ap in access_points:
        if not ap.ssid:
            continue
        by_ssid.setdefault(ap.ssid, []).append(ap)

    collisions = {ssid: aps for ssid, aps in by_ssid.items() if len(aps) >= 2}
    return collisions


def analyze(ap_a, ap_b):
    ies_a, _ = parse_ies(ap_a.ie_bytes)
    ies_b, _ = parse_ies(ap_b.ie_bytes)

    result = score(ap_a, ap_b, ies_a, ies_b)

    print(f"\nTrust: {result.trust_bssid}")
    print(f"Avoid: {result.avoid_bssid}")
    print(f"Confidence: {result.confidence}/100")
    print("\nEvidence:")
    for name, detail in result.breakdown.items():
        against = detail["against"]
        if against == "a":
            against = ap_a.bssid
        elif against == "b":
            against = ap_b.bssid
        else:
            against = "neither"
        print(f"  {name}: {detail['points']} points, against {against}")


BANNER = r"""
⠀⠀⠀⠀⣠⣤⣶⣶⣶⣤⣄⡀⠀
⠀⠀⣴⣾⣿⣿⣿⣿⣿⣧⡀⠈⠢
⠀⣼⣿⣿⣿⣿⣿⣿⣿⡿⠁⠀EVIL-TWIN DETECTOR⠀v 1.0.0
⢰⡿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀Designed by @zerodayblitz⠀
⠘⣽⡿⠿⠿⣿⣿⣿⣿⣿⣦⣤⡀
⠀⣟⠀⠀⠀⣸⣿⡏⠀⠀⠀⢹⠗
⠀⣿⣷⣶⣾⡿⠁⠙⣄⣀⣀⣠⡀
⠀⠙⠙⢿⡿⣷⣶⣤⣿⣿⡿⠿⠃
⠀⠀⠀⠺⡏⡏⡏⡏⡏⠉⠁⠀⠀
⠀⠀⠀⠀⠀⠀⠁⠁⠀⠀⠀⠀⠀
"""


def main():
    print(BANNER)
    print("[*] Scanning for Collisions...")

    access_points = scan()
    collisions = find_collisions(access_points)

    if not collisions:
        print("[+] No collisions detected. Type 'rescan' to scan again\n")
    else:
        print(f"[!] {len(collisions)} collision(s) detected:")
        for ssid, aps in collisions.items():
            print(f'      "{ssid}"  —  {len(aps)} BSSIDs')

    print('Enter "scan [ssid]" to analyze collision or "rescan" to rescan (q to quit)')

    while True:
        command = input(">").strip()
        if command == "q" or command == "quit":
            break
        elif command == "rescan":
            print("[*] Scanning for Collisions...")
            access_points = scan()
            collisions = find_collisions(access_points)
            if not collisions:
                print("[+] No collisions detected. Type 'rescan' to scan again\n")
            else:
                print(f"[!] {len(collisions)} collision(s) detected:")
                for ssid, aps in collisions.items():
                    print(f'      "{ssid}"  —  {len(aps)} BSSIDs')
                print()
        elif command.startswith("scan "):
            ssid = command[5:].strip('"')
            if ssid not in collisions:
                print(f'No collision found for "{ssid}". Try "rescan" first.\n')
            else:
                aps = collisions[ssid]
                analyze(aps[0], aps[1])
                print()
        else:
            print('Unknown command. Try: "scan [ssid]", "rescan", or "q" to quit.')


if __name__ == "__main__":
    main()
