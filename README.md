# evil-twin-detector

Passive Wi-Fi evil-twin detector that scores two access points sharing an SSID and tells you which one to trust using only beacon frames already broadcast to the air. No prior knowledge of which network is legitimate.

## The problem

An evil twin is a rogue access point broadcasting the same SSID as a real network to lure victims into connecting through an attacker. Most tools detect evil twins by comparing live traffic against a known-good baseline. This one doesn't assume a baseline exists; it compares two candidate APs against each other and reasons about which is more likely the impostor, from a single passive scan.

## How it works

```
scan()      Windows Native WLAN API (ctypes, no monitor mode) that reads every
            nearby AP's beacon data: SSID, BSSID, RSSI, channel, TSF timestamp,
            and the raw Information Element (IE) blob.

parse_ies() Walks the IE blob as a TLV (type-length-value) structure, with
            bounds-checking against truncated/malformed data.

score()     Compares two same-SSID APs across four independent signals and
            returns a confidence-rated verdict: which BSSID to trust, which
            to avoid, and the full evidence breakdown.

cli.py      An interactive shell: scans on start, flags any SSID broadcast by
            2+ BSSIDs, and lets you run `scan "<SSID>"` to get a verdict.
```

## Signals

Four signals, each chosen because it can **asymmetrically name a suspect** — not just detect that two APs differ, but say *which one* is more likely fake.

| Signal | Weight | What it checks |
|---|---|---|
| **TSF uptime gap** | 30 (strong) | Beacon timestamps reveal how long each radio has been running. A rogue AP that just went up betrays itself against a real AP with days of uptime. Scored on a squared curve, saturating at a 7-day gap. |
| **IE richness** | 30 (strong) | Real firmware advertises a dense, vendor-specific Information Element set. Rogue AP software (hostapd) typically advertises a much sparser one. Scored proportionally: `(richer − sparser) / richer`, squared. |
| **Security (RSN) mismatch** | 15 (medium) | Checks whether each AP advertises an RSN (WPA2/WPA3) element. An open AP masquerading as a normally-secured network is the more likely impostor. |
| **Locally-administered bit** | 10 (supporting) | The LA bit in a BSSID's first byte flags a software-set (non-factory) MAC address common in ad hoc rogue AP setups. |

Suspicion points accumulate per AP across all four signals; confidence (0–100) is derived from the gap between the two totals.

## What was deliberately cut

Every candidate signal was tested against one bar: **can it name a suspect, not just detect a mismatch?** Several plausible-sounding signals failed that test and were cut, with reasons:

- **IE ordering** — two *legitimate* APs from different vendors naturally order their elements differently. A difference in order is the normal case between any two different radios, not evidence of an attack.
- **OUI vendor lookup** — a real attacker uses their own hardware's valid, registered OUI (or clones the real AP's). OUI validity checking only fires against randomized MACs, which no competent attacker produces.
- **Clock skew fingerprinting** — a real signal in the literature, but it detects *that* two radios share an identity, not *which one* is legitimate, without a reference baseline this tool doesn't have.
- **Malformed-beacon flag** — real attacker tooling (hostapd) produces clean, well-formed beacons. This signal rarely fires against an actual attack, and when it does fire it's usually a corrupted capture or a flaky legitimate device, not an evil twin.
- **One-shot RSSI** — signal strength reflects the *scanner's* position relative to each radio, not either radio's legitimacy. It has no fixed direction to exploit.

## Install

```bash
git clone https://github.com/zerodayblitz/evil-twin-detector
cd evil-twin-detector
pip install -e .
```

## Usage

```bash
evil-twin-detector
```

```
[*] Scanning for Collisions...
[!] 1 collision(s) detected:
      "HomeWifi"  —  2 BSSIDs

Enter "scan [ssid]" to analyze collision or "rescan" to rescan (q to quit)

> scan "HomeWifi"

Trust: a4:2b:8c:11:22:33
Avoid: 02:de:ad:be:ef:01
Confidence: 73/100

Evidence:
  tsf: 30 points, against 02:de:ad:be:ef:01
  ie_richness: 18 points, against 02:de:ad:be:ef:01
  security: 15 points, against 02:de:ad:be:ef:01
  la_bit: 10 points, against 02:de:ad:be:ef:01
```

(The example above is real output (replaced with fake data) from testing this tool against a `hostapd` clone of a router I own.)

## License

MIT
