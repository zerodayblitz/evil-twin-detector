# evil-twin-detector

Passive Wi-Fi evil-twin detector that fingerprints and scores nearby access points from raw 802.11 beacon data to flag rogue APs, with no prior knowledge of which network is legitimate.

## The problem

An evil twin is a rogue access point broadcasting the same SSID as a legitimate network to lure devices into connecting through an attacker. This tool identifies which of two APs sharing an SSID is the impostor, using only passively observed beacon data. It never connects, transmits, or interferes.

## How it works

The tool reads the beacon frames every access point broadcasts, parses each one into a fingerprint, and scores APs that share an SSID against each other across multiple independent signals. The output is a confidence-rated verdict (which BSSID to trust and why) rather than a binary alarm.

## Signals

- TSF uptime gap: a just-started rogue AP betrays itself against a long-running legitimate one
- Information Element richness and ordering: vendor firmware produces a characteristic beacon structure that is hard to fully replicate
- Security configuration mismatch (RSN)
- BSSID analysis: OUI vendor lookup and the locally-administered bit

## License

MIT
