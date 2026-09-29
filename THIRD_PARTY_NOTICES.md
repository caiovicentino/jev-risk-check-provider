# Third-party data notices

x402check is MIT-licensed. It uses the following third-party data. Nothing below changes the license of this repository's code.

## OFAC Specially Designated Nationals (SDN) list — U.S. Treasury

- Source: https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.XML
- Use: `scripts/update-ofac.ts` extracts the "Digital Currency Address - <TICKER>" identifiers into `src/data/ofac-sdn.ts` (address, ticker, SDN entry uid, entry name).
- Status: U.S. Government public data. The snapshot date is recorded in the generated file and in every attestation (`checks.sanctions.as_of`).
- Scope: **direct listing of an address only.** A `not_listed` result does not clear indirect exposure (funds received from listed addresses). x402check is not a compliance control.

## MetaMask eth-phishing-detect — DBAD Public License v1.2

- Source: https://github.com/MetaMask/eth-phishing-detect (`src/config.json`, blacklist and whitelist)
- Use: `scripts/update-threat-feeds.ts` derives `src/data/metamask-phishing.bin` (sorted 8-byte SHA-256 prefixes of the normalized blacklisted hosts, no plaintext) and `src/data/threat-feeds.ts` (source commit, date, counts, and the list's own allowlist).
- Attribution: this derived data comes from the MetaMask eth-phishing-detect project, licensed under the "DON'T BE A DICK PUBLIC LICENSE" v1.2 (Copyright (C) 2018 kumavis): "Do whatever you like with the original work, just don't be a dick." The license text is at https://github.com/MetaMask/eth-phishing-detect/blob/main/LICENSE. x402check does not sell the unmodified list. Detection-quality issues belong upstream: https://github.com/MetaMask/eth-phishing-detect/issues
- Not used: MetaMask's hosted phishing-detection API. Its Terms of Use restrict scraping.

## ScamSniffer scam-database — GPL-3.0

- Source: https://github.com/scamsniffer/scam-database (`blacklist/domains.json`, `blacklist/address.json`). The public data is published with a 7-day delay.
- Use: runtime only. `scripts/update-threat-feeds.ts --scamsniffer --upload` builds hash blobs locally under `.cache/` (git-ignored) and stores them in the operator's Cloudflare KV. The Worker reads them at request time.
- Not done: the derived data is **not committed to this repository and not bundled into the distributed Worker code**, so no GPL-covered work is conveyed.
- Handling: ScamSniffer domain hits cap a score only when x402check's own domain analysis corroborates them, because the list also contains popular shared hosts (URL shorteners, storage platforms). EVM address hits are applied directly.
