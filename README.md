# x402check feeds

Generated daily by `.github/workflows/feeds.yml` from the `main` branch scripts. The x402check Worker reads these files at runtime and verifies each against `manifest.json` (SHA-256, entry counts) before use; if anything fails it keeps the snapshot embedded at deploy time.

- `metamask-phishing.bin`, `metamask.json`: derived from MetaMask eth-phishing-detect (DBAD-1.2; see THIRD_PARTY_NOTICES.md on `main`).
- `ofac-sdn.json`: digital currency addresses from the OFAC SDN list (U.S. Government public data).
