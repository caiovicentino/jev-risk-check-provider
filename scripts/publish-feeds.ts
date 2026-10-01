// Packages the refreshed public-domain/DBAD feeds for the Worker's runtime refresh
// (deploy/fresh-feeds.ts). The scheduled workflow (.github/workflows/feeds.yml)
// regenerates src/data with update-ofac.ts and update-threat-feeds.ts, runs the
// tests, then publishes this directory as the single commit of the `feeds` branch.
//
//   npx tsx scripts/publish-feeds.ts feeds-out
//
// ScamSniffer (GPL) data is never published here: it stays in the operator's KV.
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { OFAC_SDN_ADDRESSES, OFAC_SDN_META } from "../src/data/ofac-sdn.js";
import { METAMASK_ALLOWLIST, METAMASK_FEED_META } from "../src/data/threat-feeds.js";

export const FEEDS_FORMAT = 1;

const sha256 = (data: Uint8Array | string): string => createHash("sha256").update(data).digest("hex");

function main(): void {
  const out = process.argv[2] ?? "feeds-out";
  mkdirSync(out, { recursive: true });
  const bin = readFileSync(new URL("../src/data/metamask-phishing.bin", import.meta.url));
  const mmJson = JSON.stringify({ meta: METAMASK_FEED_META, allowlist: METAMASK_ALLOWLIST });
  const ofacJson = JSON.stringify({ meta: OFAC_SDN_META, rows: OFAC_SDN_ADDRESSES });
  writeFileSync(join(out, "metamask-phishing.bin"), bin);
  writeFileSync(join(out, "metamask.json"), mmJson);
  writeFileSync(join(out, "ofac-sdn.json"), ofacJson);
  const manifest = {
    format: FEEDS_FORMAT,
    generated_at: new Date().toISOString(),
    metamask: { as_of: METAMASK_FEED_META.as_of, commit: METAMASK_FEED_META.commit, entries: bin.byteLength / 8, bin_sha256: sha256(bin), json_sha256: sha256(mmJson) },
    // xml_sha256: the SDN.XML the snapshot was built from (the artifact relying parties can fetch and recompute).
    ofac: { publish_date: OFAC_SDN_META.publish_date, addresses: OFAC_SDN_ADDRESSES.length, json_sha256: sha256(ofacJson), xml_sha256: OFAC_SDN_META.sha256 },
  };
  writeFileSync(join(out, "manifest.json"), JSON.stringify(manifest, null, 2));
  writeFileSync(
    join(out, "README.md"),
    [
      "# x402check feeds",
      "",
      "Generated daily by `.github/workflows/feeds.yml` from the `main` branch scripts. The x402check Worker reads these files at runtime and verifies each against `manifest.json` (SHA-256, entry counts) before use; if anything fails it keeps the snapshot embedded at deploy time.",
      "",
      "- `metamask-phishing.bin`, `metamask.json`: derived from MetaMask eth-phishing-detect (DBAD-1.2; see THIRD_PARTY_NOTICES.md on `main`).",
      "- `ofac-sdn.json`: digital currency addresses from the OFAC SDN list (U.S. Government public data).",
      "",
    ].join("\n"),
  );
  console.log(`feeds → ${out}: MetaMask ${manifest.metamask.as_of} (${manifest.metamask.entries}), OFAC ${manifest.ofac.publish_date} (${manifest.ofac.addresses})`);
}

main();
