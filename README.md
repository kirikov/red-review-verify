# Red Review: verify a delivery

Red Review runs code reviews and red-team tests of AI agents inside an Intel TDX confidential VM (dstack on Phala Cloud). Every delivery carries `evidence.zip`, `cvm-attestation.json` and `bundle-manifest.json`. This repository is the public reference you check them against. Its history is the record of every release.

## Check a bundle

```sh
git clone https://github.com/kirikov/red-review-verify && cd red-review-verify
cargo install dcap-qvl-cli          # Intel quote-chain check; without it the result is UNVERIFIED
unzip evidence.zip -d bundle
python3 verify-bundle.py bundle --reference hashes.json
```

PASS means all of these hold:

1. Every file in the bundle matches `bundle-manifest.json`.
2. The TDX quote's `report_data` is the SHA-256 of that manifest.
3. The quote is signed by Intel's chain (dcap-qvl), with an up-to-date TCB.
4. The event log replays to the quote's RTMR3, and the compose hash in it is a release listed in `hashes.json`.
5. The VM's OS measurements (MRTD, RTMR0-2) are those of that release's dstack image.
6. For a code review: NEAR AI's attestation record is present and every model completion is signature-verified.

The manifest names the assignment, the repository and the commit. Compare them with your job.

What PASS does not prove: in a code review, the reviewer works inside a container built from your own Dockerfile, so the content of `out/` is only as trustworthy as that image. In a red-team test, the model calls are not signed one by one; the quote covers the result files.

## Releases

`hashes.json` lists each release: the compose hash, the runner image digest and the dstack OS measurements. `releases/<tag>/` holds the compose file and the app-compose document. Check a compose hash yourself:

```sh
sha256sum releases/v29/app-compose.json        # = compose_hash in hashes.json
python3 -c "import json;print(json.load(open('releases/v29/app-compose.json'))['docker_compose_file'])" | diff - releases/v29/docker-compose.market.yml
```

The compose pins the runner image by digest and carries the egress allowlist.

Listings: https://market.near.ai/a/red-review (code review, prompt red-team) and https://market.near.ai/a/red-review-agent (red-team of your agent's container).
