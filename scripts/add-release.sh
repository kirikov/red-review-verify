#!/bin/sh
# Records the running release: app-compose, compose file and measurements of a CVM.
#   scripts/add-release.sh <tag> <cvm-id> <compose-file>   (needs the phala CLI and its token)
# FEATURES (comma-separated, default out-provenance) lists what bundles of this release must carry;
# verify-bundle.py enforces each one it knows.
set -eu
tag=$1; cvm=$2; compose=$3
mkdir -p "releases/$tag"
# ATT=<file> uses a saved attestation instead (GET /api/v1/cvms/<vm uuid>/attestation): the CLI
# resolves a CVM to its app id, which is ambiguous once a replica shares it.
att=${ATT:-/tmp/rr-att.json}
[ -n "${ATT:-}" ] || phala cvms attestation "$cvm" --json > "$att"
FEATURES=${FEATURES-out-provenance} python3 - "$tag" "$compose" "$att" <<'PY'
import hashlib, json, os, sys, datetime
tag, compose, att = sys.argv[1:4]
a = json.load(open(att))
def find(o, k):
    if isinstance(o, dict):
        if k in o: return o[k]
        for v in o.values():
            r = find(v, k)
            if r is not None: return r
    if isinstance(o, list):
        for v in o:
            r = find(v, k)
            if r is not None: return r
tcb = find(a, "tcb_info")
ac = tcb["app_compose"]
open(f"releases/{tag}/app-compose.json", "w").write(ac)
open(f"releases/{tag}/docker-compose.market.yml", "w").write(json.loads(ac)["docker_compose_file"])
h = hashlib.sha256(ac.encode()).hexdigest()
ref = json.load(open("hashes.json"))
ref["releases"] = [r for r in ref["releases"] if r["tag"] != tag]
ref["releases"].insert(0, {"tag": tag, "date": datetime.date.today().isoformat(), "compose_hash": h,
                           "os": {k: tcb[k] for k in ("mrtd", "rtmr0", "rtmr1", "rtmr2")},
                           "features": [f for f in os.environ.get("FEATURES", "").split(",") if f]})
json.dump(ref, open("hashes.json", "w"), indent=1)
print(tag, h)
PY
