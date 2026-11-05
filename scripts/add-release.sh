#!/bin/sh
# Records the running release: app-compose, compose file and measurements of a CVM.
#   scripts/add-release.sh <tag> <cvm-id> <compose-file>   (needs the phala CLI and its token)
set -eu
tag=$1; cvm=$2; compose=$3
mkdir -p "releases/$tag"
phala cvms attestation "$cvm" --json > /tmp/rr-att.json
python3 - "$tag" "$compose" <<'PY'
import hashlib, json, sys, datetime
tag, compose = sys.argv[1:3]
a = json.load(open("/tmp/rr-att.json"))
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
                           "os": {k: tcb[k] for k in ("mrtd", "rtmr0", "rtmr1", "rtmr2")}})
json.dump(ref, open("hashes.json", "w"), indent=1)
print(tag, h)
PY
