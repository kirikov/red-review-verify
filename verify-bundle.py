#!/usr/bin/env python3
"""Offline check of one review session's attestation bundle.

    verify-bundle.py <session-dir> [--reference hashes.json|URL] [--compose docker-compose.yml] [--no-dcap]

Checks, in order:
  1. bundle-manifest.json lists every file with a sha256 that matches the file.
  2. cvm-attestation.json's report_data is sha256(bundle-manifest.json).
  3. The TDX quote inside carries that report_data (first 32 bytes; the rest
     zero), and its MRTD/RTMRs are printed.
  4. The quote's RTMR3 replays from the event log, and the compose-hash event
     in that log matches Info.compose_hash (and the given compose file, if any).
     The quote's mr_config_id is 0x01 || compose_hash (dstack's MrConfigId v1),
     so the Intel-signed measurement itself names the compose, not only the
     replayed event log.
  4b. A code review's out/: out-provenance.json (written by rts outside the
     buyer's image) must name verdict.json and findings.md as the reviewer's
     own writes. Required for releases that list the "out-provenance" feature.
  5. attestation.json (NEAR AI) has status "verified", and every inference
     line is signature-verified.
  6. The quote's signature chain, via `dcap-qvl verify` (cargo install
     dcap-qvl-cli; collateral from Phala's PCCS): TCB status must be UpToDate or
     SWHardeningNeeded, and the measurements it reports must equal the parsed
     ones. Skipped with a warning when dcap-qvl is not installed; --no-dcap
     skips it on purpose (then the run is PASS (unsigned)).

Exit 1 on the first failed check.
"""
import hashlib, json, os, shutil, subprocess, sys, tempfile

# The published reference: every released compose hash and the dstack OS measurements it runs on.
# Kept in a public git repository (history = audit trail) and served by GitHub Pages.
REFERENCE_URL = "https://kirikov.github.io/red-review-verify/hashes.json"
EXPECTED_COMPOSE_HASHES = set(filter(None, os.environ.get("RR_EXPECTED_COMPOSE_HASHES", "").split(",")))
EXPECTED_OS = []
FEATURES = {}  # compose hash -> the release's features, e.g. {"out-provenance"}


def load_reference(where):
    """hashes.json from a path or URL: {"releases": [{"compose_hash", "os": {"mrtd","rtmr0","rtmr1","rtmr2"}, ...}]}."""
    import urllib.request
    if where.startswith("https://"):
        with urllib.request.urlopen(where, timeout=20) as r:
            doc = json.loads(r.read())
    else:
        doc = json.load(open(where))
    rel = doc.get("releases") or []
    EXPECTED_COMPOSE_HASHES.update(x["compose_hash"] for x in rel if x.get("compose_hash"))
    EXPECTED_OS.extend(x["os"] for x in rel if x.get("os"))
    FEATURES.update({x["compose_hash"]: set(x.get("features") or []) for x in rel if x.get("compose_hash")})
    return len(rel)


def die(msg):
    print("FAIL:", msg); sys.exit(1)

def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def replay_rtmr(digests):
    # As dstack's SDK: sha384(mr || digest), digests shorter than 48 bytes zero-padded.
    mr = bytes(48)
    for d in digests:
        mr = hashlib.sha384(mr + bytes.fromhex(d).ljust(48, b"\0")).digest()
    return mr.hex()

def main():
    args = sys.argv[1:]
    if not args: die(__doc__)
    d = args[0]
    compose = args[args.index("--compose") + 1] if "--compose" in args else None
    dcap = "--no-dcap" not in args
    reference = args[args.index("--reference") + 1] if "--reference" in args else REFERENCE_URL
    if not compose:
        try:
            n = load_reference(reference)
            print(f"ok  published reference loaded: {n} release(s) from {reference}")
        except Exception as e:
            print(f"warn: could not load the published reference {reference}: {type(e).__name__}")

    # 1. manifest vs files
    mpath = os.path.join(d, "bundle-manifest.json")
    manifest = json.load(open(mpath))
    if manifest.get("schema") != "red-review/bundle@1": die("unknown manifest schema")
    for rel, meta in manifest["files"].items():
        p = os.path.join(d, rel)
        if not os.path.isfile(p): die(f"manifest lists missing file {rel}")
        if sha256_file(p) != meta["sha256"]: die(f"sha256 mismatch for {rel}")
    print(f"ok  manifest: {len(manifest['files'])} files match")

    # 2. report_data
    att = json.load(open(os.path.join(d, "cvm-attestation.json")))
    if att.get("schema") != "red-review/cvm-attestation@1": die("unknown cvm-attestation schema")
    want = sha256_file(mpath)
    if att["report_data"] != want: die("report_data is not sha256(bundle-manifest.json)")
    print("ok  report_data = sha256(manifest)")

    # 3. quote body (TDX quote v4/v5: 48-byte header, TD report body follows)
    q = bytes.fromhex(att["quote"]["quote"])
    version = int.from_bytes(q[0:2], "little")
    tee = int.from_bytes(q[4:6], "little")
    if version not in (4, 5) or tee != 0x81: die(f"not a TDX quote (version {version}, tee type {tee:#x})")
    body = q[48:]
    if version == 5:
        body = q[48 + 6:]  # v5 adds a 6-byte body descriptor (type u16, size u32)
    fields = {}
    off = 0
    for name, size in (("tee_tcb_svn", 16), ("mr_seam", 48), ("mr_signer_seam", 48), ("seam_attributes", 8),
                       ("td_attributes", 8), ("xfam", 8), ("mr_td", 48), ("mr_config_id", 48), ("mr_owner", 48),
                       ("mr_owner_config", 48), ("rtmr0", 48), ("rtmr1", 48), ("rtmr2", 48), ("rtmr3", 48),
                       ("report_data", 64)):
        fields[name] = body[off:off + size]; off += size
    rd = fields["report_data"]
    if rd[:32].hex() != want or any(rd[32:]): die("quote report_data does not carry sha256(manifest)")
    print(f"ok  quote v{version}: report_data bound; mr_td {fields['mr_td'].hex()[:16]}…")
    for i in range(4):
        print(f"    rtmr{i} {fields[f'rtmr{i}'].hex()}")

    # 4. event log: RTMR3 replay + compose hash. GetQuote's event_log carries
    # the events without digests on dstack 0.5; Info's tcb_info.event_log has
    # them. Both must describe the same events, and the digests must replay to
    # the quote's RTMR3.
    quote_events = json.loads(att["quote"]["event_log"]) if isinstance(att["quote"]["event_log"], str) else att["quote"]["event_log"]
    tcb = att["info"].get("tcb_info") or {}
    if isinstance(tcb, str): tcb = json.loads(tcb)
    events = tcb.get("event_log") or quote_events
    # dstack's GetQuote log omits firmware payloads and app-event digests;
    # the sequence of (register, type, name) must still be identical, and the
    # app events' payloads (compose-hash, app-id, ...) must agree.
    key = lambda e: (e.get("imr"), e.get("event_type"), e.get("event"), e.get("event_payload") if e.get("event") else None)
    if [key(e) for e in events] != [key(e) for e in quote_events]: die("Info and GetQuote event logs differ")
    digests = [e.get("digest", "") for e in events if e.get("imr") == 3]
    if not all(digests): die("event log has no digests to replay")
    rtmr3 = replay_rtmr(digests)
    if rtmr3 != fields["rtmr3"].hex(): die("RTMR3 does not replay from the event log")
    compose_events = [e for e in events if e.get("event") == "compose-hash"]
    info_hash = att["info"].get("compose_hash") or tcb.get("compose_hash")
    if not compose_events: die("no compose-hash event in the event log")
    logged = compose_events[0].get("event_payload")
    if info_hash and logged != info_hash: die(f"compose-hash event {logged} != Info.compose_hash {info_hash}")
    print(f"ok  RTMR3 replays; compose_hash {logged}; app_id {att['info'].get('app_id')}")
    mr_config = fields["mr_config_id"].hex()
    if mr_config != ("01" + logged).ljust(96, "0"): die(f"mr_config_id {mr_config[:20]}… is not 0x01||compose_hash")
    print("ok  mr_config_id = 0x01 || compose_hash")
    if compose:
        # dstack hashes the app-compose document it generated, which embeds this
        # compose file; compare the embedded docker_compose_file text instead.
        app_compose = tcb.get("app_compose")
        if not app_compose:
            die("--compose given but the bundle carries no app_compose to compare")
        # The info block is not signed: app_compose counts only if it hashes to the measured compose hash.
        if hashlib.sha256(app_compose.encode()).hexdigest() != logged:
            die("app_compose in the bundle does not hash to the measured compose hash")
        embedded = json.loads(app_compose).get("docker_compose_file", "")
        if embedded.strip() != open(compose).read().strip(): die("the attested app-compose embeds a different compose file")
        print(f"ok  attested compose equals {compose} (sha256 of app_compose = measured compose hash)")
    else:
        if not EXPECTED_COMPOSE_HASHES:
            print(f"UNVERIFIED: the published reference ({reference}) could not be loaded, so which software ran is not checked; "
                  "pass --reference hashes.json from a clone of github.com/kirikov/red-review-verify")
            sys.exit(2)
        if logged not in EXPECTED_COMPOSE_HASHES:
            die(f"compose hash {logged} is not a published Red Review release")
        print("ok  compose hash is a published Red Review release")
    if EXPECTED_OS:
        os_now = {k: fields[k].hex() for k in ("mr_td", "rtmr0", "rtmr1", "rtmr2")}
        if not any(os_now == {"mr_td": o["mrtd"], "rtmr0": o["rtmr0"], "rtmr1": o["rtmr1"], "rtmr2": o["rtmr2"]} for o in EXPECTED_OS):
            die("the VM's OS measurements (MRTD, RTMR0-2) are not those of a published release")
        print("ok  OS measurements (MRTD, RTMR0-2) match a published release")

    # 4b. who wrote out/: the reviewer's recorded writes, not the buyer's image
    is_review = manifest.get("kind", "review") != "redteam"
    if is_review:
        prov_rel = "out-provenance.json"
        if prov_rel in manifest["files"]:
            prov = json.load(open(os.path.join(d, prov_rel)))
            files = prov.get("files") or {}
            for rel in ("verdict.json", "findings.md"):
                if f"out/{rel}" in manifest["files"] and (files.get(rel) or {}).get("source") != "reviewer":
                    die(f"out/{rel} is not the reviewer's own write (source {(files.get(rel) or {}).get('source')})")
            differed = prov.get("guestCopyDiffered") or []
            print("ok  out/verdict.json and out/findings.md are the reviewer's recorded writes"
                  + (f"; the image rewrote its copy of {len(differed)} file(s), discarded: {', '.join(differed[:8])}" if differed else ""))
        elif "out-provenance" in FEATURES.get(logged, set()):
            die("this release records who wrote out/, but the bundle has no out-provenance.json")
        else:
            print("warn: this release predates out-provenance.json; out/ is only as trustworthy as the reviewed image")

    # 5. NEAR AI attestation + signatures (a red-team bundle has none: its model calls went
    #    through the test broker and are not individually signed; the quote still covers the files)
    if not os.path.exists(os.path.join(d, "attestation.json")):
        if is_review:
            die("a code-review bundle without NEAR's attestation record: the review's inference is unattested")
        print("ok  no NEAR attestation record in this bundle (a red-team run); the quote binds the result files")
        near = {"status": "verified"}
        lines = []
    else:
        near = json.load(open(os.path.join(d, "attestation.json")))
        if near.get("status") != "verified": die(f"NEAR attestation status {near.get('status')}: {near.get('reason')}")
        lines = [json.loads(l) for l in open(os.path.join(d, "inference.jsonl")) if l.strip()] if os.path.exists(os.path.join(d, "inference.jsonl")) else []
        bad = [l for l in lines if not str(l.get("result", "")).startswith("verified")]
        if bad: die(f"{len(bad)} of {len(lines)} inference lines are not signature-verified (first: {bad[0].get('result')})")
        print(f"ok  NEAR attestation verified ({near.get('inference', '?')} mode); {len(lines)} inference lines signature-verified")
    # 5b. the precise pass (ocr scan), when the bundle has one: its own NEAR AI verification record
    scan_path = os.path.join(d, "ocr", "ocr-scan.json")
    if os.path.exists(scan_path):
        try:
            ver = (json.load(open(scan_path)).get("llm") or {}).get("verification") or {}
        except ValueError:
            die("ocr/ocr-scan.json is not JSON")
        # request_failed = an HTTP/transport error on some call, not a failed verification
        if ver.get("failed") or not ver.get("verified"):
            die(f"precise pass: NEAR AI verification {ver.get('status')} ({ver.get('failed')} failed, {ver.get('verified')} verified)")
        print(f"ok  precise pass (ocr scan): {ver.get('verified')} completions verified, E2EE {'on' if ver.get('e2ee') else 'off'}, {ver.get('verification_level')}")

    # 6. quote signature chain (Intel PCK -> QE -> quote) via dcap-qvl
    if not dcap:
        print("UNVERIFIED (--no-dcap: the quote's certificate chain was not checked; everything above is self-consistency)")
        sys.exit(2)
    if not shutil.which("dcap-qvl"):
        print("UNVERIFIED: dcap-qvl not installed (cargo install dcap-qvl-cli); without it the quote is not proven to come from Intel hardware")
        sys.exit(2)
    with tempfile.NamedTemporaryFile("w", suffix=".hex", delete=False) as f:
        f.write(att["quote"]["quote"].strip()); qpath = f.name
    try:
        r = subprocess.run(["dcap-qvl", "verify", "--hex", qpath], capture_output=True, text=True, timeout=120)
    finally:
        os.unlink(qpath)
    out = r.stdout.strip().splitlines()
    report = next((json.loads(l) for l in out if l.startswith("{")), None)
    if r.returncode != 0 or not report or "Quote verified" not in (r.stdout + r.stderr): die(f"dcap-qvl: {r.stdout.strip() or r.stderr.strip()}")
    status = report.get("status")
    if status not in ("UpToDate", "SWHardeningNeeded"): die(f"TCB status {status} (advisories {report.get('advisory_ids')})")
    td = report["report"].get("TD10") or report["report"].get("TD15") or {}
    for ours, theirs in (("mr_td", "mr_td"), ("rtmr0", "rt_mr0"), ("rtmr1", "rt_mr1"), ("rtmr2", "rt_mr2"), ("rtmr3", "rt_mr3"), ("report_data", "report_data")):
        if fields[ours].hex() != td.get(theirs): die(f"dcap-qvl reports a different {theirs}")
    adv = report.get("advisory_ids") or []
    print(f"ok  quote signature chain verified by dcap-qvl; TCB {status}" + (f" (advisories {', '.join(adv)})" if adv else ""))
    for k in ("assignment", "repo", "commit", "target", "model"):
        if manifest.get(k):
            print(f"    {k}: {manifest[k]}")
    print("PASS")

if __name__ == "__main__":
    main()
