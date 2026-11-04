#!/usr/bin/env python3
"""Runs ProVerif on the two smarthome-v2 models and on deliberately broken /
stronger-attacker variants.  Each variant must change exactly the expected
results, which shows the queries are not vacuous; the real models must pass.

    python formal/run_formal.py          (needs `proverif` on PATH; tested with 2.00)
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

HANDSHAKE_QUERIES = [
    # label, regex identifying its RESULT line, expected result for the real model
    ("protocol can complete (CtrlAccepts reachable)", r"not event\(CtrlAccepts", "false"),
    ("protocol can complete (PeerReady reachable)",   r"not event\(PeerReady", "false"),
    ("controller authenticates peer (injective)",     r"inj-event\(CtrlAccepts", "true"),
    ("peer authenticates controller + key confirm",   r"inj-event\(PeerReady", "true"),
    ("forward secrecy controller->peer",              r"not attacker_p1\(s_ctrl", "true"),
    ("forward secrecy peer->controller",              r"not attacker_p1\(s_peer", "true"),
    ("anonymity: identity never revealed",            r"not attacker\(good_id", "true"),
]

GUESSING_QUERIES = [
    ("no offline PIN guessing with stolen config",    r"Weak secret pin", "true"),
]

KDF = "kdf(psk, es, ee, tr, "

HANDSHAKE_VARIANTS = {
    "broken: no ephemeral DH (keys from PSK + static DH only)": (
        [(KDF, "kdf(psk, es, es, tr, ")],
        {"forward secrecy controller->peer": "false",
         "forward secrecy peer->controller": "false"}),
    "broken: controller does not check FINISH": (
        [("  if f = mac(kmp, tagPEER) then\n", "")],
        {"controller authenticates peer (injective)": "false"}),
    "broken: peer does not check READY": (
        [("  let (=tagREADY, conf: bitstring) = sdec(ready, kc2p) in\n"
          "  if conf = mac(kmc, tagCTRL) then\n", "")],
        {"peer authenticates controller + key confirm": "false"}),
    "broken: identity sent in clear (v1 behaviour)": (
        [("let idct = senc(id, kid(es, np, xp)) in", "let idct = id in"),
         ("let id = sdec(idct, kid(es, np, xp)) in", "let id = idct in")],
        {"anonymity: identity never revealed": "false"}),
    "stronger attacker: good_id and its PSK known from the start": (
        [("out(c, psk_bad);", "out(c, psk_bad); out(c, (psk_good, good_id));")],
        {"controller authenticates peer (injective)": "false",
         "peer authenticates controller + key confirm": "true"}),
    "broken: PSK leaked AND static DH es dropped from the key schedule": (
        [("out(c, psk_bad);", "out(c, psk_bad); out(c, (psk_good, good_id));"),
         (KDF, "kdf(psk, ee, ee, tr, ")],
        {"peer authenticates controller + key confirm": "false"}),
}

GUESSING_VARIANTS = {
    "broken: controller proves first (MAC in CHALLENGE, as in v1)": (
        [("  out(c, (nc, yc));\n", "  out(c, (nc, yc, mac(kmc, tagCTRL)));\n"),
         ("in(c, (nc: bitstring, yc: bitstring));",
          "in(c, (nc: bitstring, yc: bitstring, cm: bitstring));")],
        {"no offline PIN guessing with stolen config": "false"}),
    "broken: static DH es dropped from the key schedule": (
        [(KDF, "kdf(psk, ee, ee, tr, ")],
        {"no offline PIN guessing with stolen config": "false"}),
}

MODELS = [
    ("smarthome_handshake.pv", HANDSHAKE_QUERIES, HANDSHAKE_VARIANTS),
    ("stolen_config.pv", GUESSING_QUERIES, GUESSING_VARIANTS),
]


def run(source_text, queries):
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "m.pv")
        with open(path, "w") as f:
            f.write(source_text)
        out = subprocess.run(["proverif", path], capture_output=True, text=True,
                             timeout=600).stdout
    results = {}
    for label, regex, _ in queries:
        for line in out.splitlines():
            if re.match(r"RESULT\s+" + regex, line):
                results[label] = line.rstrip(".").rsplit(" ", 1)[-1]
                break
        else:
            results[label] = "NOT-DECIDED"
    return results


def main():
    if not shutil.which("proverif"):
        sys.exit("proverif not found on PATH")
    ok = True
    for filename, queries, variants in MODELS:
        model = open(os.path.join(HERE, filename)).read()
        print("== real model: %s ==" % filename)
        res = run(model, queries)
        for label, _, expected in queries:
            good = res[label] == expected
            ok &= good
            print("  %-48s %-6s %s" % (label, res[label], "ok" if good else "UNEXPECTED"))
        for name, (edits, expected_results) in variants.items():
            text = model
            for old, new in edits:
                if old not in text:
                    sys.exit("variant edit not applicable: %r" % old)
                text = text.replace(old, new)
            print("== %s ==" % name)
            res = run(text, queries)
            for label, expected in expected_results.items():
                good = res[label] == expected
                ok &= good
                note = "ok" if not good else (
                    "attack found, as intended" if expected == "false" else "still holds")
                print("  %-48s %-6s %s" % (label, res[label], note if good else "UNEXPECTED"))
    print("\nALL AS EXPECTED" if ok else "\nMISMATCH")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
