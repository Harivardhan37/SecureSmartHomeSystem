"""demo.py - one-command end-to-end demonstration of the protocol and all attacks.

    python demo.py            summary of each scenario
    python demo.py --verbose  also show controller/device/attacker logs
"""
import argparse
import json
import os
import shutil
import socket
import tempfile
import time

import attacker as atk
import controller as ctl
import device as dev
import provision
import user as usr
from common import ProtocolError, send_frame, unwrap_user_secrets

PIN = "demo-pin-1234"


class Testbed:
    """Starts controller + both devices in-process on an ephemeral port."""

    def __init__(self, quiet=True):
        self.quiet = quiet
        self.cfg = provision.make_config(pin=PIN)
        c = self.cfg["controller"]
        self.workdir = tempfile.mkdtemp(prefix="smarthome_demo_")
        self.audit_path = os.path.join(self.workdir, "audit.log")
        self.ctrl = ctl.Controller(c, port=0, quiet=quiet, audit_path=self.audit_path).start()
        self.controller_public = bytes.fromhex(self.ctrl.public_key_hex)
        self.devices = {}
        for did, dcfg in self.cfg["devices"].items():
            self.devices[did] = dev.Device(dcfg, port=self.ctrl.port, quiet=quiet).start()
        wait(lambda: len(self.ctrl.registry) == len(self.devices))
        self.captured_frame = None

    def user(self, name, port=None):
        cfg = dict(self.cfg["users"][name])
        return usr.UserClient(cfg, port=port or self.ctrl.port,
                              pin_callback=lambda: PIN).connect()

    def count(self, kind, since=0):
        return sum(1 for k, _ in self.ctrl.events[since:] if k == kind)

    def stop(self):
        self.ctrl.stop()
        for d in self.devices.values():
            d.stop()
        shutil.rmtree(self.workdir, ignore_errors=True)


def wait(pred, timeout=3.0):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.02)
    return False


def R(name, attack, expected, observed, passed):
    return dict(name=name, attack=attack, expected=expected, observed=observed, passed=bool(passed))


# ------------------------------------------------------------- scenarios
def s_legit(tb):
    u = tb.user("hari")
    r1 = u.command("light1", "TURN_ON")
    r2 = u.command("door1", "UNLOCK")
    u.close()
    ok = r1["status"] == "OK" and r2["status"] == "OK" and \
        tb.devices["light1"].state == "ON" and tb.devices["door1"].state == "UNLOCKED"
    u = tb.user("hari"); u.command("door1", "LOCK"); u.close()
    return R("Legitimate use", "none (normal operation)",
             "mutual auth succeeds, commands executed",
             "light=%s, door unlocked then relocked" % tb.devices["light1"].state, ok)


def s_eavesdrop(tb):
    px = atk.Proxy(("127.0.0.1", tb.ctrl.port), "eavesdrop", quiet=tb.quiet).start()
    u = tb.user("hari", port=px.port)
    u.command("light1", "TURN_OFF"); u.command("door1", "STATUS"); u.close()
    time.sleep(0.2)
    data = [f for _, f in px.captured if f.get("type") == "DATA"]
    leaked = any(w in bytes.fromhex(f["ct"]) for f in data for w in (b"TURN_OFF", b"light1", b"door1", b"STATUS"))
    tb.captured_frame = next(f for d, f in px.captured if d == "C->S" and f.get("type") == "DATA")
    px.stop()
    return R("Eavesdropping", "passive sniffing of all traffic",
             "attacker sees only ciphertext",
             "%d frames captured, command/device names found in them: %s" % (len(px.captured), leaked),
             data and not leaked)


def s_replay(tb):
    px = atk.Proxy(("127.0.0.1", tb.ctrl.port), "replay", quiet=tb.quiet).start()
    before, mark = len(tb.devices["light1"].history), len(tb.ctrl.events)
    u = tb.user("hari", port=px.port)
    r = u.command("light1", "TURN_ON"); u.close()
    seen = wait(lambda: tb.count("REPLAY", mark) >= 1)
    n = len(tb.devices["light1"].history) - before
    px.stop()
    return R("Replay attack", "attacker re-injects a captured command packet",
             "duplicate rejected, command runs exactly once",
             "REPLAY detected: %s, device executed command %d time(s)" % (seen, n),
             r["status"] == "OK" and seen and n == 1)


def s_tamper(tb):
    px = atk.Proxy(("127.0.0.1", tb.ctrl.port), "tamper", quiet=tb.quiet).start()
    before, mark = len(tb.devices["door1"].history), len(tb.ctrl.events)
    u = tb.user("hari", port=px.port)
    try:
        u.command("door1", "UNLOCK"); got = "response received (!!)"
    except (ProtocolError, OSError) as e:
        got = "session aborted"
    u.close()
    seen = wait(lambda: tb.count("TAMPER", mark) >= 1)
    n = len(tb.devices["door1"].history) - before
    px.stop()
    return R("Message modification", "attacker flips a bit in a command in transit",
             "integrity check fails, command dropped",
             "TAMPER detected: %s, %s, device executed %d command(s)" % (seen, got, n),
             seen and n == 0)


def s_fake_user(tb):
    mark = len(tb.ctrl.events)
    a = atk.fake_peer(("127.0.0.1", tb.ctrl.port), "user", "hari",      # real ID, no key
                      tb.controller_public)
    b = atk.fake_peer(("127.0.0.1", tb.ctrl.port), "user", "mallory",   # unknown ID
                      tb.controller_public)
    seen = wait(lambda: tb.count("AUTH_FAIL", mark) >= 2)
    return R("Fake user", "login as 'hari' without key / as unknown user",
             "authentication fails, identical error for both",
             "known-ID: %s | unknown-ID: %s" % (a, b), seen and a == b and "rejected" in a)


def s_fake_device(tb):
    mark = len(tb.ctrl.events)
    a = atk.fake_peer(("127.0.0.1", tb.ctrl.port), "device", "light1", tb.controller_public)
    wait(lambda: tb.count("AUTH_FAIL", mark) >= 1)
    u = tb.user("hari"); r = u.command("light1", "STATUS"); u.close()
    return R("Fake device", "rogue device registers as 'light1'",
             "rejected; real light1 session untouched",
             "%s; real device still answers: %s" % (a, r["status"]),
             "rejected" in a and r["status"] == "OK")


def s_rogue_controller(tb):
    rc = atk.RogueController().start()
    try:
        tb.user("hari", port=rc.port); got = "ACCEPTED (!!)"
    except ProtocolError as e:
        got = str(e)
    rc.stop()
    return R("Fake controller", "attacker impersonates the controller to the user",
             "user rejects key confirmation (READY) and sends no command",
             got, got == "controller authentication failed")


def s_unauthorized(tb):
    mark = len(tb.ctrl.events)
    u = tb.user("guest")
    r = u.command("door1", "UNLOCK"); u.close()
    seen = wait(lambda: tb.count("CMD_DENIED", mark) >= 1)
    return R("Unauthorized command", "authenticated 'guest' tries UNLOCK on door1",
             "access denied by ACL, door stays locked",
             "status=%s, door=%s" % (r["status"], tb.devices["door1"].state),
             r["status"] == "DENIED" and seen and tb.devices["door1"].state == "LOCKED")


def s_stale(tb):
    mark = len(tb.ctrl.events)
    before = len(tb.devices["door1"].history)
    u = tb.user("hari")
    u.ch.send(u._signed_command("door1", "LOCK", os.urandom(16).hex()),
              _ts=int(time.time()) - 3600)
    seen = wait(lambda: tb.count("STALE", mark) >= 1)
    u.close()
    return R("Delayed / stale message", "valid command held back and delivered an hour late",
             "timestamp check rejects it",
             "STALE detected: %s, device executed %d" % (seen, len(tb.devices["door1"].history) - before),
             seen and len(tb.devices["door1"].history) == before)


def s_cross_session(tb):
    mark = len(tb.ctrl.events)
    before = len(tb.devices["light1"].history)
    u = tb.user("hari")                                  # brand-new session
    send_frame(u.ch.sock, tb.captured_frame)            # packet recorded in an OLD session
    seen = wait(lambda: tb.count("TAMPER", mark) >= 1)
    u.close()
    return R("Cross-session replay", "packet captured earlier is injected into a new session",
             "rejected: session keys differ (fresh nonces + ephemeral DH)",
             "rejected: %s, device executed %d" % (seen, len(tb.devices["light1"].history) - before),
             seen and len(tb.devices["light1"].history) == before)


def s_traceability(tb):
    px = atk.Proxy(("127.0.0.1", tb.ctrl.port), "eavesdrop", quiet=tb.quiet).start()
    for _ in range(2):
        u = tb.user("hari", port=px.port); u.command("light1", "STATUS"); u.close()
    time.sleep(0.2)
    px.stop()
    hellos = [f for d, f in px.captured if d == "C->S" and f.get("type") == "HELLO"]
    wire = json.dumps(hellos).encode()
    leaked = b"hari" in wire or b"hari".hex().encode() in wire or b'"user"' in wire
    linkable = len({f["id"] for f in hellos}) < len(hellos)
    return R("User anonymity / untraceability", "eavesdropper watches hari log in twice",
             "identity never on the wire; two logins cannot be linked",
             "%d HELLOs captured, identity visible: %s, ciphertexts repeat: %s, sizes: %s" % (
                 len(hellos), leaked, linkable, sorted({len(f["id"]) for f in hellos})),
             len(hellos) == 2 and not leaked and not linkable)


def s_leaked_psk_rogue_controller(tb):
    leaked = bytes.fromhex(tb.cfg["controller"]["users"]["hari"]["key"])
    rc = atk.RogueController(leaked_psk=leaked).start()
    try:
        tb.user("hari", port=rc.port); got = "ACCEPTED (!!)"
    except ProtocolError as e:
        got = str(e)
    rc.stop()
    return R("Fake controller with leaked PSK", "attacker knows hari's long-term PSK and "
             "impersonates the controller",
             "still rejected: controller must also prove its static X25519 key",
             got, got == "controller authentication failed")


def s_compromised_controller_forgery(tb):
    light, dc = tb.devices["light1"], tb.ctrl.registry["light1"]
    relayed, original = [], dc.request
    dc.request = lambda body: relayed.append(dict(body)) or original(body)
    u = tb.user("hari"); ok = u.command("light1", "TURN_OFF"); u.close()
    dc.request = original
    signed = next(b for b in relayed if b.get("type") == "COMMAND")
    before = len(light.history)
    unsigned = dc.request({"type": "COMMAND", "device_id": "light1", "command": "TURN_ON",
                           "on_behalf_of": "hari"})
    altered = dc.request(dict(signed, command="TURN_ON"))
    replayed = dc.request(dict(signed))
    executed = len(light.history) - before
    return R("Compromised controller forges / replays", "controller injects an unsigned "
             "TURN_ON for hari, alters a signed one, and replays an old signed one",
             "device verifies hari's own signature and nonce; all three refused",
             "legit=%s; unsigned=%s, altered=%s, replayed=%s; executed %d" % (
                 ok["status"], unsigned["detail"], altered["detail"], replayed["detail"],
                 executed),
             ok["status"] == "OK" and executed == 0 and
             all(r["status"] == "DENIED" for r in (unsigned, altered, replayed)))


def s_non_repudiation(tb):
    u = tb.user("hari"); u.command("light1", "TURN_ON"); u.close()
    time.sleep(0.1)
    result = ctl.Controller.verify_command_evidence(tb.audit_path, tb.ctrl.users)
    forged_path = os.path.join(tb.workdir, "forged_audit.log")
    with open(tb.audit_path) as f, open(forged_path, "w") as out:
        for line in f:
            record = json.loads(line)
            if "evidence" in record:
                record["evidence"]["payload"] = record["evidence"]["payload"].replace(
                    '"TURN_ON"', '"TURN_OFF"')
            out.write(json.dumps(record) + "\n")
    forged = ctl.Controller.verify_command_evidence(forged_path, tb.ctrl.users)
    return R("Repudiation / forged evidence", "hari denies a command; insider edits the "
             "logged command",
             "each logged command carries hari's verifiable signature; edits are detected",
             "genuine evidence verified: %d (invalid %d); edited evidence invalid: %d" % (
                 result["verified"], len(result["invalid"]), len(forged["invalid"])),
             result["verified"] >= 1 and not result["invalid"] and
             len(forged["invalid"]) >= 1)


def s_stolen_config(tb):
    stolen = tb.cfg["users"]["guest"]
    guesses = ["00000000", "12345678", "password", "guest123", "letmein1"]
    offline = len({unwrap_user_secrets(stolen, g)[0] for g in guesses + [PIN]})
    mark = len(tb.ctrl.events)
    results = atk.guess_pins(("127.0.0.1", tb.ctrl.port), stolen, guesses + [PIN])
    locked = results[-1][1] != "ACCEPTED"          # even the right PIN is refused now
    notified = wait(lambda: tb.count("OWNER_NOTIFY", mark) >= 1)
    time.sleep(tb.ctrl.identity_backoff + 0.1)     # lockout is temporary ...
    u = tb.user("guest"); r = u.command("light1", "STATUS"); u.close()   # ... owner gets back in
    return R("Stolen config file + PIN guessing", "attacker copies guest's config and "
             "tries PINs",
             "no offline test; online guesses throttled, owner alerted",
             "%d guesses gave %d distinct plausible keys offline; online: 5 rejected, then "
             "locked (right PIN refused: %s); owner notified: %s; after lockout guest: %s" % (
                 len(guesses) + 1, offline, locked, notified, r["status"]),
             offline == len(guesses) + 1 and
             all(v.startswith("rejected") for _, v in results[:5]) and locked and notified
             and r["status"] == "OK")


SCENARIOS = [s_legit, s_eavesdrop, s_replay, s_tamper, s_fake_user, s_fake_device,
             s_rogue_controller, s_unauthorized, s_stale, s_cross_session,
             s_traceability, s_leaked_psk_rogue_controller, s_compromised_controller_forgery,
             s_non_repudiation, s_stolen_config]


def run_all(tb, verbose=False):
    results = []
    for i, fn in enumerate(SCENARIOS, 1):
        if verbose:
            print("\n--- scenario %d ---" % i)
        r = fn(tb)
        results.append(r)
        print("\n[%d/%d] %s" % (i, len(SCENARIOS), r["name"]))
        print("   attack  :", r["attack"])
        print("   expected:", r["expected"])
        print("   observed:", r["observed"])
        print("   result  :", "✓ PASS" if r["passed"] else "✗ FAIL")
    return results


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args()
    print("=" * 60, "\nSECURE SMART HOME - PROTOCOL & ATTACK DEMONSTRATION\n" + "=" * 60)
    tb = Testbed(quiet=not a.verbose)
    print("controller up on port %d, devices registered: %s" % (tb.ctrl.port, sorted(tb.ctrl.registry)))
    try:
        results = run_all(tb, a.verbose)
    finally:
        tb.stop()
    ok = sum(r["passed"] for r in results)
    print("\n" + "=" * 60, "\nSUMMARY: %d/%d scenarios behaved as designed" % (ok, len(results)))
    raise SystemExit(0 if ok == len(results) else 1)


if __name__ == "__main__":
    main()
