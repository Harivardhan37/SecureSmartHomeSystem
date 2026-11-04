#!/usr/bin/env python3
"""Separate-process smoke run: controller + 2 devices + CLI users, like a real deployment.

    python scripts/live_smoke.py

Starts every component as its own OS process in a temporary directory, runs real CLI
commands (PIN login, PIN step-up UNLOCK, wrong PINs, a stolen-config guessing attack),
then verifies the audit chain and the signed command evidence and prints the
owner-notification file.  Exit status is non-zero if any expectation fails.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT = 9781
PIN = "live-run-pin-1"
failures = []


def clean(text):
    return "\n".join(l for l in text.splitlines()
                     if "Warning" not in l and "fallback_getpass" not in l).strip()


def run_user(work, user, cmds, stdin=PIN + "\n"):
    argv = [sys.executable, "user.py", "config/user_%s.json" % user]
    for c in cmds:
        argv += ["--cmd", c]
    out = subprocess.run(argv, cwd=work, input=stdin, capture_output=True, text=True,
                         timeout=30)
    text = clean(out.stdout + out.stderr)
    print("$ python user.py config/user_%s.json %s" % (user, " ".join("--cmd " + c for c in cmds)))
    print(text + "\n")
    return text


def expect(label, condition):
    print("CHECK %-62s %s" % (label, "ok" if condition else "FAILED"))
    if not condition:
        failures.append(label)


def main():
    work = tempfile.mkdtemp(prefix="smarthome_live_")
    procs = []
    try:
        for f in os.listdir(ROOT):
            if f.endswith(".py"):
                shutil.copy(os.path.join(ROOT, f), work)
        subprocess.run([sys.executable, "-c",
                        "import provision; provision.write_config('config', port=%d, pin=%r)"
                        % (PORT, PIN)], cwd=work, capture_output=True, check=True)
        env = dict(os.environ, PYTHONWARNINGS="ignore")

        def start(argv, log):
            p = subprocess.Popen([sys.executable] + argv, cwd=work, env=env,
                                 stdout=open(os.path.join(work, log), "w"),
                                 stderr=subprocess.STDOUT)
            procs.append(p)
            return p
        start(["controller.py", "config/controller.json", "--audit", "audit.log",
               "--notify-file", "notifications.log"], "controller.out")
        time.sleep(1.0)
        start(["device.py", "config/device_light1.json"], "light1.out")
        start(["device.py", "config/device_door1.json"], "door1.out")
        time.sleep(1.5)

        print("# Separate-process smoke run (controller, light1, door1, CLI users)\n")
        t = run_user(work, "hari", ["light1:TURN_ON", "light1:STATUS"])
        expect("hari can turn the light on and read its status", "LIGHT TURNED ON" in t and "STATE IS ON" in t)
        t = run_user(work, "guest", ["door1:STATUS", "light1:TURN_OFF"])
        expect("guest cannot read the door status", "DENIED" in t)
        expect("guest can switch the light", "LIGHT TURNED OFF" in t)
        t = run_user(work, "hari", ["door1:UNLOCK"], stdin=PIN + "\n" + PIN + "\n")
        expect("hari UNLOCK with the correct step-up PIN succeeds", "DOOR UNLOCKED" in t)
        t = run_user(work, "hari", ["door1:UNLOCK"], stdin=PIN + "\nwrong-pin-xx\n")
        expect("hari UNLOCK with a wrong step-up PIN is refused cleanly",
               "incorrect step-up PIN" in t and "Traceback" not in t and "DOOR UNLOCKED" not in t)
        t = run_user(work, "hari", ["light1:STATUS"], stdin="wrong-pin-xx\n")
        expect("login with a wrong PIN is rejected",
               "authentication failed" in t and "STATE IS" not in t and "Traceback" not in t)

        argv = [sys.executable, "attacker.py", "stolen-config", "config/user_guest.json",
                "00000000", "12345678", "password", "guest123", "letmein1", PIN,
                "--port", str(PORT)]
        out = subprocess.run(argv, cwd=work, capture_output=True, text=True, timeout=60)
        print("$ python attacker.py stolen-config config/user_guest.json <6 guesses incl. "
              "the real PIN>")
        print(clean(out.stdout + out.stderr) + "\n")
        expect("stolen config: online guesses throttled, even the real PIN refused",
               "ACCEPTED" not in out.stdout and out.stdout.count("rejected") == 6)
        time.sleep(0.5)

        print("$ python controller.py --verify-audit --audit audit.log")
        v = subprocess.run([sys.executable, "controller.py", "--verify-audit", "--audit",
                            "audit.log"], cwd=work, capture_output=True, text=True, env=env)
        print(clean(v.stdout + v.stderr) + "\n")
        expect("audit hash chain verifies", "hash chain verified" in v.stdout.lower())
        expect("every logged command carries a valid user signature",
               " 0 invalid" in v.stdout and "Signed command evidence:" in v.stdout)

        print("$ cat notifications.log")
        notes = open(os.path.join(work, "notifications.log")).read()
        print(notes)
        expect("owner was notified of the accepted unlock", "UNLOCK_ACCEPTED" in notes)
        expect("owner was alerted to the PIN-guessing attack", "AUTH_GUESSING" in notes)

        print("$ controller console (last lines)")
        print(clean(open(os.path.join(work, "controller.out")).read()).replace(work, "<tmp>"))
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
        shutil.rmtree(work, ignore_errors=True)
    print("\nRESULT: %s" % ("ALL CHECKS PASSED" if not failures else "FAILED: %s" % failures))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
