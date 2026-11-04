"""provision.py - generates pre-shared keys and per-party config files.

Run once:  python provision.py            (writes ./config/*.json)
In a real product this happens at pairing/manufacturing time.
"""
import argparse
import getpass
import json
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from common import (MIN_STEP_UP_PIN_LENGTH, new_static_keypair, wrap_user_secrets,
                    write_json_secure)

DEVICES = {"light1": "light", "door1": "lock"}
USERS = {  # user -> {device: allowed commands}
    "hari": {"light1": ["TURN_ON", "TURN_OFF", "STATUS"],
             "door1": ["LOCK", "UNLOCK", "STATUS"]},
    "guest": {"light1": ["TURN_ON", "TURN_OFF", "STATUS"],
              "door1": []},
}


def make_user_config(uid, acl, addr, pin, controller_public, devices=None):
    """Returns (controller-side record, user config).  The user config holds the PSK and
    Ed25519 seed only in PIN-wrapped form and contains no public key, so nothing in the
    file can confirm a PIN guess offline."""
    psk = os.urandom(32)
    signing_private = Ed25519PrivateKey.generate()
    public_hex = signing_private.public_key().public_bytes_raw().hex()
    device_types = devices or DEVICES
    user_config = {"user_id": uid,
                   "controller": dict(addr),
                   "controller_public_key": controller_public,
                   "devices": {did: dtype for did, dtype in device_types.items()
                               if acl.get(did)}}
    user_config.update(wrap_user_secrets(psk, signing_private.private_bytes_raw(), pin))
    return ({"key": psk.hex(), "allowed": acl, "signing_public_key": public_hex},
            user_config)


def make_config(host="127.0.0.1", port=9000, pin="demo-pin-1234", pins=None):
    static_private, static_public = new_static_keypair()
    ctrl = {"host": host, "port": port, "static_private_key": static_private,
            "users": {}, "devices": {}}
    addr = {"host": host, "port": port}
    cfg = {"controller": ctrl, "users": {}, "devices": {}}
    for uid, acl in USERS.items():
        user_pin = pins.get(uid, pin) if pins else pin
        ctrl["users"][uid], cfg["users"][uid] = make_user_config(
            uid, acl, addr, user_pin, static_public)
    for did, dtype in DEVICES.items():
        key = os.urandom(32).hex()
        allowed_users = [u for u, a in USERS.items() if a.get(did)]
        allowed_commands = {u: list(a[did]) for u, a in USERS.items() if a.get(did)}
        signing_keys = {u: ctrl["users"][u]["signing_public_key"] for u in allowed_users}
        ctrl["devices"][did] = {"key": key, "type": dtype,
                                "allowed_users": allowed_users,
                                "allowed_commands": allowed_commands,
                                "signing_public_keys": signing_keys}
        cfg["devices"][did] = {"device_id": did, "type": dtype, "key": key,
                               "controller": dict(addr),
                               "controller_public_key": static_public,
                               "allowed_users": allowed_users,
                               "allowed_commands": allowed_commands,
                               "signing_public_keys": signing_keys}
    return cfg


def write_config(out="config", **kw):
    cfg = make_config(**kw)
    os.makedirs(out, exist_ok=True)
    files = {"controller.json": cfg["controller"]}
    files.update({"user_%s.json" % k: v for k, v in cfg["users"].items()})
    files.update({"device_%s.json" % k: v for k, v in cfg["devices"].items()})
    for name, data in files.items():
        path = os.path.join(out, name)
        write_json_secure(path, data)
        print("wrote", path)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="config")
    ap.add_argument("--port", type=int, default=9000)
    a = ap.parse_args()
    pins = {}
    for user_id in USERS:
        pin = getpass.getpass("Set PIN for %s (8+ characters): " % user_id)
        confirm = getpass.getpass("Confirm PIN for %s: " % user_id)
        if len(pin) < MIN_STEP_UP_PIN_LENGTH or pin != confirm:
            ap.error("PINs must be at least 8 characters and entries must match")
        pins[user_id] = pin
    write_config(a.out, port=a.port, pins=pins)
