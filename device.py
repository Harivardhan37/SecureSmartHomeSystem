"""device.py - simulated smart device (light or door lock)."""
import argparse
from collections import defaultdict, deque
import json
import os
import socket
import threading
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from common import (DEVICE_TYPES, TS_WINDOW, ProtocolError, close_socket,
                    command_auth_payload, initiator_handshake, write_json_secure)

TRANSITIONS = {  # command -> (new state, message)
    "TURN_ON": ("ON", "LIGHT TURNED ON"), "TURN_OFF": ("OFF", "LIGHT TURNED OFF"),
    "LOCK": ("LOCKED", "DOOR LOCKED"), "UNLOCK": ("UNLOCKED", "DOOR UNLOCKED"),
}
INITIAL = {"light": "OFF", "lock": "LOCKED"}
MAX_SEEN_NONCES = 4096


class Device:
    def __init__(self, cfg, host=None, port=None, quiet=False, config_path=None):
        self.id, self.type = cfg["device_id"], cfg["type"]
        self.key = bytes.fromhex(cfg["key"])
        pinned = cfg.get("controller_public_key")
        self.controller_public = bytes.fromhex(pinned) if pinned else None
        self.addr = (host or cfg["controller"]["host"], port or cfg["controller"]["port"])
        configured_users = cfg.get("allowed_users")
        self.allowed_users = configured_users if isinstance(configured_users, list) else []
        # Per-command ACL enforced by the device itself.  None = legacy config without
        # the field (user-level check only); the controller always sends it on connect.
        configured_commands = cfg.get("allowed_commands")
        self.allowed_commands = (
            {u: list(c) for u, c in configured_commands.items()}
            if isinstance(configured_commands, dict) else None)
        self.signing_public_keys = dict(cfg.get("signing_public_keys", {}))
        self.step_up_challenges = {}
        self.step_up_attempts = defaultdict(deque)
        self.seen_nonces = {}           # nonce -> expiry (device clock), one-use per command
        self.auto_relock_seconds = cfg.get("auto_relock_seconds", 30)
        self._relock_timer = None
        self._relock_generation = 0
        self._state_lock = threading.Lock()
        self.config_path = config_path
        self.state = INITIAL[self.type]
        self.history, self.quiet = [], quiet
        self.sock = self.ch = None
        self._stop = threading.Event()

    def log(self, msg):
        if not self.quiet:
            print("[DEVICE %s] %s" % (self.id, msg), flush=True)

    def start(self):
        self._connect()
        threading.Thread(target=self._run, daemon=True).start()
        return self

    def _connect(self):
        if self.controller_public is None:
            raise ProtocolError("device config has no controller_public_key; re-provision")
        self.sock = socket.create_connection(self.addr, timeout=10)
        try:
            self.ch = initiator_handshake(self.sock, "device", self.id, self.key,
                                          self.controller_public)
        except (ProtocolError, OSError):
            close_socket(self.sock)
            self.sock = self.ch = None
            raise
        self.sock.settimeout(None)
        self.log("authenticated to controller, secure session up")

    def stop(self):
        self._stop.set()
        if self._relock_timer:
            self._relock_timer.cancel()
        if self.sock:
            close_socket(self.sock)

    def _run(self):
        while not self._stop.is_set():
            try:
                self.ch.send(self.execute(self.ch.recv()))
            except (ProtocolError, OSError) as e:
                self.log("session ended: %s" % e)
                if self.sock:
                    close_socket(self.sock)
                    self.sock = self.ch = None
                if self._stop.wait(1):
                    return
                try:
                    self._connect()
                except (ProtocolError, OSError) as reconnect_error:
                    self.log("reconnect failed: %s" % reconnect_error)

    def execute(self, req):
        """Validates and executes one command (all checks are device-side too)."""
        def r(status, detail):
            return {"type": "RESPONSE", "status": status, "detail": detail, "state": self.state}
        if req.get("type") == "HEARTBEAT":
            return r("OK", "alive")
        if req.get("type") == "UPDATE_AUTHZ":
            allowed_users, public_keys = req.get("allowed_users"), req.get("signing_public_keys")
            if not isinstance(allowed_users, list) or not all(
                    isinstance(user, str) for user in allowed_users) \
                    or not isinstance(public_keys, dict):
                return r("ERROR", "invalid authorization update")
            try:
                for user, public_key in public_keys.items():
                    if not isinstance(user, str) or not isinstance(public_key, str) \
                            or len(bytes.fromhex(public_key)) != 32:
                        raise ValueError("invalid signing key")
            except (TypeError, ValueError):
                return r("ERROR", "invalid authorization update")
            commands = req.get("allowed_commands")
            if commands is not None:
                valid = DEVICE_TYPES[self.type]
                if not isinstance(commands, dict) or not all(
                        isinstance(user, str) and isinstance(user_commands, list)
                        and all(isinstance(command, str) and command in valid
                                for command in user_commands)
                        for user, user_commands in commands.items()):
                    return r("ERROR", "invalid authorization update")
                self.allowed_commands = {u: list(c) for u, c in commands.items()}
            self.allowed_users = allowed_users
            for user, public_key in public_keys.items():
                if user in self.signing_public_keys and \
                        self.signing_public_keys[user] != public_key:
                    self.log("IGNORED controller attempt to replace signing key for %s" % user)
            self._save_authorization()
            return r("OK", "authorization updated")

        cmd, user = req.get("command"), req.get("on_behalf_of")
        if req.get("type") == "STEP_UP_CHALLENGE":
            if not isinstance(user, str) or user not in self.allowed_users \
                    or user not in self.signing_public_keys:
                return r("DENIED", "user not authorized for step-up")
            if self.allowed_commands is not None and \
                    "UNLOCK" not in self.allowed_commands.get(user, []):
                return r("DENIED", "user not authorized for step-up")
            now = time.monotonic()
            attempts = self.step_up_attempts[user]
            while attempts and now - attempts[0] >= 60:
                attempts.popleft()
            if len(attempts) >= 5:
                return r("DENIED", "step-up rate limit exceeded")
            attempts.append(now)
            self.step_up_challenges = {
                challenge: value for challenge, value in self.step_up_challenges.items()
                if value[1] > now
            }
            challenge = os.urandom(32).hex()
            self.step_up_challenges[challenge] = (user, now + 30)
            return {"type": "RESPONSE", "status": "OK",
                    "detail": "step-up challenge", "challenge": challenge}

        if req.get("type") != "COMMAND" or req.get("device_id") != self.id:
            return r("ERROR", "wrong device")
        if not isinstance(user, str) or not isinstance(cmd, str):
            return r("ERROR", "malformed command")
        if user not in self.allowed_users:
            self.log("REJECTED %s from %r (not in device allow-list)" % (cmd, user))
            return r("DENIED", "user not authorized on device")
        if cmd not in DEVICE_TYPES[self.type]:
            return r("ERROR", "unsupported command")
        if self.allowed_commands is not None and \
                cmd not in self.allowed_commands.get(user, []):
            self.log("REJECTED %s from %r (command not in device ACL)" % (cmd, user))
            return r("DENIED", "command not authorized on device")
        denial = self._verify_user_signature(user, cmd, req)
        if denial:
            self.log("REJECTED %s from %r (%s)" % (cmd, user, denial))
            return r("DENIED", denial)
        if cmd != "STATUS":
            with self._state_lock:
                self.state, msg = TRANSITIONS[cmd]
                if cmd == "UNLOCK" and self.auto_relock_seconds > 0:
                    if self._relock_timer:
                        self._relock_timer.cancel()
                    self._relock_generation += 1
                    self._relock_timer = threading.Timer(
                        self.auto_relock_seconds, self._auto_relock,
                        args=(self._relock_generation,))
                    self._relock_timer.daemon = True
                    self._relock_timer.start()
                elif cmd == "LOCK":
                    self._relock_generation += 1
                    if self._relock_timer:
                        self._relock_timer.cancel()
                        self._relock_timer = None
        else:
            with self._state_lock:
                msg = "STATE IS " + self.state
        self.history.append((user, cmd))
        self.log("command verified (%s by %s) -> %s" % (cmd, user, msg))
        return r("OK", msg)

    def _now(self):
        """Controller-synchronized time (offset learned from READY)."""
        return time.time() + (self.ch.clock_offset if self.ch else 0)

    def _verify_user_signature(self, user, cmd, req):
        """End-to-end check that the *user* (not just the controller) issued this command.

        Users whose signing key was pinned at provisioning must sign every command; the
        controller only relays it.  Returns None if acceptable, else the denial reason."""
        nonce, issued_at = req.get("nonce"), req.get("issued_at")
        if cmd == "UNLOCK":
            if not isinstance(nonce, str):
                return "step-up challenge missing or expired"
            pending = self.step_up_challenges.pop(nonce, None)   # one use, even if invalid
            if pending is None or pending[0] != user or pending[1] <= time.monotonic():
                return "step-up challenge missing or expired"
        public_hex = self.signing_public_keys.get(user)
        if public_hex is None:
            # Users enrolled after provisioning have no pinned key: the device can only
            # rely on the authenticated controller, and never for UNLOCK.
            return "step-up verification failed" if cmd == "UNLOCK" else None
        if not isinstance(nonce, str) or not isinstance(issued_at, int) \
                or abs(self._now() - issued_at) > TS_WINDOW:
            return "user signature missing or stale"
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(
                bytes.fromhex(req["signature"]),
                command_auth_payload(user, self.id, cmd, nonce, issued_at))
        except (InvalidSignature, KeyError, TypeError, ValueError):
            return "user signature verification failed"
        if cmd != "UNLOCK":
            now = self._now()
            self.seen_nonces = {n: exp for n, exp in self.seen_nonces.items() if exp > now}
            if nonce in self.seen_nonces:
                return "replayed signed command"
            if len(self.seen_nonces) >= MAX_SEEN_NONCES:
                return "too many recent commands"
            self.seen_nonces[nonce] = issued_at + TS_WINDOW + 1
        return None

    def _auto_relock(self, generation):
        with self._state_lock:
            if generation == self._relock_generation and self.state == "UNLOCKED":
                self.state = "LOCKED"
                self.log("automatic relock after configured delay")
            self._relock_timer = None

    def _save_authorization(self):
        if not self.config_path:
            return
        with open(self.config_path, "r") as f:
            config = json.load(f)
        config["allowed_users"] = self.allowed_users
        if self.allowed_commands is not None:
            config["allowed_commands"] = self.allowed_commands
        config["signing_public_keys"] = self.signing_public_keys
        write_json_secure(self.config_path, config)


def main():
    ap = argparse.ArgumentParser(description="Simulated smart device")
    ap.add_argument("config", help="e.g. config/device_light1.json")
    ap.add_argument("--host")
    ap.add_argument("--port", type=int)
    a = ap.parse_args()
    with open(a.config) as f:
        cfg = json.load(f)
    Device(cfg, a.host, a.port, config_path=a.config).start()
    threading.Event().wait()


if __name__ == "__main__":
    main()
