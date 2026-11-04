"""user.py - the user's app: authenticates to the controller and sends commands."""
import argparse
import getpass
import hmac
import json
import os
import socket
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from common import (DEVICE_TYPES, AuthError, ProtocolError, SessionExpiredError,
                    close_socket, command_auth_payload, initiator_handshake,
                    MIN_STEP_UP_PIN_LENGTH, unwrap_user_secrets, USER_IDLE_TIMEOUT,
                    wrap_user_secrets, write_json_secure)


class UserClient:
    """The user's app.  Its PSK and signing key are stored PIN-wrapped; the PIN is asked
    once at login (pin_callback) and again as a step-up confirmation for UNLOCK."""

    def __init__(self, cfg, host=None, port=None, pin_callback=None, config_path=None):
        self.config = cfg
        self.id = cfg["user_id"]
        if "wrapped_secrets" not in cfg or "controller_public_key" not in cfg:
            raise ValueError("config predates smarthome-v2; re-run provision.py or re-enroll")
        self.controller_public = bytes.fromhex(cfg["controller_public_key"])
        self.devices = cfg.get("devices", {})
        self.addr = (host or cfg["controller"]["host"], port or cfg["controller"]["port"])
        self.sock = self.ch = None
        self.pin_callback = pin_callback
        self.config_path = config_path
        self.last_activity = 0
        self.key = self._seed = self._signing = None

    # ---- local secrets
    def unlock(self, pin=None):
        """Unwraps the PSK and signing key.  A wrong PIN is NOT detected here (there is
        deliberately nothing in the file to check it against); it shows up as a failed
        handshake at the controller, which counts and limits such failures."""
        if pin is None:
            if not self.pin_callback:
                raise ValueError("a PIN is required to unlock this user's keys")
            pin = self.pin_callback()
        self.key, self._seed = unwrap_user_secrets(self.config, pin)
        self._signing = Ed25519PrivateKey.from_private_bytes(self._seed)

    def lock(self):
        self.key = self._seed = self._signing = None

    def _confirm_pin(self):
        """Step-up: re-enter the PIN; compared with the secrets already in memory."""
        if not self.pin_callback:
            raise ValueError("this action requires a local step-up PIN")
        psk, seed = unwrap_user_secrets(self.config, self.pin_callback())
        return hmac.compare_digest(psk + seed, self.key + self._seed)

    @staticmethod
    def enroll(user_id, pairing_code, host, port, pin):
        if len(pin) < MIN_STEP_UP_PIN_LENGTH:
            raise ValueError("PIN must contain at least 8 characters")
        code = bytes.fromhex(pairing_code)
        if len(code) != 64:
            raise ValueError("pairing code must be 64 bytes (token + controller key)")
        token_key, controller_public = code[:32], code[32:]
        sock = socket.create_connection((host, port), timeout=10)
        try:
            channel = initiator_handshake(sock, "user", user_id, token_key, controller_public)
            permanent_key = os.urandom(32)
            signing_private = Ed25519PrivateKey.generate()
            public_bytes = signing_private.public_key().public_bytes_raw()
            channel.send({"type": "ENROLL", "key": permanent_key.hex(),
                          "signing_public_key": public_bytes.hex()})
            response = channel.recv()
            if response.get("status") != "OK":
                raise ProtocolError(response.get("detail", "enrollment rejected"))
            cfg = {
                "user_id": user_id,
                "controller": {"host": host, "port": port},
                "controller_public_key": controller_public.hex(),
                "devices": response.get("devices", {}),
            }
            cfg.update(wrap_user_secrets(permanent_key, signing_private.private_bytes_raw(),
                                         pin))
            return cfg
        finally:
            close_socket(sock)

    # ---- session
    def connect(self):
        if self.key is None:
            self.unlock()
        last_error = None
        for attempt in range(3):
            self.sock = None
            try:
                self.sock = socket.create_connection(self.addr, timeout=10)
                self.ch = initiator_handshake(self.sock, "user", self.id, self.key,
                                              self.controller_public)
                self.sock.settimeout(10)
                self.last_activity = time.monotonic()
                return self
            except (ProtocolError, OSError) as error:
                if self.sock:
                    close_socket(self.sock)
                self.sock = self.ch = None
                last_error = error
                if isinstance(error, AuthError) and \
                        str(error) != "controller authentication failed":
                    self.lock()        # wrong PIN is the usual cause: ask again next time
                    raise AuthError("authentication failed (wrong PIN, revoked, or "
                                    "temporarily locked after failed attempts)")
                if isinstance(error, ProtocolError):
                    raise
                if attempt < 2:
                    time.sleep(0.05 * (attempt + 1))
        raise last_error

    def _signed_command(self, device_id, command, nonce):
        issued_at = int(self.ch.now())
        signature = self._signing.sign(command_auth_payload(
            self.id, device_id, command, nonce, issued_at)).hex()
        return {"type": "COMMAND", "user_id": self.id, "device_id": device_id,
                "command": command, "nonce": nonce, "issued_at": issued_at,
                "signature": signature}

    def command(self, device_id, command):
        high_risk = command == "UNLOCK"
        self._ensure_session(messages=4 if high_risk else 2)
        if high_risk:
            self.ch.send({"type": "STEP_UP_PREPARE", "user_id": self.id,
                          "device_id": device_id, "command": command})
            step_up = self.ch.recv()
            self.last_activity = time.monotonic()
            if step_up.get("status") != "OK":
                return step_up
            if not self._confirm_pin():
                # Wrong PIN: nothing is signed or sent. The device's challenge simply expires.
                return {"type": "RESPONSE", "status": "DENIED",
                        "detail": "incorrect step-up PIN", "state": None}
            self.ch.send(self._signed_command(device_id, command, step_up.get("challenge")))
            response = self.ch.recv()
            self.last_activity = time.monotonic()
            return response
        try:
            self.ch.send(self._signed_command(device_id, command, os.urandom(16).hex()))
        except SessionExpiredError:
            self.close()
            self.connect()
            self.ch.send(self._signed_command(device_id, command, os.urandom(16).hex()))
        response = self.ch.recv()
        self.last_activity = time.monotonic()
        return response

    def _ensure_session(self, messages):
        idle = time.monotonic() - self.last_activity
        idle_refresh_threshold = USER_IDLE_TIMEOUT - min(1.0, USER_IDLE_TIMEOUT / 10)
        if (self.ch is None or self.ch.needs_rehandshake(messages=messages)
                or idle >= idle_refresh_threshold):
            self.close()
            self.connect()

    def rotate_key(self):
        self._ensure_session(messages=2)
        pin = self.pin_callback() if self.pin_callback else None
        if pin is None or not hmac.compare_digest(
                b"".join(unwrap_user_secrets(self.config, pin)), self.key + self._seed):
            return {"type": "RESPONSE", "status": "DENIED",
                    "detail": "incorrect PIN", "state": None}
        new_key = os.urandom(32)
        self.ch.send({"type": "KEY_ROTATE", "new_key": new_key.hex()})
        response = self.ch.recv()
        self.last_activity = time.monotonic()
        if response.get("status") == "OK":
            self.config.update(wrap_user_secrets(new_key, self._seed, pin))
            self.key = new_key
            if self.config_path:
                write_json_secure(self.config_path, self.config)
        self.close()
        return response

    def close(self):
        if self.sock:
            close_socket(self.sock)
            self.sock = self.ch = None


def menu(client):
    items = [(d, c, label) for d, t in client.devices.items()
             for c, label in DEVICE_TYPES[t].items()]
    while True:
        print("\nAvailable commands:")
        for i, (d, c, label) in enumerate(items, 1):
            print("  %d. %s  [%s]" % (i, label, d))
        print("  q. Quit")
        choice = input("> ").strip().lower()
        if choice == "q":
            return
        if not choice.isdigit() or not 1 <= int(choice) <= len(items):
            print("Invalid choice"); continue
        d, c, _ = items[int(choice) - 1]
        show(client.command(d, c))


def show(resp):
    mark = "✓" if resp.get("status") == "OK" else "✗"
    print("  %s %s: %s" % (mark, resp.get("status"), resp.get("detail")))


def main():
    ap = argparse.ArgumentParser(description="Smart-home user app")
    ap.add_argument("config", nargs="?", help="e.g. config/user_hari.json")
    ap.add_argument("--host")
    ap.add_argument("--port", type=int)
    ap.add_argument("--enroll-user", metavar="ID",
                    help="enroll a new user with a one-time owner token")
    ap.add_argument("--pairing-code", help="one-time pairing code printed by the controller")
    ap.add_argument("--output", help="write enrolled user's protected config here")
    ap.add_argument("--rotate-key", action="store_true",
                    help="replace this user's long-term key using the current session")
    ap.add_argument("--cmd", action="append", metavar="DEVICE:COMMAND",
                    help="non-interactive, repeatable (e.g. light1:TURN_ON)")
    a = ap.parse_args()
    if a.enroll_user:
        if not a.output:
            ap.error("--output is required with --enroll-user")
        token = a.pairing_code or getpass.getpass("One-time pairing code: ")
        pin = getpass.getpass("Set PIN: ")
        if len(pin) < MIN_STEP_UP_PIN_LENGTH or pin != getpass.getpass("Confirm PIN: "):
            ap.error("PIN must contain at least 8 characters and entries must match")
        try:
            cfg = UserClient.enroll(a.enroll_user, token, a.host or "127.0.0.1",
                                    a.port or 9000, pin)
        except (ProtocolError, OSError, ValueError) as e:
            ap.error("enrollment failed: %s" % e)
        os.makedirs(os.path.dirname(os.path.abspath(a.output)), exist_ok=True)
        write_json_secure(a.output, cfg)
        print("Enrolled user %s; protected config written to %s" %
              (a.enroll_user, a.output))
        return
    if not a.config:
        ap.error("a user config path is required unless --enroll-user is used")
    with open(a.config) as f:
        cfg = json.load(f)
    client = UserClient(cfg, a.host, a.port,
                        pin_callback=lambda: getpass.getpass("PIN: "),
                        config_path=a.config)
    print("-" * 40, "\nSECURE SMART HOME SYSTEM\n" + "-" * 40)
    print("User:", client.id, "\nAuthenticating with controller...")
    try:
        client.connect()
    except (ProtocolError, OSError, ValueError) as e:
        print("[✗] Could not establish secure session:", e); return
    print("[✓] Mutual authentication done, session key established")
    try:
        if a.rotate_key:
            show(client.rotate_key())
        elif a.cmd:
            for item in a.cmd:
                d, c = item.split(":", 1)
                print("%s -> %s" % (d, c)); show(client.command(d, c))
        else:
            menu(client)
    except (ProtocolError, OSError, ValueError) as e:
        print("[✗] Session terminated:", e)
    finally:
        client.close()


if __name__ == "__main__":
    main()
