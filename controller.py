"""controller.py - the trusted home gateway.

Authenticates users and devices, enforces the access-control list (ACL),
and relays commands between two *separate* secure channels:
    user <--(session key A)--> controller <--(session key B)--> device
"""
import argparse
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
import socket
import threading
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from common import (AuthError, ProtocolError, ReplayError, StaleError, TamperError,
                    DEVICE_TYPES, TS_WINDOW, USER_IDLE_TIMEOUT, close_socket,
                    command_auth_payload, responder_handshake, static_public_from_private,
                    write_json_secure)


class DeviceConn:
    """A live, authenticated connection to one device."""

    def __init__(self, ch, sock):
        self.ch, self.sock = ch, sock
        self.lock = threading.Lock()
        self.closed = threading.Event()

    def request(self, body):
        with self.lock:
            try:
                self.ch.send(body)
                return self.ch.recv()
            except (ProtocolError, OSError):
                self.close()
                raise

    def probe(self, timeout=1.0):
        with self.lock:
            if self.closed.is_set():
                return False
            original_timeout = self.sock.gettimeout()
            try:
                self.sock.settimeout(timeout)
                self.ch.send({"type": "HEARTBEAT"})
                response = self.ch.recv()
                return response.get("type") == "RESPONSE" and \
                    response.get("status") == "OK" and response.get("detail") == "alive"
            except (ProtocolError, OSError):
                self.close()
                return False
            finally:
                if not self.closed.is_set():
                    try:
                        self.sock.settimeout(original_timeout)
                    except OSError:
                        self.close()

    def close(self):
        self.closed.set()
        close_socket(self.sock)


class Controller:
    def __init__(self, config, host=None, port=None, audit_path=None, quiet=False,
                 max_connections=64, per_ip_limit=20, rate_window=60,
                 pre_auth_timeout=3, config_path=None, max_session_age: float = 900,
                 max_session_messages=10000, rate_limit_backoff=1.0, notifier=None,
                 identity_failure_threshold=5, identity_backoff=1.0,
                 identity_backoff_cap=300):
        self._config = config
        if not config.get("static_private_key"):
            raise ValueError("controller config has no static_private_key; re-run provision.py")
        self.static_private = X25519PrivateKey.from_private_bytes(
            bytes.fromhex(config["static_private_key"]))
        self.public_key_hex = static_public_from_private(config["static_private_key"])
        self.users, self.devices = config["users"], config["devices"]
        self.config_path = config_path
        self.host = host or config.get("host", "127.0.0.1")
        self.req_port = config.get("port", 9000) if port is None else port
        self.port = self.req_port
        self.audit_path, self.quiet = audit_path, quiet
        self.registry, self.user_sessions, self.events = {}, {}, []
        self._lock = threading.Lock()
        self._audit_lock = threading.Lock()
        self._stop = threading.Event()
        self.max_connections = max_connections
        self.per_ip_limit, self.rate_window = per_ip_limit, rate_window
        if not isinstance(rate_limit_backoff, (int, float)) or rate_limit_backoff <= 0:
            raise ValueError("rate-limit backoff must be positive")
        self.rate_limit_backoff = rate_limit_backoff
        self.pre_auth_timeout = pre_auth_timeout
        if not isinstance(max_session_age, (int, float)) or max_session_age <= 0 or \
                max_session_age > 900:
            raise ValueError("session age must be in (0, 900] seconds")
        if not isinstance(max_session_messages, int) or not 4 <= max_session_messages <= 10000:
            raise ValueError("session message limit must be between 4 and 10000")
        self.max_session_age = max_session_age
        self.max_session_messages = max_session_messages
        self.revoked_users = set()
        # notifier(kind, detail) delivers security-relevant events to the owner (push, e-mail,
        # SMS, ...).  The prototype ships a console/file notifier (see main()).
        self.notifier = notifier
        self._connection_lock = threading.Lock()
        self._connections = set()
        self._ip_attempts = defaultdict(deque)
        self._ip_backoff_until = {}
        self.max_tracked_ips = 4096
        self._pairing_tokens = {}
        # Online-guessing defence: consecutive handshake failures per known identity
        # (e.g. someone with a stolen config trying PINs) trigger an exponential backoff.
        self.identity_failure_threshold = identity_failure_threshold
        self.identity_backoff, self.identity_backoff_cap = identity_backoff, identity_backoff_cap
        self._identity_failures = {}     # (role, id) -> [consecutive failures, locked_until]
        self._executor = None
        self._audit_hash = self._load_audit_hash(audit_path)

    @staticmethod
    def _load_audit_hash(path):
        if not path or not os.path.exists(path):
            return "0" * 64
        previous = "0" * 64
        chain_started = False
        with open(path, "r") as f:
            for line in f:
                try:
                    record = json.loads(line)
                except ValueError:
                    if chain_started:
                        raise ValueError("invalid entry in hash-chained audit log")
                    continue
                if not isinstance(record, dict) or "hash" not in record:
                    if chain_started:
                        raise ValueError("invalid entry in hash-chained audit log")
                    continue
                expected = Controller._audit_record_hash(record)
                if record.get("previous_hash") != previous or record.get("hash") != expected:
                    raise ValueError("audit log hash chain verification failed")
                previous = expected
                chain_started = True
        return previous

    @staticmethod
    def _audit_record_hash(record):
        payload = {key: value for key, value in record.items() if key != "hash"}
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def verify_audit_log(path):
        if not path or not os.path.isfile(path):
            return False
        try:
            Controller._load_audit_hash(path)
        except (OSError, ValueError):
            return False
        with open(path, "r") as f:
            for line in f:
                try:
                    if "hash" in json.loads(line):
                        return True
                except (TypeError, ValueError):
                    continue
        return False

    @staticmethod
    def verify_command_evidence(path, users):
        """Re-verifies the user signature stored with every forwarded command.

        Returns {"verified": n, "invalid": [...], "unverifiable": [...]}.  A valid entry is
        non-repudiable evidence that the user's signing key authorized that exact command:
        the controller cannot fabricate one because it never holds user private keys."""
        result = {"verified": 0, "invalid": [], "unverifiable": []}
        with open(path, "r") as f:
            for number, line in enumerate(f, 1):
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                evidence = record.get("evidence") if isinstance(record, dict) else None
                if not isinstance(evidence, dict):
                    continue
                try:
                    payload = json.loads(evidence["payload"])
                    user = payload["user_id"]
                except (KeyError, TypeError, ValueError):
                    result["invalid"].append(number)
                    continue
                public_hex = users.get(user, {}).get("signing_public_key")
                if not public_hex:
                    result["unverifiable"].append(number)
                    continue
                try:
                    Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(
                        bytes.fromhex(evidence["signature"]), evidence["payload"].encode())
                    result["verified"] += 1
                except (InvalidSignature, KeyError, TypeError, ValueError):
                    result["invalid"].append(number)
        return result

    # ---- logging / audit
    def event(self, kind, detail="", evidence=None):
        with self._lock:
            self.events.append((kind, detail))
        line = "%-12s %s" % (kind, detail)
        if not self.quiet:
            print("[CONTROLLER]", line, flush=True)
        if self.audit_path:
            with self._audit_lock:
                record = {
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "event": kind,
                    "detail": detail,
                    "previous_hash": self._audit_hash,
                }
                if evidence is not None:
                    record["evidence"] = evidence
                record["hash"] = self._audit_record_hash(record)
                with open(self.audit_path, "a") as f:
                    f.write(json.dumps(record, sort_keys=True) + "\n")
                self._audit_hash = record["hash"]

    def notify_owner(self, kind, detail):
        """Audit-log the event AND hand it to the configured notifier."""
        self.event("OWNER_NOTIFY", "%s: %s" % (kind, detail))
        if self.notifier is not None:
            try:
                self.notifier(kind, detail)
            except Exception as error:  # a broken notifier must never break the protocol
                self.event("NOTIFY_FAIL", "%s: %s" % (kind, error))

    # ---- lifecycle
    def start(self):
        self._executor = ThreadPoolExecutor(max_workers=self.max_connections)
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.srv.bind((self.host, self.req_port))
            self.srv.listen(16)
        except OSError:
            self._executor.shutdown(wait=False, cancel_futures=True)
            self._executor = None
            close_socket(self.srv)
            raise
        self.port = self.srv.getsockname()[1]
        threading.Thread(target=self._accept_loop, daemon=True).start()
        return self

    def stop(self):
        self._stop.set()
        close_socket(self.srv)
        with self._connection_lock:
            connections = list(self._connections)
        for conn in connections:
            close_socket(conn)
        for dc in list(self.registry.values()):
            dc.close()
        if self._executor:
            self._executor.shutdown(wait=False, cancel_futures=True)

    def _accept_loop(self):
        while not self._stop.is_set():
            try:
                conn, addr = self.srv.accept()
            except OSError:
                break
            now = time.monotonic()
            log_rate_limit = False
            with self._connection_lock:
                backoff_until = self._ip_backoff_until.get(addr[0], 0)
                if backoff_until > now:
                    limited = True
                else:
                    if backoff_until:
                        self._ip_backoff_until.pop(addr[0], None)
                        self._ip_attempts.pop(addr[0], None)
                    limited = False
                attempts = self._ip_attempts.get(addr[0], deque())
                while attempts and now - attempts[0] >= self.rate_window:
                    attempts.popleft()
                if not attempts:
                    self._ip_attempts.pop(addr[0], None)
                if not limited and len(attempts) >= self.per_ip_limit:
                    limited = True
                    log_rate_limit = True
                    self._ip_backoff_until[addr[0]] = now + self.rate_limit_backoff
                    self._ip_attempts.pop(addr[0], None)
                full = len(self._connections) >= self.max_connections
                if not limited and not full:
                    self._connections.add(conn)
            if limited:
                if log_rate_limit:
                    self.event("RATE_LIMIT",
                               "%s entered temporary connection cooldown" % addr[0])
                close_socket(conn)
                continue
            if full:
                self.event("CONNECTION_LIMIT", "%s connection capacity reached" % addr[0])
                close_socket(conn)
                continue
            try:
                self._executor.submit(self._handle_connection, conn, addr)
            except RuntimeError:
                with self._connection_lock:
                    self._connections.discard(conn)
                close_socket(conn)

    def _handle_connection(self, conn, addr):
        try:
            self._handle(conn, addr)
        finally:
            with self._connection_lock:
                self._connections.discard(conn)

    def _record_auth_failure(self, ip):
        now = time.monotonic()
        with self._connection_lock:
            for address, attempts in list(self._ip_attempts.items()):
                while attempts and now - attempts[0] >= self.rate_window:
                    attempts.popleft()
                if not attempts:
                    self._ip_attempts.pop(address, None)
            for address, until in list(self._ip_backoff_until.items()):
                if until <= now:
                    self._ip_backoff_until.pop(address, None)
            if ip not in self._ip_attempts and \
                    len(self._ip_attempts) >= self.max_tracked_ips:
                oldest_ip = min(self._ip_attempts,
                                key=lambda address: self._ip_attempts[address][0])
                del self._ip_attempts[oldest_ip]
                self._ip_backoff_until.pop(oldest_ip, None)
            attempts = self._ip_attempts[ip]
            attempts.append(now)

    def _lookup(self, role, ident):
        with self._lock:
            failures = self._identity_failures.get((role, ident))
            if failures and failures[1] > time.monotonic():
                return None            # locked: indistinguishable from a wrong key
            if role == "user":
                if ident in self.revoked_users:
                    return None
                if ident not in self.users:
                    pending = self._pairing_tokens.get(ident)
                    if pending is None or pending[2] <= time.monotonic():
                        self._pairing_tokens.pop(ident, None)
                        return None
                    return pending[0]
            ent = (self.users if role == "user" else self.devices).get(ident)
            return bytes.fromhex(ent["key"]) if ent else None

    def _record_identity_failure(self, role, ident):
        with self._lock:
            entry = self._identity_failures.setdefault((role, ident), [0, 0])
            entry[0] += 1
            over = entry[0] - self.identity_failure_threshold
            if over < 0:
                return
            delay = min(self.identity_backoff_cap, self.identity_backoff * 2 ** over)
            entry[1] = time.monotonic() + delay
            count = entry[0]
        self.event("AUTH_LOCKOUT", "%s %s locked for %.0fs after %d failed handshakes" %
                   (role, ident, delay, count))
        self.notify_owner("AUTH_GUESSING", "%d failed logins for %s %s (wrong PIN or stolen "
                          "credentials?); locked for %.0fs" % (count, role, ident, delay))

    def _clear_identity_failures(self, role, ident):
        with self._lock:
            self._identity_failures.pop((role, ident), None)

    def _claim_user_session(self, user, conn):
        with self._lock:
            if user in self.revoked_users or user not in self.users:
                return "revoked"
            if user in self.user_sessions:
                return "duplicate"
            self.user_sessions[user] = conn
        return None

    def _claim_pairing(self, user):
        with self._lock:
            pairing = self._pairing_tokens.pop(user, None)
            if pairing is not None and pairing[2] <= time.monotonic():
                return None
            return pairing

    # ---- per-connection logic
    def _handle(self, conn, addr):
        try:
            conn.settimeout(self.pre_auth_timeout)
            role, ident, ch = responder_handshake(
                conn, self._lookup, self.static_private,
                self.max_session_age, self.max_session_messages)
        except (ProtocolError, OSError) as e:
            self._record_auth_failure(addr[0])
            self.event("AUTH_FAIL", "%s:%s  %s" % (addr[0], addr[1], e))
            if isinstance(e, AuthError) and e.known:
                self._record_identity_failure(e.role, e.ident)
            close_socket(conn)
            return
        self._clear_identity_failures(role, ident)
        if role == "user":
            pairing = self._claim_pairing(ident)
            if pairing is not None:
                self._serve_enrollment(conn, ident, ch, pairing[1])
                close_socket(conn)
                return
            claim_error = self._claim_user_session(ident, conn)
            if claim_error == "revoked":
                self.event("AUTH_REVOKED", "%s attempted login after revocation" % ident)
                close_socket(conn)
                return
            if claim_error == "duplicate":
                self.event("USER_DUPLICATE", "%s already has an active session" % ident)
                close_socket(conn)
                return
        self.event("%s_AUTH_OK" % role.upper(), "%s authenticated, session keys derived" % ident)
        try:
            (self._serve_device if role == "device" else self._serve_user)(conn, ident, ch)
        finally:
            if role == "user":
                with self._lock:
                    if self.user_sessions.get(ident) is conn:
                        del self.user_sessions[ident]
            close_socket(conn)

    def _serve_enrollment(self, conn, user, ch, allowed):
        conn.settimeout(30)
        try:
            request = ch.recv()
            if request.get("type") != "ENROLL":
                raise ProtocolError("expected enrollment message")
            new_key = bytes.fromhex(request["key"])
            public_key = bytes.fromhex(request["signing_public_key"])
            if len(new_key) != 32 or len(public_key) != 32:
                raise ProtocolError("invalid enrollment key")
        except (KeyError, TypeError, ValueError, ProtocolError, OSError) as error:
            self.event("ENROLL_FAIL", "%s: %s" % (user, error))
            return
        with self._lock:
            if user in self.users or user in self.revoked_users:
                ch.send(self._resp("DENIED", "user ID unavailable"))
                return
            self.users[user] = {"key": new_key.hex(), "allowed": allowed,
                                "signing_public_key": public_key.hex()}
            self._config.setdefault("users", self.users)
            for device_id in allowed:
                self.devices[device_id]["allowed_users"] = \
                    self._device_allowed_users(device_id)
                self.devices[device_id]["allowed_commands"] = \
                    self._device_allowed_commands(device_id)
                self.devices[device_id]["signing_public_keys"] = \
                    self._device_signing_keys(device_id)
        try:
            self._persist_config()
            self._sync_all_device_authz()
        except OSError as error:
            with self._lock:
                self.users.pop(user, None)
            ch.send(self._resp("ERROR", "could not persist enrollment"))
            self.event("ENROLL_FAIL", "%s: %s" % (user, error))
            return
        ch.send({"type": "RESPONSE", "status": "OK", "detail": "enrolled",
                 "devices": {device_id: self.devices[device_id]["type"]
                             for device_id in allowed}})
        self.event("USER_ENROLLED", "%s enrolled by one-time owner token" % user)
        self.notify_owner("USER_ENROLLED", "new user %s enrolled" % user)

    def _serve_device(self, conn, ident, ch):
        conn.settimeout(5)
        dc = DeviceConn(ch, conn)
        with self._lock:
            existing = self.registry.get(ident)
            if existing is None:
                self.registry[ident] = dc

        if existing is not None:
            is_alive = existing.probe()
            with self._lock:
                current = self.registry.get(ident)
                # A failed probe closes `existing`, and its own serving thread then removes
                # it from the registry.  So "slot empty" or "still the dead session" both
                # mean the old session is gone and this connection may take over.  Only a
                # live session, or a *different* connection that registered meanwhile, makes
                # this one a duplicate.
                if current is None or (current is existing and not is_alive):
                    self.registry[ident] = dc
                    duplicate = False
                else:
                    duplicate = True
            if duplicate:
                self.event("DEVICE_DUPLICATE", "%s already has a live session" % ident)
                dc.close()
                return
            existing.close()
            self.event("DEVICE_SESSION_REPLACED",
                       "%s previous session failed heartbeat" % ident)

        try:
            self._sync_device_authz(ident, dc)
        except (ProtocolError, OSError) as e:
            self.event("AUTHZ_SYNC_FAIL", "%s: %s" % (ident, e))
            dc.close()
            with self._lock:
                if self.registry.get(ident) is dc:
                    del self.registry[ident]
            return
        if not dc.closed.wait(ch.remaining_lifetime()):
            self.event("SESSION_EXPIRED", "%s device session reached maximum age" % ident)
            dc.close()
        with self._lock:
            if self.registry.get(ident) is dc:
                del self.registry[ident]

    def _serve_user(self, conn, user, ch):
        conn.settimeout(min(USER_IDLE_TIMEOUT, max(0.01, ch.remaining_lifetime())))
        while True:
            try:
                req = ch.recv()
            except ReplayError as e:
                self.event("REPLAY", "%s: %s -> session dropped" % (user, e)); return
            except TamperError as e:
                self.event("TAMPER", "%s: %s -> session dropped" % (user, e)); return
            except StaleError as e:
                self.event("STALE", "%s: %s -> session dropped" % (user, e)); return
            except socket.timeout:
                self.event("SESSION_EXPIRED",
                           "%s user session timed out (idle or maximum age)" % user)
                return
            except (ProtocolError, OSError) as e:
                if not isinstance(e, ConnectionError):
                    self.event("PROTO_ERROR", "%s: %s" % (user, e))
                return
            if req.get("type") == "KEY_ROTATE":
                try:
                    new_key = bytes.fromhex(req["new_key"])
                    if len(new_key) != 32:
                        raise ValueError("new key must be 32 bytes")
                    self.rotate_user_key(user, new_key)
                    ch.send(self._resp("OK", "key rotated; reconnect using the new key"))
                except (KeyError, TypeError, ValueError) as e:
                    ch.send(self._resp("DENIED", "invalid replacement key: %s" % e))
                except OSError as e:
                    ch.send(self._resp("ERROR", "could not persist replacement key: %s" % e))
                return
            try:
                ch.send(self._process(user, req))
            except OSError:
                return

    def revoke(self, user):
        with self._lock:
            self.revoked_users.add(user)
            self.users.pop(user, None)
            conn = self.user_sessions.pop(user, None)
        if conn is not None:
            close_socket(conn)
        self._persist_config()
        self._sync_all_device_authz()
        self.event("USER_REVOKED", "%s revoked" % user)
        self.notify_owner("USER_REVOKED", "%s revoked" % user)

    def issue_pairing_token(self, user_id, allowed, ttl=300):
        if not isinstance(user_id, str) or not user_id or len(user_id) > 64:
            raise ValueError("user ID must contain 1-64 characters")
        if not isinstance(allowed, dict) or not allowed or ttl <= 0:
            raise ValueError("pairing requires a valid ACL and positive lifetime")
        for dev_id, commands in allowed.items():
            if dev_id not in self.devices or not isinstance(commands, list):
                raise ValueError("invalid device ACL")
            try:
                valid_commands = DEVICE_TYPES[self.devices[dev_id]["type"]]
            except KeyError as error:
                raise ValueError("invalid device ACL") from error
            if not all(isinstance(command, str) and command in valid_commands
                       for command in commands):
                raise ValueError("invalid device ACL")
            if "UNLOCK" in commands:
                raise ValueError(
                    "new users cannot receive UNLOCK until their signing key is trusted by each device")
        token = os.urandom(32)
        with self._lock:
            if user_id in self.users or user_id in self.revoked_users:
                raise ValueError("user ID is unavailable")
            self._pairing_tokens[user_id] = (
                token, dict(allowed), time.monotonic() + ttl)
        self.event("PAIRING_TOKEN", "owner issued a one-time token")
        # The pairing code also carries the controller's static public key, so the new
        # user pins it from the same trusted out-of-band channel as the token.
        return token.hex() + self.public_key_hex

    def rotate_user_key(self, user, new_key):
        if not isinstance(new_key, bytes) or len(new_key) != 32:
            raise ValueError("replacement key must be exactly 32 bytes")
        with self._lock:
            if user in self.revoked_users or user not in self.users:
                raise ValueError("unknown or revoked user")
            previous_key = self.users[user]["key"]
            self.users[user]["key"] = new_key.hex()
        try:
            self._persist_config()
        except OSError:
            with self._lock:
                self.users[user]["key"] = previous_key
            raise
        self.event("KEY_ROTATED", "%s replaced the long-term user key" % user)
        self.notify_owner("KEY_ROTATED", "%s replaced the long-term key" % user)

    def _persist_config(self):
        if self.config_path:
            write_json_secure(self.config_path, self._config)

    def _device_allowed_users(self, device_id):
        return [user for user, record in self.users.items()
                if record.get("allowed", {}).get(device_id)]

    def _device_allowed_commands(self, device_id):
        return {user: list(record["allowed"][device_id])
                for user, record in self.users.items()
                if record.get("allowed", {}).get(device_id)}

    def _device_signing_keys(self, device_id):
        return {user: self.users[user]["signing_public_key"]
                for user in self._device_allowed_users(device_id)
                if self.users[user].get("signing_public_key")}

    def _sync_device_authz(self, device_id, connection):
        response = connection.request({
            "type": "UPDATE_AUTHZ",
            "allowed_users": self._device_allowed_users(device_id),
            "allowed_commands": self._device_allowed_commands(device_id),
            "signing_public_keys": self._device_signing_keys(device_id),
        })
        if response.get("status") != "OK":
            raise ProtocolError("device rejected authorization update")

    def _sync_all_device_authz(self):
        for device_id, connection in list(self.registry.items()):
            try:
                self._sync_device_authz(device_id, connection)
            except (ProtocolError, OSError) as e:
                self.event("AUTHZ_SYNC_FAIL", "%s: %s" % (device_id, e))

    @staticmethod
    def _resp(status, detail, state=None):
        return {"type": "RESPONSE", "status": status, "detail": detail, "state": state}

    def _process(self, user, req):
        dev_id, cmd = req.get("device_id"), req.get("command")
        with self._lock:
            account = self.users.get(user)
            revoked = user in self.revoked_users
        if revoked or account is None:
            self.event("CMD_DENIED", "%s: user revoked or unknown" % user)
            return self._resp("DENIED", "user is not authorized")
        req_type = req.get("type")
        if req_type not in ("COMMAND", "STEP_UP_PREPARE") or req.get("user_id") != user \
                or not isinstance(dev_id, str) or not isinstance(cmd, str):
            self.event("CMD_DENIED", "%s: malformed or spoofed request" % user)
            return self._resp("DENIED", "malformed request")
        if cmd not in account.get("allowed", {}).get(dev_id, []):
            self.event("CMD_DENIED", "%s -> %s %s (not authorized)" % (user, dev_id, cmd))
            return self._resp("DENIED", "access denied")
        if req_type == "STEP_UP_PREPARE" and cmd != "UNLOCK":
            return self._resp("DENIED", "step-up is only supported for UNLOCK")
        dc = self.registry.get(dev_id)
        if dc is None:
            self.event("DEVICE_DOWN", "%s offline" % dev_id)
            return self._resp("ERROR", "device offline")
        if req_type == "STEP_UP_PREPARE":
            try:
                challenge = dc.request({"type": "STEP_UP_CHALLENGE", "on_behalf_of": user})
            except (ProtocolError, OSError) as e:
                self.event("DEVICE_DOWN", "%s unreachable: %s" % (dev_id, e))
                return self._resp("ERROR", "device unreachable")
            return {"type": "RESPONSE", "status": challenge.get("status"),
                    "detail": challenge.get("detail"), "challenge": challenge.get("challenge")}
        # Every command is signed by the user (end-to-end authenticity, non-repudiation).
        nonce, issued_at, signature = req.get("nonce"), req.get("issued_at"), req.get("signature")
        try:
            if not isinstance(nonce, str) or not isinstance(issued_at, int) \
                    or not isinstance(signature, str):
                raise ValueError("signature fields missing")
            payload = command_auth_payload(user, dev_id, cmd, nonce, issued_at)
            Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(account["signing_public_key"])).verify(
                    bytes.fromhex(signature), payload)
        except (InvalidSignature, KeyError, TypeError, ValueError):
            self.event("CMD_DENIED", "%s -> %s %s (signature verification failed)" %
                       (user, dev_id, cmd))
            if cmd == "UNLOCK":
                self.notify_owner("UNLOCK_REJECTED",
                                  "invalid step-up signature for %s by %s" % (dev_id, user))
            return self._resp("DENIED", "signature verification failed")
        if abs(time.time() - issued_at) > TS_WINDOW:
            self.event("CMD_DENIED", "%s -> %s %s (stale signed command)" % (user, dev_id, cmd))
            return self._resp("DENIED", "stale signed command")
        evidence = {"payload": payload.decode(), "signature": signature}
        try:
            r = dc.request({"type": "COMMAND", "device_id": dev_id, "command": cmd,
                            "on_behalf_of": user, "nonce": nonce, "issued_at": issued_at,
                            "signature": signature})
        except (ProtocolError, OSError) as e:
            self.event("DEVICE_DOWN", "%s unreachable: %s" % (dev_id, e))
            return self._resp("ERROR", "device unreachable")
        self.event("CMD_OK" if r.get("status") == "OK" else "CMD_FAILED",
                   "%s -> %s %s => %s" % (user, dev_id, cmd, r.get("status")),
                   evidence=evidence)
        if cmd == "UNLOCK" and r.get("status") == "OK":
            self.notify_owner("UNLOCK_ACCEPTED", "%s unlocked by %s" % (dev_id, user))
        return self._resp(r.get("status"), r.get("detail"), r.get("state"))


def make_file_notifier(path):
    """Console + JSON-lines notifier.  Forward the file to push/e-mail in a real product."""
    lock = threading.Lock()

    def notify(kind, detail):
        record = {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "kind": kind, "detail": detail}
        print("[OWNER NOTIFICATION] %s: %s" % (kind, detail), flush=True)
        if path:
            with lock, open(path, "a") as f:
                f.write(json.dumps(record) + "\n")
    return notify


def main():
    ap = argparse.ArgumentParser(description="Smart-home controller")
    ap.add_argument("config", nargs="?", default="config/controller.json")
    ap.add_argument("--host")
    ap.add_argument("--port", type=int)
    ap.add_argument("--audit", default="audit.log")
    ap.add_argument("--verify-audit", action="store_true",
                    help="verify the hash chain in the audit log and exit")
    ap.add_argument("--notify-file", default="notifications.log",
                    help="append owner notifications (JSON lines) here; also printed")
    ap.add_argument("--pairing-console", action="store_true",
                    help="enable local owner-approved one-time user enrollment")
    a = ap.parse_args()
    if a.verify_audit:
        if not Controller.verify_audit_log(a.audit):
            ap.error("audit hash chain verification failed")
        print("Audit hash chain verified.")
        if os.path.isfile(a.config):
            with open(a.config) as f:
                users = json.load(f).get("users", {})
            result = Controller.verify_command_evidence(a.audit, users)
            print("Signed command evidence: %d verified, %d invalid, %d unverifiable "
                  "(user key no longer in config)." % (
                      result["verified"], len(result["invalid"]), len(result["unverifiable"])))
            if result["invalid"]:
                ap.error("invalid command signatures on audit lines %s" % result["invalid"])
        return
    with open(a.config) as f:
        cfg = json.load(f)
    c = Controller(cfg, a.host, a.port, a.audit, config_path=a.config,
                   notifier=make_file_notifier(a.notify_file)).start()
    print("[CONTROLLER] listening on %s:%d (audit log: %s)" % (c.host, c.port, a.audit))
    if a.pairing_console:
        threading.Thread(target=_pairing_console, args=(c,), daemon=True).start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        c.stop()


def _pairing_console(controller):
    print("[PAIRING] Enter a new user ID, 'revoke <ID>', or q to exit.")
    while not controller._stop.is_set():
        try:
            command = input("[PAIRING] command: ").strip()
        except EOFError:
            return
        if command.lower() == "q":
            return
        if command.startswith("revoke "):
            user_id = command.split(None, 1)[1]
            try:
                controller.revoke(user_id)
                print("[PAIRING] revoked %s" % user_id)
            except OSError as error:
                print("[PAIRING] could not persist revocation: %s" % error)
            continue
        user_id = command
        try:
            acl_text = input('[PAIRING] device ACL JSON (e.g. {"light1":["STATUS"]}): ')
            token = controller.issue_pairing_token(user_id, json.loads(acl_text))
        except (ValueError, json.JSONDecodeError) as error:
            print("[PAIRING] could not issue token: %s" % error)
            continue
        print("[PAIRING] one-time pairing code for %s (valid 300 seconds): %s" %
              (user_id, token))


if __name__ == "__main__":
    main()
