"""common.py - framing, handshake and the encrypted Channel shared by all parties.

Security building blocks (see docs/PROTOCOL.md):
  * Controller static X25519 key (pinned)  -> identity hiding, PSK-leak-resistant controller auth
  * PSK + ephemeral X25519 + HKDF          -> mutual authentication, forward secrecy
  * Peer proves first, controller confirms -> no offline PIN-guessing oracle on the wire
  * AES-256-GCM                            -> confidentiality + integrity
  * Strict sequence numbers + timestamps   -> replay protection
  * Ed25519 signature on every command     -> end-to-end authenticity + non-repudiation
  * Tagless Scrypt wrap of user secrets    -> stolen config gives no offline PIN oracle
"""
import hashlib
import hmac
import json
import os
import socket
import struct
import tempfile
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

MAX_FRAME = 65536
TS_WINDOW = 30          # seconds a message timestamp may differ from local clock
PROTO = b"smarthome-v2"
CHANNEL_PLAINTEXT_SIZE = 1024
IDENTITY_PLAINTEXT_SIZE = 96   # role + id are padded to this size before encryption
IDENTITY_CIPHERTEXT_SIZE = IDENTITY_PLAINTEXT_SIZE + 16
MAX_ID_LENGTH = 64
MAX_SESSION_AGE = 900
MAX_SESSION_MESSAGES = 10000
USER_IDLE_TIMEOUT = 300
MIN_STEP_UP_PIN_LENGTH = 8
SECRET_WRAP_SCRYPT_N = 2 ** 15

DEVICE_TYPES = {
    "light": {"TURN_ON": "Turn ON", "TURN_OFF": "Turn OFF", "STATUS": "Status"},
    "lock": {"LOCK": "Lock", "UNLOCK": "Unlock", "STATUS": "Status"},
}


class ProtocolError(Exception):
    """Base class for all protocol violations."""


class AuthError(ProtocolError):
    """Peer failed authentication.

    On the controller side `role`/`ident` carry the decrypted identity and `known` says
    whether it matched a real account, so failures can be counted per identity."""

    def __init__(self, message, role=None, ident=None, known=False):
        super().__init__(message)
        self.role, self.ident, self.known = role, ident, known


class TamperError(ProtocolError):
    """AEAD tag mismatch: message modified, forged or from another session."""


class ReplayError(ProtocolError):
    """Sequence number already used."""


class StaleError(ProtocolError):
    """Timestamp outside the freshness window."""


class SessionExpiredError(ProtocolError):
    """The session reached its age or message limit and must be re-established."""


# ---------------------------------------------------------------- framing
def send_frame(sock, obj):
    data = json.dumps(obj, separators=(",", ":")).encode()
    sock.sendall(struct.pack(">I", len(data)) + data)


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def recv_frame(sock):
    (n,) = struct.unpack(">I", _recv_exact(sock, 4))
    if n > MAX_FRAME:
        raise ProtocolError("frame too large")
    try:
        obj = json.loads(_recv_exact(sock, n))
    except ValueError:
        raise ProtocolError("malformed frame")
    if not isinstance(obj, dict):
        raise ProtocolError("frame is not an object")
    return obj


def close_socket(s):
    for fn in (lambda: s.shutdown(socket.SHUT_RDWR), s.close):
        try:
            fn()
        except (OSError, TypeError, ValueError):
            pass


def write_json_secure(path, value):
    directory = os.path.dirname(os.path.abspath(path))
    fd, temporary_path = tempfile.mkstemp(prefix=".config-", dir=directory)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(value, f, indent=2)
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, path)
    except OSError:
        try:
            os.unlink(temporary_path)
        except FileNotFoundError:
            pass
        raise


# ----------------------------------------------------------------- crypto
def tlv(*parts):
    """Unambiguous encoding: each part is length-prefixed."""
    return b"".join(struct.pack(">H", len(p)) + p for p in parts)


def mac(key, *parts):
    return hmac.new(key, tlv(*parts), hashlib.sha256).digest()


def _pub_bytes(priv):
    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def new_static_keypair():
    """Returns (private_hex, public_hex) for the controller's long-term X25519 key."""
    private = X25519PrivateKey.generate()
    return private.private_bytes_raw().hex(), _pub_bytes(private).hex()


def static_public_from_private(private_hex):
    return _pub_bytes(X25519PrivateKey.from_private_bytes(bytes.fromhex(private_hex))).hex()


def _field(msg, name, length):
    try:
        v = bytes.fromhex(msg[name])
    except (KeyError, TypeError, ValueError):
        raise ProtocolError("bad field: " + name)
    if len(v) != length:
        raise ProtocolError("bad length: " + name)
    return v


def _dh(private, public_bytes):
    try:
        return private.exchange(X25519PublicKey.from_public_bytes(public_bytes))
    except ValueError:   # malformed or low-order point (all-zero shared secret)
        raise ProtocolError("bad key share")


def _hkdf(ikm, salt, info, length):
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def _identity_key(es, n_p, pub_p):
    return _hkdf(es, n_p, tlv(PROTO, b"identity", pub_p), 32)


def seal_identity(es, n_p, pub_p, role, ident):
    """Encrypts role||id under DH(peer ephemeral, controller static), padded to fixed size."""
    plain = tlv(role.encode(), ident.encode())
    if len(plain) > IDENTITY_PLAINTEXT_SIZE:
        raise ValueError("identity too long")
    padded = plain + b"\0" * (IDENTITY_PLAINTEXT_SIZE - len(plain))
    # The key is fresh per handshake (fresh ephemeral), so a fixed nonce is safe.
    return AESGCM(_identity_key(es, n_p, pub_p)).encrypt(
        b"\0" * 12, padded, tlv(PROTO, n_p, pub_p))


def open_identity(es, n_p, pub_p, ciphertext):
    """Returns (role, id) or None if the ciphertext does not open or is malformed."""
    try:
        padded = AESGCM(_identity_key(es, n_p, pub_p)).decrypt(
            b"\0" * 12, ciphertext, tlv(PROTO, n_p, pub_p))
        parts, offset = [], 0
        for _ in range(2):
            (n,) = struct.unpack(">H", padded[offset:offset + 2])
            parts.append(padded[offset + 2:offset + 2 + n].decode())
            offset += 2 + n
        if offset > len(padded) or any(padded[offset:]):
            return None
        return parts[0], parts[1]
    except (InvalidTag, struct.error, UnicodeDecodeError):
        return None


def transcript_hash(role, ident, n_p, pub_p, id_ct, n_c, pub_c):
    return hashlib.sha256(tlv(PROTO, role.encode(), ident.encode(),
                              n_p, pub_p, id_ct, n_c, pub_c)).digest()


def key_schedule(psk, es, ee, n_p, n_c, th):
    """All handshake and session keys depend on the PSK, the static-ephemeral DH (es),
    the ephemeral-ephemeral DH (ee) and the whole transcript.  Returns
    (mac_peer, mac_ctrl, key_peer_to_controller, key_controller_to_peer)."""
    okm = _hkdf(psk + es + ee, n_p + n_c, tlv(PROTO, b"key schedule", th), 128)
    return okm[:32], okm[32:64], okm[64:96], okm[96:]


# ------------------------------------------------- user secrets at rest
def _wrap_pad(pin, salt, n):
    return Scrypt(salt=salt, length=64, n=n, r=8, p=1).derive(pin.encode())


def wrap_user_secrets(psk, signing_seed, pin):
    """Encrypts the user's PSK and Ed25519 seed under a PIN-derived pad.

    Deliberately *no* authentication tag and *no* public key in the file: every PIN
    guess yields a well-formed candidate key, so a stolen config file gives the attacker
    no way to test guesses offline.  A guess can only be tested online against the
    controller, which counts failures per identity (see controller.py)."""
    if not isinstance(pin, str) or len(pin) < MIN_STEP_UP_PIN_LENGTH:
        raise ValueError("PIN must contain at least 8 characters")
    if len(psk) != 32 or len(signing_seed) != 32:
        raise ValueError("secrets must be 32 bytes each")
    salt = os.urandom(16)
    pad = _wrap_pad(pin, salt, SECRET_WRAP_SCRYPT_N)
    wrapped = bytes(a ^ b for a, b in zip(psk + signing_seed, pad))
    return {"wrap_salt": salt.hex(), "wrap_scrypt_n": SECRET_WRAP_SCRYPT_N,
            "wrapped_secrets": wrapped.hex()}


def unwrap_user_secrets(config, pin):
    """Returns (psk, signing_seed).  A wrong PIN returns wrong-but-valid-looking keys."""
    if "wrapped_secrets" not in config:
        raise ValueError("config predates smarthome-v2; re-run provision.py or re-enroll")
    if config.get("wrap_scrypt_n") != SECRET_WRAP_SCRYPT_N:
        raise ValueError("unsupported Scrypt cost in config")
    wrapped = bytes.fromhex(config["wrapped_secrets"])
    if len(wrapped) != 64:
        raise ValueError("corrupt wrapped secrets")
    pad = _wrap_pad(pin, bytes.fromhex(config["wrap_salt"]), SECRET_WRAP_SCRYPT_N)
    secrets = bytes(a ^ b for a, b in zip(wrapped, pad))
    return secrets[:32], secrets[32:]


def command_auth_payload(user_id, device_id, command, nonce, issued_at):
    """Exact bytes a user signs for every command.  For UNLOCK the nonce is the
    device-issued one-use challenge; otherwise it is a fresh random value."""
    return json.dumps({"proto": PROTO.decode(), "user_id": user_id, "device_id": device_id,
                       "command": command, "nonce": nonce, "issued_at": issued_at},
                      sort_keys=True, separators=(",", ":")).encode()


# ---------------------------------------------------------------- channel
class Channel:
    """Authenticated-encrypted, replay-protected message stream over a socket."""

    def __init__(self, sock, send_key, recv_key, send_label, recv_label,
                 clock_offset=0, max_session_age=MAX_SESSION_AGE,
                 max_messages=MAX_SESSION_MESSAGES):
        self.sock = sock
        self._s, self._r = AESGCM(send_key), AESGCM(recv_key)
        self._sl, self._rl = send_label, recv_label
        self.send_seq = 0
        self.recv_seq = 0
        self.clock_offset = clock_offset
        self.max_session_age = max_session_age
        self.max_messages = max_messages
        self.started_at = time.monotonic()

    def remaining_lifetime(self):
        return max(0, self.max_session_age - (time.monotonic() - self.started_at))

    def needs_rehandshake(self, messages=1, safety_margin=1):
        return (self.remaining_lifetime() <= safety_margin or
                self.send_seq + messages >= self.max_messages or
                self.recv_seq + messages >= self.max_messages)

    def now(self):
        """Current time on the controller's clock (as estimated by this side)."""
        return time.time() + self.clock_offset

    def _check_expiry(self, sequence):
        if self.remaining_lifetime() <= 0 or sequence >= self.max_messages:
            raise SessionExpiredError("session limit reached; reconnect required")

    def send(self, obj, _ts=None):
        """_ts lets tests forge a stale timestamp; never used in normal code."""
        self._check_expiry(self.send_seq + 1)
        self.send_seq += 1
        seq = self.send_seq
        body = dict(obj, ts=int(self.now()) if _ts is None else _ts)
        encoded = json.dumps(body, separators=(",", ":")).encode()
        if len(encoded) + 4 > CHANNEL_PLAINTEXT_SIZE:
            raise ProtocolError("message too large for padded channel frame")
        padded = (len(encoded).to_bytes(4, "big") + encoded +
                  os.urandom(CHANNEL_PLAINTEXT_SIZE - len(encoded) - 4))
        ct = self._s.encrypt(seq.to_bytes(12, "big"), padded,
                             self._sl + seq.to_bytes(8, "big"))
        send_frame(self.sock, {"type": "DATA", "seq": seq, "ct": ct.hex()})

    def recv(self, *, initial_ready=False):
        self._check_expiry(self.recv_seq + 1)
        return self.open(recv_frame(self.sock), initial_ready=initial_ready)

    def open(self, msg, *, initial_ready=False):
        """Decrypts and checks one already-received DATA frame."""
        self._check_expiry(self.recv_seq + 1)
        seq = msg.get("seq")
        if msg.get("type") != "DATA" or not isinstance(seq, int) or not 0 < seq < 2 ** 62:
            raise ProtocolError("expected DATA frame")
        try:
            ct = bytes.fromhex(msg["ct"])
            pt = self._r.decrypt(seq.to_bytes(12, "big"), ct,
                                 self._rl + seq.to_bytes(8, "big"))
        except InvalidTag:
            raise TamperError("authentication tag mismatch")
        except (KeyError, TypeError, ValueError):
            raise ProtocolError("malformed DATA frame")
        if seq <= self.recv_seq:
            raise ReplayError("sequence %d already seen (last=%d)" % (seq, self.recv_seq))
        if seq != self.recv_seq + 1:
            raise ProtocolError("missing messages (got %d, expected %d)" % (seq, self.recv_seq + 1))
        if len(pt) != CHANNEL_PLAINTEXT_SIZE or len(pt) < 4:
            raise ProtocolError("invalid padded message")
        body_len = int.from_bytes(pt[:4], "big")
        if body_len > CHANNEL_PLAINTEXT_SIZE - 4:
            raise ProtocolError("invalid padded message length")
        try:
            body = json.loads(pt[4:4 + body_len])
        except (ValueError, UnicodeDecodeError):
            raise ProtocolError("malformed encrypted message")
        if not isinstance(body, dict):
            raise ProtocolError("encrypted message is not an object")
        if initial_ready and (seq != 1 or body.get("type") != "READY"):
            raise ProtocolError("timestamp bypass is only valid for the initial READY")
        ts = body.get("ts", 0)
        if not initial_ready and (not isinstance(ts, (int, float)) or
                                  abs(self.now() - ts) > TS_WINDOW):
            raise StaleError("timestamp outside %ds window" % TS_WINDOW)
        self.recv_seq = seq
        return body


# -------------------------------------------------------------- handshake
#
#   Peer P (user/device)                                   Controller C (static key s, S=g^s)
#   x fresh; es = DH(x,S)
#   HELLO {N_p, X, Enc_es(role||id)}            ---->     es = DH(s,X); open identity; look up K
#                                               <----     CHALLENGE {N_c, Y}         (no MAC!)
#   ee = DH(x,Y); th = H(role,id,N_p,X,idct,N_c,Y); keys = HKDF(K||es||ee, N_p||N_c, th)
#   FINISH {HMAC(mac_peer, "PEER", th)}         ---->     verify => P knows K (and x)
#                                               <----     READY (AEAD k_c2p, seq 1) incl.
#                                                         HMAC(mac_ctrl, "CTRL", th)
#   verify READY => C knows K *and* s
#
def initiator_handshake(sock, role, ident, key, controller_public):
    """Run by a user or a device towards the controller. Returns a Channel."""
    if not isinstance(controller_public, bytes) or len(controller_public) != 32:
        raise ValueError("pinned controller public key must be 32 bytes")
    eph = X25519PrivateKey.generate()
    pub_p, n_p = _pub_bytes(eph), os.urandom(16)
    es = _dh(eph, controller_public)
    id_ct = seal_identity(es, n_p, pub_p, role, ident)
    send_frame(sock, {"type": "HELLO", "nonce": n_p.hex(), "pub": pub_p.hex(),
                      "id": id_ct.hex()})
    msg = recv_frame(sock)
    if msg.get("type") == "ERROR":
        raise AuthError(msg.get("reason", "rejected"))
    if msg.get("type") != "CHALLENGE":
        raise ProtocolError("expected CHALLENGE")
    n_c, pub_c = _field(msg, "nonce", 16), _field(msg, "pub", 32)
    ee = _dh(eph, pub_c)
    th = transcript_hash(role, ident, n_p, pub_p, id_ct, n_c, pub_c)
    mac_peer, mac_ctrl, k_p2c, k_c2p = key_schedule(key, es, ee, n_p, n_c, th)
    send_frame(sock, {"type": "FINISH", "mac": mac(mac_peer, b"PEER", th).hex()})
    ch = Channel(sock, k_p2c, k_c2p, b"P2C", b"C2P")
    reply = recv_frame(sock)
    if reply.get("type") == "ERROR":
        raise AuthError(reply.get("reason", "rejected"))
    try:
        ready = ch.open(reply, initial_ready=True)
    except TamperError:
        # Only a party knowing K *and* the controller's static private key can produce it.
        raise AuthError("controller authentication failed")
    confirm = ready.get("confirm")
    if not isinstance(confirm, str) or not hmac.compare_digest(
            confirm, mac(mac_ctrl, b"CTRL", th).hex()):
        raise AuthError("controller authentication failed")
    controller_time = ready.get("controller_time")
    if not isinstance(controller_time, (int, float)):
        raise ProtocolError("missing controller time in READY")
    ch.clock_offset = controller_time - time.time()
    session_age = ready.get("session_age")
    session_messages = ready.get("session_messages")
    if not isinstance(session_age, (int, float)) or not 0 < session_age <= MAX_SESSION_AGE \
            or not isinstance(session_messages, int) or \
            not 4 <= session_messages <= MAX_SESSION_MESSAGES:
        raise ProtocolError("invalid session limits in READY")
    ch.max_session_age = session_age
    ch.max_messages = session_messages
    return ch


def responder_handshake(sock, lookup, static_private, max_session_age=MAX_SESSION_AGE,
                        max_messages=MAX_SESSION_MESSAGES):
    """Run by the controller. lookup(role, id) -> key bytes or None.
    Returns (role, id, Channel).

    Unknown, locked or undecryptable identities follow exactly the same path with a
    random dummy key and fail only at FINISH with the same error, so valid IDs cannot
    be enumerated.  The CHALLENGE carries no PSK-dependent value, so an attacker who
    stole a PIN-wrapped config learns one bit (accept/reject) per online attempt."""
    msg = recv_frame(sock)
    if msg.get("type") != "HELLO":
        raise ProtocolError("expected HELLO")
    n_p, pub_p = _field(msg, "nonce", 16), _field(msg, "pub", 32)
    id_ct = _field(msg, "id", IDENTITY_CIPHERTEXT_SIZE)
    es = _dh(static_private, pub_p)
    identity = open_identity(es, n_p, pub_p, id_ct)
    role, ident = identity if identity else ("?", "?")
    key = lookup(role, ident) if role in ("user", "device") else None
    known = key is not None
    if not known:
        key = os.urandom(32)
    eph, n_c = X25519PrivateKey.generate(), os.urandom(16)
    pub_c = _pub_bytes(eph)
    ee = _dh(eph, pub_p)
    th = transcript_hash(role, ident, n_p, pub_p, id_ct, n_c, pub_c)
    mac_peer, mac_ctrl, k_p2c, k_c2p = key_schedule(key, es, ee, n_p, n_c, th)
    send_frame(sock, {"type": "CHALLENGE", "nonce": n_c.hex(), "pub": pub_c.hex()})
    fin = recv_frame(sock)
    try:
        fin_mac = _field(fin, "mac", 32)
    except ProtocolError:
        fin_mac = b""
    if fin.get("type") != "FINISH" or not known or \
            not hmac.compare_digest(fin_mac, mac(mac_peer, b"PEER", th)):
        send_frame(sock, {"type": "ERROR", "reason": "authentication failed"})
        raise AuthError("authentication failed for %s %r" % (role, ident),
                        role=role, ident=ident, known=known)
    ch = Channel(sock, k_c2p, k_p2c, b"C2P", b"P2C",
                 max_session_age=max_session_age, max_messages=max_messages)
    ch.send({"type": "READY", "controller_time": time.time(),
             "confirm": mac(mac_ctrl, b"CTRL", th).hex(),
             "session_age": max_session_age, "session_messages": max_messages})
    return role, ident, ch
