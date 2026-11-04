"""attacker.py - active/passive network attacker used to test the protocol.

  proxy             man-in-the-middle TCP proxy: eavesdrop | replay | tamper
  fake-user         tries to log in as a user without the key
  fake-device       tries to register as a device without the key
  rogue-controller  impersonates the controller towards a user/device
                    (--leaked-psk-from CONFIG: even knowing the victim's PSK)
  stolen-config     has a user's config file but not the PIN; tries PIN guesses

Example (three terminals already running controller/device):
  python attacker.py proxy --mode replay --listen 9100 --target 9000
  python user.py config/user_hari.json --port 9100 --cmd light1:TURN_ON

The controller's static *public* key is public information; commands that need it
read it from a config file (default config/device_light1.json).
"""
import argparse
import json
import os
import socket
import threading

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from common import (AuthError, Channel, ProtocolError, _dh, _pub_bytes, close_socket,
                    key_schedule, mac, recv_frame, seal_identity, send_frame,
                    transcript_hash, unwrap_user_secrets, initiator_handshake)


class Proxy:
    def __init__(self, target, mode="eavesdrop", listen=("127.0.0.1", 0), quiet=False):
        assert mode in ("eavesdrop", "replay", "tamper")
        self.target, self.mode, self.listen, self.quiet = target, mode, listen, quiet
        self.captured = []                      # (direction, frame)

    def log(self, msg):
        if not self.quiet:
            print("[ATTACKER]", msg, flush=True)

    def start(self):
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(self.listen)
        self.srv.listen(8)
        self.port = self.srv.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()
        return self

    def stop(self):
        close_socket(self.srv)

    def _accept(self):
        while True:
            try:
                client, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._session, args=(client,), daemon=True).start()

    def _session(self, client):
        try:
            up = socket.create_connection(self.target, timeout=10)
        except OSError:
            close_socket(client); return
        threading.Thread(target=self._pump, args=(up, client, "S->C"), daemon=True).start()
        self._pump(client, up, "C->S")

    def _describe(self, frame):
        if frame.get("type") == "DATA":
            return "DATA seq=%s ciphertext=%s...(%d bytes)" % (
                frame.get("seq"), frame["ct"][:24], len(frame["ct"]) // 2)
        return "%s %s" % (frame.get("type"), {k: str(v)[:16] for k, v in frame.items() if k != "type"})

    def _pump(self, src, dst, direction):
        try:
            while True:
                frame = recv_frame(src)
                self.captured.append((direction, frame))
                self.log("%s %s" % (direction, self._describe(frame)))
                is_cmd = direction == "C->S" and frame.get("type") == "DATA"
                if is_cmd and self.mode == "tamper":
                    ct = frame["ct"]
                    frame = dict(frame, ct=ct[:-1] + ("0" if ct[-1] != "0" else "1"))
                    self.log("   !! flipped one bit of the ciphertext")
                send_frame(dst, frame)
                if is_cmd and self.mode == "replay":
                    self.log("   !! REPLAYING the captured packet")
                    send_frame(dst, frame)
        except (ProtocolError, OSError):
            pass
        finally:
            close_socket(src); close_socket(dst)


def fake_peer(addr, role, ident, controller_public):
    """Speaks the protocol correctly (the controller's public key is public) but with a
    random PSK.  Returns the controller's verdict."""
    s = socket.create_connection(addr, timeout=10)
    try:
        eph, n_p = X25519PrivateKey.generate(), os.urandom(16)
        pub_p = _pub_bytes(eph)
        id_ct = seal_identity(_dh(eph, controller_public), n_p, pub_p, role, ident)
        send_frame(s, {"type": "HELLO", "nonce": n_p.hex(), "pub": pub_p.hex(),
                       "id": id_ct.hex()})
        recv_frame(s)
        send_frame(s, {"type": "FINISH", "mac": mac(os.urandom(32), b"PEER").hex()})
        reply = recv_frame(s)
        return "rejected: %s" % reply.get("reason") if reply.get("type") == "ERROR" \
            else "ACCEPTED (!!)"
    except (ProtocolError, OSError) as e:
        return "rejected: %s" % e
    finally:
        close_socket(s)


class RogueController:
    """Pretends to be the controller and runs the whole handshake, including a READY.

    Without `leaked_psk` it uses a random key.  With the victim's leaked PSK it is the
    strongest network impostor possible, but it still lacks the controller's static
    private key, so it cannot compute es = DH(s, X) and the victim rejects READY."""

    def __init__(self, listen=("127.0.0.1", 0), leaked_psk=None, assumed=("user", "hari"),
                 static_private=None):
        # static_private exists only so tests can show the attack *would* work with it.
        self.leaked_psk, self.assumed, self.static_private = leaked_psk, assumed, static_private
        self.srv = socket.socket()
        self.srv.bind(listen)
        self.srv.listen(2)
        self.port = self.srv.getsockname()[1]

    def start(self):
        threading.Thread(target=self._run, daemon=True).start()
        return self

    def _run(self):
        try:
            c, _ = self.srv.accept()
            hello = recv_frame(c)
            n_p, pub_p = bytes.fromhex(hello["nonce"]), bytes.fromhex(hello["pub"])
            id_ct = bytes.fromhex(hello["id"])
            guessed_static = self.static_private or X25519PrivateKey.generate()  # real one unknown
            eph, n_c = X25519PrivateKey.generate(), os.urandom(16)
            pub_c = _pub_bytes(eph)
            send_frame(c, {"type": "CHALLENGE", "nonce": n_c.hex(), "pub": pub_c.hex()})
            recv_frame(c)
            role, ident = self.assumed
            th = transcript_hash(role, ident, n_p, pub_p, id_ct, n_c, pub_c)
            _, mac_ctrl, k_p2c, k_c2p = key_schedule(
                self.leaked_psk or os.urandom(32), _dh(guessed_static, pub_p),
                _dh(eph, pub_p), n_p, n_c, th)
            Channel(c, k_c2p, k_p2c, b"C2P", b"P2C").send(
                {"type": "READY", "controller_time": 0,
                 "confirm": mac(mac_ctrl, b"CTRL", th).hex(),
                 "session_age": 900, "session_messages": 10000})
            recv_frame(c)
        except (ProtocolError, OSError, KeyError, ValueError):
            pass

    def stop(self):
        close_socket(self.srv)


def guess_pins(addr, stolen_config, guesses):
    """Attacker holds a user's config file but not the PIN.

    Offline, every guess unwraps to a well-formed 32-byte PSK and Ed25519 seed (no tag,
    no public key in the file), so nothing distinguishes the right PIN.  The only test is
    an online handshake, which the controller counts and throttles per identity.
    Returns a list of (guess, verdict)."""
    controller_public = bytes.fromhex(stolen_config["controller_public_key"])
    results = []
    for guess in guesses:
        psk, _ = unwrap_user_secrets(stolen_config, guess)      # always "works" offline
        s = socket.create_connection(addr, timeout=10)
        try:
            initiator_handshake(s, "user", stolen_config["user_id"], psk, controller_public)
            results.append((guess, "ACCEPTED"))
        except AuthError as e:
            results.append((guess, "rejected: %s" % e))
        except (ProtocolError, OSError) as e:
            results.append((guess, "error: %s" % e))
        finally:
            close_socket(s)
    return results


def _controller_public(path):
    with open(path) as f:
        return bytes.fromhex(json.load(f)["controller_public_key"])


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("proxy")
    p.add_argument("--mode", choices=["eavesdrop", "replay", "tamper"], default="eavesdrop")
    p.add_argument("--listen", type=int, default=9100)
    p.add_argument("--target", type=int, default=9000)
    for name in ("fake-user", "fake-device"):
        q = sub.add_parser(name)
        q.add_argument("id")
        q.add_argument("--port", type=int, default=9000)
        q.add_argument("--pubkey-from", default="config/device_light1.json")
    r = sub.add_parser("rogue-controller")
    r.add_argument("--listen", type=int, default=9000)
    r.add_argument("--leaked-psk-from", metavar="CONTROLLER_CONFIG",
                   help="give the impostor the victim's real PSK (from controller.json)")
    r.add_argument("--victim", default="hari")
    g = sub.add_parser("stolen-config")
    g.add_argument("config", help="the stolen user config, e.g. config/user_guest.json")
    g.add_argument("guesses", nargs="+", help="PIN guesses to try online")
    g.add_argument("--port", type=int, default=9000)
    a = ap.parse_args()
    if a.cmd == "proxy":
        px = Proxy(("127.0.0.1", a.target), a.mode, ("127.0.0.1", a.listen)).start()
        print("[ATTACKER] %s proxy on :%d -> :%d  (Ctrl+C to stop)" % (a.mode, px.port, a.target))
        threading.Event().wait()
    elif a.cmd in ("fake-user", "fake-device"):
        role = "user" if a.cmd == "fake-user" else "device"
        print("[ATTACKER] login as %s %r:" % (role, a.id),
              fake_peer(("127.0.0.1", a.port), role, a.id, _controller_public(a.pubkey_from)))
    elif a.cmd == "stolen-config":
        with open(a.config) as f:
            stolen = json.load(f)
        for guess, verdict in guess_pins(("127.0.0.1", a.port), stolen, a.guesses):
            print("[ATTACKER] PIN guess %-16r -> %s" % (guess, verdict))
    else:
        psk = None
        if a.leaked_psk_from:
            with open(a.leaked_psk_from) as f:
                psk = bytes.fromhex(json.load(f)["users"][a.victim]["key"])
        rc = RogueController(("127.0.0.1", a.listen), psk, ("user", a.victim)).start()
        print("[ATTACKER] rogue controller on :%d - point a user at it" % rc.port)
        threading.Event().wait()


if __name__ == "__main__":
    main()
