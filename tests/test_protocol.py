import contextlib
import io
import os
import json
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import common as c
import controller as controller_module
from controller import Controller
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import attacker
import demo
import provision
from device import Device
from user import UserClient

PIN = demo.PIN
STATIC = X25519PrivateKey.generate()
STATIC_PUB = c._pub_bytes(STATIC)


def static_hex():
    return STATIC.private_bytes_raw().hex()


def signed(private_key, user, device, command, nonce=None, issued_at=None, **extra):
    """A COMMAND as the controller forwards it to a device, signed by `private_key`."""
    nonce = nonce or os.urandom(16).hex()
    issued_at = int(time.time()) if issued_at is None else issued_at
    body = {"type": "COMMAND", "device_id": device, "command": command,
            "on_behalf_of": user, "nonce": nonce, "issued_at": issued_at,
            "signature": private_key.sign(c.command_auth_payload(
                user, device, command, nonce, issued_at)).hex()}
    body.update(extra)
    return body


def channel_pair():
    """x (peer side) <-> y (controller side), with raw sockets a, b exposed."""
    a, b = socket.socketpair()
    k1, k2 = os.urandom(32), os.urandom(32)
    return c.Channel(a, k1, k2, b"P2C", b"C2P"), c.Channel(b, k2, k1, b"C2P", b"P2C"), a, b


class TestChannel(unittest.TestCase):
    def test_roundtrip(self):
        x, y, *_ = channel_pair()
        x.send({"hello": "world"})
        self.assertEqual(y.recv()["hello"], "world")

    def test_tamper_detected(self):
        x, y, a, b = channel_pair()
        x.send({"m": 1})
        f = c.recv_frame(b)
        f["ct"] = f["ct"][:-1] + ("0" if f["ct"][-1] != "0" else "1")
        c.send_frame(a, f)
        with self.assertRaises(c.TamperError):
            y.recv()

    def test_replay_detected(self):
        x, y, a, b = channel_pair()
        x.send({"m": 1})
        f = c.recv_frame(b)
        c.send_frame(a, f); c.send_frame(a, f)
        y.recv()
        with self.assertRaises(c.ReplayError):
            y.recv()

    def test_stale_detected(self):
        x, y, *_ = channel_pair()
        x.send({"m": 1}, _ts=int(time.time()) - 999)
        with self.assertRaises(c.StaleError):
            y.recv()

    def test_dropped_message_detected(self):
        x, y, a, b = channel_pair()
        x.send({"m": 1}); c.recv_frame(b)      # attacker swallows message 1
        x.send({"m": 2})
        with self.assertRaises(c.ProtocolError):
            y.recv()

    def test_reflection_rejected(self):
        """A frame cannot be bounced back to its sender (direction labels in AAD/keys)."""
        x, y, a, b = channel_pair()
        x.send({"m": 1})
        f = c.recv_frame(b)
        c.send_frame(b, f)
        with self.assertRaises(c.TamperError):
            x.recv()

    def test_same_plaintext_different_ciphertext(self):
        x, y, a, b = channel_pair()
        x.send({"m": 1}); x.send({"m": 1})
        first, second = c.recv_frame(b), c.recv_frame(b)
        self.assertNotEqual(first["ct"], second["ct"])
        self.assertEqual(len(first["ct"]), len(second["ct"]))

    def test_session_expires_by_age_and_message_count(self):
        a, b = socket.socketpair()
        sender = c.Channel(a, os.urandom(32), os.urandom(32), b"P2C", b"C2P",
                           max_session_age=0.01)
        time.sleep(0.02)
        with self.assertRaises(c.SessionExpiredError):
            sender.send({"m": 1})
        a.close(); b.close()

        a, b = socket.socketpair()
        send_key, recv_key = os.urandom(32), os.urandom(32)
        sender = c.Channel(a, send_key, recv_key, b"P2C", b"C2P", max_messages=2)
        receiver = c.Channel(b, recv_key, send_key, b"C2P", b"P2C", max_messages=2)
        sender.send({"m": 1})
        self.assertEqual(receiver.recv()["m"], 1)
        with self.assertRaises(c.SessionExpiredError):
            sender.send({"m": 2})
        a.close(); b.close()

    def test_randomized_malformed_frames_fail_cleanly(self):
        import random
        rng = random.Random(80210)
        for _ in range(100):
            sender, receiver = socket.socketpair()
            receiver.settimeout(0.2)
            payload = os.urandom(rng.randint(0, 48))
            sender.sendall(len(payload).to_bytes(4, "big") + payload)
            try:
                try:
                    result = c.recv_frame(receiver)
                    self.assertIsInstance(result, dict)
                except c.ProtocolError:
                    pass
            finally:
                sender.close()
                receiver.close()

    def test_randomized_handshake_frames_fail_without_hanging(self):
        import random
        rng = random.Random(104729)
        for _ in range(30):
            client, server = socket.socketpair()
            server.settimeout(0.2)
            payload = os.urandom(rng.randint(1, 48))
            client.sendall(len(payload).to_bytes(4, "big") + payload)
            try:
                with self.assertRaises((c.ProtocolError, OSError)):
                    c.responder_handshake(server, lambda role, ident: None, STATIC)
            finally:
                client.close()
                server.close()


class TestHandshake(unittest.TestCase):
    def run_hs(self, key_client, key_server, known=True, pinned=STATIC_PUB, server_static=STATIC,
               ident="hari"):
        a, b = socket.socketpair()
        out = {}

        def server():
            try:
                out["r"] = c.responder_handshake(
                    b, lambda r, i: key_server if known else None, server_static)
            except (c.ProtocolError, OSError) as e:
                out["e"] = e
        t = threading.Thread(target=server); t.start()
        try:
            ch = c.initiator_handshake(a, "user", ident, key_client, pinned)
        except c.ProtocolError as e:
            ch = e
        if isinstance(ch, c.AuthError):
            a.close()
        t.join(3)
        if isinstance(ch, c.AuthError):
            b.close()
        return ch, out, a

    def test_success_and_two_way_traffic(self):
        k = os.urandom(32)
        ch, out, sock = self.run_hs(k, k)
        _, _, sch = out["r"]
        try:
            self.assertIsInstance(ch, c.Channel)
            self.assertLess(abs(ch.clock_offset), 1)
            ch.send({"x": 1}); self.assertEqual(sch.recv()["x"], 1)
            sch.send({"y": 2}); self.assertEqual(ch.recv()["y"], 2)
        finally:
            sock.close()
            sch.sock.close()

    def test_handshake_accepts_clock_skew_over_timestamp_window(self):
        key = os.urandom(32)
        original_time = time.time
        client_thread = threading.current_thread()

        def skewed_time():
            return original_time() + (120 if threading.current_thread() is client_thread else 0)

        with patch("common.time.time", side_effect=skewed_time):
            ch, out, sock = self.run_hs(key, key)
            _, _, server_channel = out["r"]
            try:
                self.assertIsInstance(ch, c.Channel)
                self.assertAlmostEqual(ch.clock_offset, -120, delta=1)
                received = {}
                receiver = threading.Thread(
                    target=lambda: received.setdefault("message", server_channel.recv()))
                receiver.start()
                ch.send({"command": "after-clock-sync"})
                receiver.join(2)
                self.assertEqual(received["message"]["command"], "after-clock-sync")
            finally:
                sock.close()
                server_channel.sock.close()

    def test_wrong_key_rejected(self):
        ch, out, _ = self.run_hs(os.urandom(32), os.urandom(32))
        self.assertIsInstance(ch, c.AuthError)

    def test_secret_wrap_rejects_short_pin(self):
        with self.assertRaisesRegex(ValueError, "at least 8 characters"):
            c.wrap_user_secrets(os.urandom(32), os.urandom(32), "123456")

    def test_wrapped_secrets_give_no_offline_pin_oracle(self):
        psk, seed = os.urandom(32), os.urandom(32)
        cfg = c.wrap_user_secrets(psk, seed, PIN)
        self.assertEqual(c.unwrap_user_secrets(cfg, PIN), (psk, seed))
        candidates = set()
        for guess in ("00000000", "password", "demo-pin-1235"):
            wrong_psk, wrong_seed = c.unwrap_user_secrets(cfg, guess)   # no exception
            self.assertEqual((len(wrong_psk), len(wrong_seed)), (32, 32))
            Ed25519PrivateKey.from_private_bytes(wrong_seed)              # still "valid"
            candidates.add(wrong_psk)
        self.assertEqual(len(candidates), 3)
        self.assertNotIn(psk, candidates)
        user_cfg = provision.make_config(pin=PIN)["users"]["hari"]
        self.assertFalse({"key", "signing_public_key", "signing_private_key"} & set(user_cfg))

    def test_identity_is_encrypted_fixed_size_and_unlinkable(self):
        frames = []
        for ident in ("hari", "a-much-longer-user-identifier"):
            for _ in range(2):
                a, b = socket.socketpair()
                worker = threading.Thread(target=lambda: self._swallow(a, ident))
                worker.start()
                frames.append(c.recv_frame(b))
                a.close(); b.close(); worker.join(1)
        wire = json.dumps(frames)
        self.assertNotIn("hari", wire)
        self.assertNotIn(b"hari".hex(), wire)
        self.assertNotIn("role", frames[0])
        self.assertEqual(len({len(f["id"]) for f in frames}), 1)       # length hides id size
        self.assertEqual(len({f["id"] for f in frames}), len(frames))  # never repeats

    @staticmethod
    def _swallow(sock, ident):
        try:
            c.initiator_handshake(sock, "user", ident, os.urandom(32), STATIC_PUB)
        except (c.ProtocolError, OSError):
            pass

    def test_challenge_carries_no_psk_dependent_value(self):
        """Peer proves first: an attacker holding a stolen PIN-wrapped config gets no MAC
        from the controller to test PIN guesses against offline."""
        a, b = socket.socketpair()

        def serve():
            try:
                c.responder_handshake(b, lambda r, i: os.urandom(32), STATIC)
            except (c.ProtocolError, OSError):
                pass
        t = threading.Thread(target=serve); t.start()
        eph = X25519PrivateKey.generate()
        n_p, pub_p = os.urandom(16), c._pub_bytes(eph)
        c.send_frame(a, {"type": "HELLO", "nonce": n_p.hex(), "pub": pub_p.hex(),
                         "id": c.seal_identity(eph.exchange(STATIC.public_key()), n_p, pub_p,
                                               "user", "hari").hex()})
        captured = c.recv_frame(a)
        a.close(); b.close(); t.join(2)
        self.assertEqual(set(captured), {"type", "nonce", "pub"})

    def test_wrong_pinned_controller_key_fails(self):
        k = os.urandom(32)
        impostor = X25519PrivateKey.generate()
        ch, out, _ = self.run_hs(k, k, server_static=impostor)
        self.assertIsInstance(ch, c.AuthError)

    def test_leaked_psk_alone_cannot_impersonate_controller(self):
        psk = os.urandom(32)
        cfg = {"user_id": "hari", "controller": {"host": "127.0.0.1", "port": 1},
               "controller_public_key": STATIC_PUB.hex()}
        cfg.update(c.wrap_user_secrets(psk, os.urandom(32), PIN))
        rogue = attacker.RogueController(leaked_psk=psk).start()
        try:
            with self.assertRaisesRegex(c.AuthError, "controller authentication failed"):
                UserClient(cfg, port=rogue.port, pin_callback=lambda: PIN).connect()
        finally:
            rogue.stop()
        # Positive control: with the controller's static key too, the impostor gets through,
        # so it is the static key that stops the attack above.
        rogue = attacker.RogueController(leaked_psk=psk, static_private=STATIC).start()
        try:
            client = UserClient(cfg, port=rogue.port, pin_callback=lambda: PIN).connect()
            self.assertIsNotNone(client.ch)      # victim accepted the impostor
            client.close()
        finally:
            rogue.stop()

    def test_unknown_id_rejected(self):
        ch, out, _ = self.run_hs(os.urandom(32), None, known=False)
        self.assertIsInstance(ch, c.AuthError)

    def test_session_keys_are_fresh(self):
        k = os.urandom(32)
        ch1, o1, sock1 = self.run_hs(k, k)
        ch2, o2, sock2 = self.run_hs(k, k)
        try:
            # same long-term key => session keys must still differ per session
            self.assertNotEqual(ch1._s.encrypt(b"\0" * 12, b"x", b""),
                                ch2._s.encrypt(b"\0" * 12, b"x", b""))
        finally:
            sock1.close()
            o1["r"][2].sock.close()
            sock2.close()
            o2["r"][2].sock.close()

    def test_forward_secrecy_against_later_psk_and_static_key_disclosure(self):
        """Recorded session + later leak of BOTH the PSK and the controller static key:
        the attacker can recompute es, but not ee, so the session key stays secret."""
        psk = os.urandom(32)
        n_p, n_c = os.urandom(16), os.urandom(16)
        peer_eph, ctrl_eph = X25519PrivateKey.generate(), X25519PrivateKey.generate()
        pub_p, pub_c = c._pub_bytes(peer_eph), c._pub_bytes(ctrl_eph)
        es = STATIC.exchange(peer_eph.public_key())
        id_ct = c.seal_identity(es, n_p, pub_p, "user", "hari")
        th = c.transcript_hash("user", "hari", n_p, pub_p, id_ct, n_c, pub_c)
        _, _, send_key, _ = c.key_schedule(
            psk, es, peer_eph.exchange(ctrl_eph.public_key()), n_p, n_c, th)
        client_sock, controller_sock = socket.socketpair()
        sender = c.Channel(client_sock, send_key, os.urandom(32), b"P2C", b"C2P")
        sender.send({"type": "COMMAND", "command": "UNLOCK"})
        frame = c.recv_frame(controller_sock)

        leaked_es = STATIC.exchange(X25519PublicKey.from_public_bytes(pub_p))  # static leaked
        self.assertEqual(c.open_identity(leaked_es, n_p, pub_p, id_ct), ("user", "hari"))
        _, _, guessed_key, _ = c.key_schedule(psk, leaked_es, os.urandom(32), n_p, n_c, th)
        sequence = frame["seq"]
        try:
            with self.assertRaises(InvalidTag):
                AESGCM(guessed_key).decrypt(
                    sequence.to_bytes(12, "big"), bytes.fromhex(frame["ct"]),
                    b"P2C" + sequence.to_bytes(8, "big"))
        finally:
            client_sock.close()
            controller_sock.close()

    def test_known_and_unknown_identity_failure_timing_is_similar(self):
        known_key = os.urandom(32)
        durations = {"known": [], "unknown": []}
        for _ in range(6):
            started = time.perf_counter()
            known, _, _ = self.run_hs(os.urandom(32), known_key, known=True)
            durations["known"].append(time.perf_counter() - started)
            started = time.perf_counter()
            unknown, _, _ = self.run_hs(os.urandom(32), None, known=False)
            durations["unknown"].append(time.perf_counter() - started)
            self.assertIsInstance(known, c.AuthError)
            self.assertIsInstance(unknown, c.AuthError)
        average_known = sum(durations["known"]) / len(durations["known"])
        average_unknown = sum(durations["unknown"]) / len(durations["unknown"])
        self.assertLess(abs(average_known - average_unknown), 0.1)


class TestDevice(unittest.TestCase):
    def mk(self, **kw):
        cfg = {"device_id": "door1", "type": "lock", "key": "00" * 32,
               "controller": {"host": "x", "port": 1}}
        cfg.update(kw)
        return Device(cfg, quiet=True)

    def test_device_side_authorization(self):
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        d = self.mk(allowed_users=["hari"], signing_public_keys={"hari": public_key.hex()})
        r = d.execute({"type": "COMMAND", "device_id": "door1", "command": "UNLOCK", "on_behalf_of": "guest"})
        self.assertEqual((r["status"], d.state), ("DENIED", "LOCKED"))
        challenge = d.execute({"type": "STEP_UP_CHALLENGE", "on_behalf_of": "hari"})["challenge"]
        command = signed(private_key, "hari", "door1", "UNLOCK", nonce=challenge)
        r = d.execute(command)
        self.assertEqual((r["status"], d.state), ("OK", "UNLOCKED"))
        replay = d.execute(dict(command))
        self.assertEqual((replay["status"], d.state), ("DENIED", "UNLOCKED"))

    def test_device_enforces_per_command_acl(self):
        d = self.mk(device_id="light1", type="light", allowed_users=["hari", "viewer"],
                    allowed_commands={"hari": ["TURN_ON", "TURN_OFF", "STATUS"],
                                      "viewer": ["STATUS"]})
        base = {"type": "COMMAND", "device_id": "light1"}
        denied = d.execute(dict(base, command="TURN_ON", on_behalf_of="viewer"))
        self.assertEqual((denied["status"], d.state), ("DENIED", "OFF"))
        self.assertEqual(d.execute(dict(base, command="STATUS", on_behalf_of="viewer"))["status"], "OK")
        self.assertEqual(d.execute(dict(base, command="TURN_ON", on_behalf_of="hari"))["status"], "OK")

    def test_authz_update_installs_and_validates_command_acl(self):
        d = self.mk(device_id="light1", type="light", allowed_users=["hari"])
        ok = d.execute({"type": "UPDATE_AUTHZ", "allowed_users": ["hari", "viewer"],
                        "allowed_commands": {"hari": ["TURN_ON"], "viewer": ["STATUS"]},
                        "signing_public_keys": {}})
        self.assertEqual(ok["status"], "OK")
        self.assertEqual(d.allowed_commands["viewer"], ["STATUS"])
        for bad in ({"hari": ["EXPLODE"]}, {"hari": "TURN_ON"}, ["hari"]):
            r = d.execute({"type": "UPDATE_AUTHZ", "allowed_users": ["hari"],
                           "allowed_commands": bad, "signing_public_keys": {}})
            self.assertEqual(r["status"], "ERROR")
        self.assertEqual(d.allowed_commands["viewer"], ["STATUS"])   # unchanged by bad updates

    def test_unlock_challenge_needs_unlock_in_device_acl(self):
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        d = self.mk(allowed_users=["hari", "viewer"],
                    allowed_commands={"hari": ["UNLOCK", "STATUS"], "viewer": ["STATUS"]},
                    signing_public_keys={"hari": public_key, "viewer": public_key})
        self.assertEqual(d.execute({"type": "STEP_UP_CHALLENGE", "on_behalf_of": "viewer"})["status"], "DENIED")
        self.assertEqual(d.execute({"type": "STEP_UP_CHALLENGE", "on_behalf_of": "hari"})["status"], "OK")

    def test_unlock_auto_relocks_and_step_up_is_rate_limited(self):
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        d = self.mk(allowed_users=["hari"], signing_public_keys={"hari": public_key.hex()},
                   auto_relock_seconds=0.02)
        first = d.execute({"type": "STEP_UP_CHALLENGE", "on_behalf_of": "hari"})
        result = d.execute(signed(private_key, "hari", "door1", "UNLOCK",
                                  nonce=first["challenge"]))
        self.assertEqual(result["status"], "OK")
        time.sleep(0.05)
        self.assertEqual(d.state, "LOCKED")
        for _ in range(4):
            d.execute({"type": "STEP_UP_CHALLENGE", "on_behalf_of": "hari"})
        denied = d.execute({"type": "STEP_UP_CHALLENGE", "on_behalf_of": "hari"})
        self.assertEqual(denied["status"], "DENIED")

    def test_unsupported_command(self):
        d = self.mk(allowed_users=["hari"])
        r = d.execute({"type": "COMMAND", "device_id": "door1", "command": "TURN_ON",
                       "on_behalf_of": "hari"})
        self.assertEqual(r["status"], "ERROR")

    def test_missing_allow_list_fails_closed(self):
        for allow_list in (None, []):
            cfg = {"device_id": "door1", "type": "lock", "key": "00" * 32,
                   "controller": {"host": "x", "port": 1}}
            if allow_list is not None:
                cfg["allowed_users"] = allow_list
            device = Device(cfg, quiet=True)
            response = device.execute({
                "type": "COMMAND", "device_id": "door1", "command": "UNLOCK",
                "on_behalf_of": "hari",
            })
            self.assertEqual((response["status"], device.state), ("DENIED", "LOCKED"))

    def test_controller_cannot_replace_device_pinned_signing_key(self):
        original = Ed25519PrivateKey.generate().public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw).hex()
        attacker_key = Ed25519PrivateKey.generate().public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw).hex()
        device = self.mk(allowed_users=["hari"], signing_public_keys={"hari": original})
        response = device.execute({
            "type": "UPDATE_AUTHZ", "allowed_users": ["hari", "mallory"],
            "signing_public_keys": {"hari": attacker_key, "mallory": attacker_key},
        })
        self.assertEqual(response["status"], "OK")
        self.assertEqual(device.signing_public_keys, {"hari": original})
        self.assertEqual(device.execute({
            "type": "STEP_UP_CHALLENGE", "on_behalf_of": "mallory",
        })["status"], "DENIED")


    def test_device_requires_user_signature_for_pinned_users(self):
        private_key = Ed25519PrivateKey.generate()
        public_hex = private_key.public_key().public_bytes_raw().hex()
        d = self.mk(device_id="light1", type="light", allowed_users=["hari", "newbie"],
                    allowed_commands={"hari": ["TURN_ON", "STATUS"], "newbie": ["STATUS"]},
                    signing_public_keys={"hari": public_hex})
        base = {"type": "COMMAND", "device_id": "light1", "on_behalf_of": "hari"}
        self.assertEqual(d.execute(dict(base, command="TURN_ON"))["status"], "DENIED")
        other = Ed25519PrivateKey.generate()
        self.assertEqual(d.execute(signed(other, "hari", "light1", "TURN_ON"))["status"],
                         "DENIED")
        stale = signed(private_key, "hari", "light1", "TURN_ON",
                       issued_at=int(time.time()) - 120)
        self.assertEqual(d.execute(stale)["detail"], "user signature missing or stale")
        good = signed(private_key, "hari", "light1", "TURN_ON")
        self.assertEqual((d.execute(good)["status"], d.state), ("OK", "ON"))
        self.assertEqual(d.execute(dict(good))["detail"], "replayed signed command")
        # Signature binds the command: same signature on another command fails.
        self.assertEqual(d.execute(dict(good, command="STATUS", nonce=os.urandom(16).hex())
                                   )["status"], "DENIED")
        # User enrolled after provisioning (no pinned key) relies on the controller.
        newbie = {"type": "COMMAND", "device_id": "light1", "on_behalf_of": "newbie",
                  "command": "STATUS"}
        self.assertEqual(d.execute(newbie)["status"], "OK")


class TestController(unittest.TestCase):
    def setUp(self):
        self.config = {
            "static_private_key": static_hex(),
            "users": {"hari": {"key": "01" * 32, "allowed": {}}},
            "devices": {"door1": {"key": "02" * 32, "type": "lock"}},
        }

    def test_duplicate_user_session_is_rejected(self):
        controller = Controller(self.config, quiet=True)
        first, second = socket.socketpair()
        try:
            self.assertIsNone(controller._claim_user_session("hari", first))
            self.assertEqual(controller._claim_user_session("hari", second), "duplicate")
            self.assertIs(controller.user_sessions["hari"], first)
        finally:
            first.close()
            second.close()

    def test_revoke_removes_user_and_closes_session(self):
        controller = Controller(self.config, quiet=True)
        server_sock, client_sock = socket.socketpair()
        controller.user_sessions["hari"] = server_sock

        controller.revoke("hari")

        self.assertNotIn("hari", controller.users)
        self.assertIsNone(controller._lookup("user", "hari"))
        response = controller._process("hari", {"type": "COMMAND"})
        self.assertEqual(response["status"], "DENIED")
        self.assertEqual(server_sock.fileno(), -1)
        client_sock.close()

    def test_audit_hash_chain_survives_restart_and_detects_edits(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "audit.log")
            first = Controller(self.config, audit_path=path, quiet=True)
            first.event("CMD_OK", "hari -> light1 TURN_ON")
            second = Controller(self.config, audit_path=path, quiet=True)
            second.event("USER_REVOKED", "guest")
            self.assertTrue(Controller.verify_audit_log(path))

            with open(path, "r+") as f:
                records = [json.loads(line) for line in f]
                records[0]["detail"] = "edited"
                f.seek(0)
                f.writelines(json.dumps(record) + "\n" for record in records)
                f.truncate()
            self.assertFalse(Controller.verify_audit_log(path))

    def test_pairing_token_enrolls_user_and_is_single_use(self):
        import provision
        config = provision.make_config()
        with tempfile.TemporaryDirectory() as directory:
            config_path = os.path.join(directory, "controller.json")
            with open(config_path, "w") as f:
                json.dump(config["controller"], f)
            controller = Controller(config["controller"], port=0, quiet=True,
                                    config_path=config_path).start()
            try:
                token = controller.issue_pairing_token("alice", {"door1": ["STATUS"]})
                enrolled = UserClient.enroll("alice", token, controller.host,
                                             controller.port, "test-pin-739101")
                self.assertEqual(enrolled["user_id"], "alice")
                self.assertEqual(enrolled["devices"], {"door1": "lock"})
                self.assertEqual(controller.users["alice"]["allowed"],
                                 {"door1": ["STATUS"]})
                psk, seed = c.unwrap_user_secrets(enrolled, "test-pin-739101")
                self.assertEqual(controller.users["alice"]["key"], psk.hex())
                self.assertEqual(controller.users["alice"]["signing_public_key"],
                                 Ed25519PrivateKey.from_private_bytes(seed).public_key()
                                 .public_bytes_raw().hex())
                self.assertEqual(enrolled["controller_public_key"], controller.public_key_hex)
                self.assertIn("alice", controller.devices["door1"]["allowed_users"])
                with self.assertRaises((c.ProtocolError, OSError)):
                    UserClient.enroll("alice", token, controller.host,
                                      controller.port, "test-pin-739101")
            finally:
                controller.stop()

    def test_pairing_updates_active_device_allow_lists(self):
        tb = demo.Testbed(quiet=True)
        client = None
        try:
            token = tb.ctrl.issue_pairing_token("visitor", {"door1": ["STATUS"]})
            config = UserClient.enroll(
                "visitor", token, "127.0.0.1", tb.ctrl.port, "test-pin-739101")
            client = UserClient(config, pin_callback=lambda: "test-pin-739101").connect()
            response = client.command("door1", "STATUS")
            denied = client.command("door1", "UNLOCK")
            self.assertEqual(response["status"], "OK")
            self.assertEqual(denied["status"], "DENIED")
            self.assertIn("visitor", tb.devices["door1"].allowed_users)
        finally:
            if client:
                client.close()
            tb.stop()

    def test_key_rotation_persists_new_user_key(self):
        config = {
            "host": "127.0.0.1", "port": 9000, "static_private_key": static_hex(),
            "users": {"hari": {"key": "01" * 32, "allowed": {}}},
            "devices": {},
        }
        with tempfile.TemporaryDirectory() as directory:
            config_path = os.path.join(directory, "controller.json")
            with open(config_path, "w") as f:
                json.dump(config, f)
            controller = Controller(config, quiet=True, config_path=config_path)
            new_key = os.urandom(32)
            controller.rotate_user_key("hari", new_key)
            with open(config_path) as f:
                persisted = json.load(f)
            self.assertEqual(persisted["users"]["hari"]["key"], new_key.hex())
            self.assertEqual(controller._lookup("user", "hari"), new_key)
            self.assertNotEqual(controller._lookup("user", "hari"), bytes.fromhex("01" * 32))

    def test_user_key_rotation_message_updates_both_sides(self):
        import provision
        generated = provision.make_config()
        controller_config = generated["controller"]
        user_config = generated["users"]["hari"]
        with tempfile.TemporaryDirectory() as directory:
            controller_path = os.path.join(directory, "controller.json")
            user_path = os.path.join(directory, "user.json")
            with open(controller_path, "w") as f:
                json.dump(controller_config, f)
            with open(user_path, "w") as f:
                json.dump(user_config, f)
            old_wrap = {k: user_config[k] for k in ("wrap_salt", "wrapped_secrets")}
            controller = Controller(controller_config, port=0, quiet=True,
                                    config_path=controller_path).start()
            user_config["controller"]["port"] = controller.port
            with open(user_path, "w") as f:
                json.dump(user_config, f)
            client = UserClient(user_config, config_path=user_path,
                                pin_callback=lambda: PIN).connect()
            try:
                response = client.rotate_key()
                self.assertEqual(response["status"], "OK")
                with open(user_path) as f:
                    persisted_user = json.load(f)
                new_psk, _ = c.unwrap_user_secrets(persisted_user, PIN)
                self.assertEqual(controller._lookup("user", "hari"), new_psk)
                renewed_client = UserClient(persisted_user, pin_callback=lambda: PIN).connect()
                renewed_client.close()
                stale_config = dict(persisted_user, **old_wrap)
                with self.assertRaises(c.AuthError):
                    UserClient(stale_config, pin_callback=lambda: PIN).connect()
            finally:
                client.close()
                controller.stop()

    def test_client_rehandshakes_after_session_age_limit(self):
        import provision
        config = provision.make_config()
        controller = Controller(config["controller"], port=0, quiet=True,
                                max_session_age=0.1).start()
        client_config = config["users"]["hari"]
        client_config["controller"]["port"] = controller.port
        client = UserClient(client_config, pin_callback=lambda: PIN).connect()
        try:
            time.sleep(0.12)
            response = client.command("light1", "STATUS")
            self.assertEqual(response["status"], "ERROR")
            self.assertEqual(response["detail"], "device offline")
            self.assertEqual(controller.events.count(
                ("USER_DUPLICATE", "hari already has an active session")), 0)
        finally:
            client.close()
            controller.stop()

    def test_client_reconnects_after_idle_timeout(self):
        import provision
        from unittest.mock import patch
        config = provision.make_config()
        with patch("controller.USER_IDLE_TIMEOUT", 0.2), \
                patch("user.USER_IDLE_TIMEOUT", 0.2):
            controller = Controller(config["controller"], port=0, quiet=True).start()
            client_config = config["users"]["hari"]
            client_config["controller"]["port"] = controller.port
            client = UserClient(client_config, pin_callback=lambda: PIN).connect()
            try:
                time.sleep(0.25)
                response = client.command("light1", "STATUS")
                self.assertEqual(response["status"], "ERROR")
                self.assertEqual(response["detail"], "device offline")
            finally:
                client.close()
                controller.stop()

    def test_duplicate_device_session_does_not_replace_existing(self):
        controller = Controller(self.config, quiet=True)
        first, second = socket.socketpair()
        fake_channel = type("ChannelStub", (), {"remaining_lifetime": lambda self: 1})()
        worker = threading.Thread(
            target=controller._serve_device, args=(first, "door1", fake_channel))
        controller._sync_device_authz = lambda device_id, connection: None
        worker.start()
        try:
            deadline = time.monotonic() + 1
            while "door1" not in controller.registry and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertIn("door1", controller.registry)
            existing = controller.registry["door1"]
            existing.probe = lambda: True

            controller._serve_device(second, "door1", object())

            self.assertIs(controller.registry["door1"], existing)
            self.assertNotEqual(first.fileno(), -1)
            self.assertIn(("DEVICE_DUPLICATE", "door1 already has a live session"),
                          controller.events)
        finally:
            controller.registry["door1"].close()
            worker.join(1)
            first.close()
            second.close()

    def _start_with_idle_connection(self, **options):
        controller = Controller(self.config, port=0, quiet=True, **options).start()
        client = socket.create_connection((controller.host, controller.port), timeout=1)
        deadline = time.monotonic() + 1
        while not controller._connections and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(controller._connections)
        return controller, client

    def test_connection_capacity_rejects_excess_connections(self):
        controller, first = self._start_with_idle_connection(
            max_connections=1, per_ip_limit=100)
        second = None
        try:
            second = socket.create_connection((controller.host, controller.port), timeout=1)
            second.settimeout(1)
            self.assertEqual(second.recv(1), b"")
            self.assertIn("CONNECTION_LIMIT", [kind for kind, _ in controller.events])
        finally:
            first.close()
            if second:
                second.close()
            controller.stop()

    def test_idle_pre_auth_connection_times_out(self):
        controller, client = self._start_with_idle_connection(
            max_connections=2, per_ip_limit=100, pre_auth_timeout=0.05)
        try:
            client.settimeout(1)
            self.assertEqual(client.recv(1), b"")
        finally:
            client.close()
            controller.stop()

    def test_failed_handshakes_are_rate_limited_per_ip(self):
        controller, first = self._start_with_idle_connection(
            max_connections=4, per_ip_limit=1)
        second = None
        try:
            c.send_frame(first, {"type": "INVALID"})
            deadline = time.monotonic() + 1
            while not any(kind == "AUTH_FAIL" for kind, _ in controller.events) \
                    and time.monotonic() < deadline:
                time.sleep(0.01)
            second = socket.create_connection((controller.host, controller.port), timeout=1)
            second.settimeout(1)
            self.assertEqual(second.recv(1), b"")
            self.assertIn("RATE_LIMIT", [kind for kind, _ in controller.events])
        finally:
            first.close()
            if second:
                second.close()
            controller.stop()

    def test_rate_limit_cooldown_allows_later_legitimate_login(self):
        import provision
        config = provision.make_config()
        controller = Controller(config["controller"], port=0, quiet=True,
                                per_ip_limit=1, rate_limit_backoff=0.05).start()
        try:
            junk = socket.create_connection((controller.host, controller.port), timeout=1)
            c.send_frame(junk, {"type": "INVALID"})
            junk.close()
            deadline = time.monotonic() + 1
            while not any(kind == "AUTH_FAIL" for kind, _ in controller.events) \
                    and time.monotonic() < deadline:
                time.sleep(0.01)

            during_backoff = socket.create_connection(
                (controller.host, controller.port), timeout=1)
            during_backoff.settimeout(1)
            self.assertEqual(during_backoff.recv(1), b"")
            during_backoff.close()

            time.sleep(0.06)
            user_config = config["users"]["hari"]
            user_config["controller"]["port"] = controller.port
            client = UserClient(user_config, pin_callback=lambda: PIN).connect()
            client.close()
            # The controller logs USER_AUTH_OK just after it sends READY, so wait for it.
            self.assertTrue(demo.wait(lambda: (
                "USER_AUTH_OK", "hari authenticated, session keys derived")
                in controller.events))
        finally:
            controller.stop()

    def test_restarted_device_replaces_dead_session(self):
        """A restarted device must take over its dead session at the first attempt.

        Repeated because the original bug was a race: a failed heartbeat makes the old
        session remove itself from the registry, and the new connection used to treat
        that empty slot as 'someone else registered' and rejected itself as a duplicate.
        """
        for attempt in range(8):
            tb = demo.Testbed(quiet=True)
            client = None
            try:
                old_connection = tb.ctrl.registry["light1"]
                # make sure the initial authorization sync is finished: idle but registered
                self.assertTrue(old_connection.probe())
                tb.devices["light1"].stop()
                replacement = Device(tb.cfg["devices"]["light1"], port=tb.ctrl.port,
                                     quiet=True).start()
                tb.devices["light1"] = replacement
                self.assertTrue(demo.wait(
                    lambda: "DEVICE_SESSION_REPLACED" in [k for k, _ in tb.ctrl.events]),
                    "attempt %d: events=%r" % (attempt, tb.ctrl.events))
                client = tb.user("hari")
                response = client.command("light1", "STATUS")
                self.assertEqual(response["status"], "OK",
                                 "%r; events=%r" % (response, tb.ctrl.events[-10:]))
                self.assertNotIn("DEVICE_DUPLICATE", [k for k, _ in tb.ctrl.events])
            finally:
                if client:
                    client.close()
                tb.stop()


class TestHardening(unittest.TestCase):
    def test_compromised_controller_cannot_escalate_past_device_acl(self):
        """Even if the controller itself forwards a forbidden command, the device refuses."""
        import provision
        tb = demo.Testbed(quiet=True)
        try:
            addr = {"host": "127.0.0.1", "port": tb.ctrl.port}
            record, viewer_cfg = provision.make_user_config(
                "viewer", {"light1": ["STATUS"], "door1": []}, addr, "viewer-pin-123",
                tb.ctrl.public_key_hex)
            tb.ctrl.users["viewer"] = record
            tb.ctrl._sync_all_device_authz()
            self.assertEqual(tb.devices["light1"].allowed_commands["viewer"], ["STATUS"])
            forged = tb.ctrl.registry["light1"].request(
                {"type": "COMMAND", "device_id": "light1", "command": "TURN_ON",
                 "on_behalf_of": "viewer"})
            self.assertEqual(forged["status"], "DENIED")
            self.assertEqual(tb.devices["light1"].state, "OFF")
        finally:
            tb.stop()

    def test_wrong_step_up_pin_is_a_clean_denial_and_session_survives(self):
        tb = demo.Testbed(quiet=True)
        client = None
        try:
            cfg = dict(tb.cfg["users"]["hari"])
            pins = iter([PIN, "definitely-wrong-pin"])
            client = UserClient(cfg, port=tb.ctrl.port,
                                pin_callback=lambda: next(pins)).connect()
            response = client.command("door1", "UNLOCK")
            self.assertEqual((response["status"], response["detail"]),
                             ("DENIED", "incorrect step-up PIN"))
            self.assertEqual(tb.devices["door1"].state, "LOCKED")
            self.assertEqual(client.command("light1", "STATUS")["status"], "OK")  # session alive
        finally:
            if client:
                client.close()
            tb.stop()

    def test_owner_notifications_delivered_and_notifier_failure_is_contained(self):
        tb = demo.Testbed(quiet=True)
        received = []
        tb.ctrl.notifier = lambda kind, detail: received.append(kind)
        client = None
        try:
            client = tb.user("hari")
            self.assertEqual(client.command("door1", "UNLOCK")["status"], "OK")
            self.assertIn("UNLOCK_ACCEPTED", received)
            self.assertIn("OWNER_NOTIFY", [k for k, _ in tb.ctrl.events])

            def broken(kind, detail):
                raise RuntimeError("push service down")
            tb.ctrl.notifier = broken
            tb.ctrl.revoke("guest")                       # must not raise
            self.assertIn("NOTIFY_FAIL", [k for k, _ in tb.ctrl.events])
        finally:
            if client:
                client.close()
            tb.stop()

    def test_wrong_login_pin_fails_and_repeated_failures_lock_identity(self):
        tb = demo.Testbed(quiet=True)
        tb.ctrl.identity_failure_threshold, tb.ctrl.identity_backoff = 3, 0.3
        alerts = []
        tb.ctrl.notifier = lambda kind, detail: alerts.append(kind)
        try:
            cfg = dict(tb.cfg["users"]["guest"])
            for _ in range(3):
                with self.assertRaisesRegex(c.AuthError, "wrong PIN"):
                    UserClient(cfg, port=tb.ctrl.port,
                               pin_callback=lambda: "wrong-pin-000").connect()
            self.assertTrue(demo.wait(lambda: "AUTH_GUESSING" in alerts))
            with self.assertRaises(c.AuthError):          # locked: right PIN refused too
                tb.user("guest")
            time.sleep(0.35)
            client = tb.user("guest")                      # lockout expires
            client.close()
            self.assertNotIn(("user", "guest"), tb.ctrl._identity_failures)  # reset on success
        finally:
            tb.stop()

    def test_controller_rejects_unsigned_forged_and_stale_commands(self):
        tb = demo.Testbed(quiet=True)
        client = None
        try:
            client = tb.user("hari")
            base = {"type": "COMMAND", "user_id": "hari", "device_id": "light1",
                    "command": "TURN_ON"}
            unsigned = tb.ctrl._process("hari", dict(base))
            good = client._signed_command("light1", "TURN_ON", os.urandom(16).hex())
            altered = tb.ctrl._process("hari", dict(good, command="TURN_OFF"))
            stale = client._signed_command("light1", "TURN_ON", os.urandom(16).hex())
            stale["issued_at"] -= 600
            stale["signature"] = client._signing.sign(c.command_auth_payload(
                "hari", "light1", "TURN_ON", stale["nonce"], stale["issued_at"])).hex()
            for r in (unsigned, altered):
                self.assertEqual(r["detail"], "signature verification failed")
            self.assertEqual(tb.ctrl._process("hari", stale)["detail"], "stale signed command")
            self.assertEqual(tb.devices["light1"].state, "OFF")
            self.assertEqual(tb.ctrl._process("hari", good)["status"], "OK")
        finally:
            if client:
                client.close()
            tb.stop()

    def test_audit_evidence_is_verifiable_and_detects_forgery(self):
        tb = demo.Testbed(quiet=True)
        try:
            client = tb.user("hari")
            client.command("light1", "TURN_ON")
            client.close()
            time.sleep(0.1)
            result = Controller.verify_command_evidence(tb.audit_path, tb.ctrl.users)
            self.assertGreaterEqual(result["verified"], 1)
            self.assertEqual(result["invalid"], [])
            self.assertTrue(Controller.verify_audit_log(tb.audit_path))
            with open(tb.audit_path) as f:
                records = [json.loads(line) for line in f]
            for record in records:
                if "evidence" in record:
                    record["evidence"]["payload"] = record["evidence"]["payload"].replace(
                        "TURN_ON", "TURN_OFF")
                    record["hash"] = Controller._audit_record_hash(record)  # insider re-hash
            path = os.path.join(tb.workdir, "edited.log")
            with open(path, "w") as f:
                f.writelines(json.dumps(r) + "\n" for r in records)
            self.assertTrue(Controller.verify_command_evidence(path, tb.ctrl.users)["invalid"])
        finally:
            tb.stop()

    def test_key_rotation_requires_correct_pin(self):
        tb = demo.Testbed(quiet=True)
        try:
            pins = iter([PIN, "not-the-pin-1"])
            client = UserClient(dict(tb.cfg["users"]["hari"]), port=tb.ctrl.port,
                                pin_callback=lambda: next(pins)).connect()
            old = tb.ctrl.users["hari"]["key"]
            self.assertEqual(client.rotate_key()["status"], "DENIED")
            self.assertEqual(tb.ctrl.users["hari"]["key"], old)
            client.close()
        finally:
            tb.stop()

    def test_old_v1_config_is_refused_with_clear_message(self):
        with self.assertRaisesRegex(ValueError, "predates smarthome-v2"):
            UserClient({"user_id": "hari", "key": "00" * 32,
                        "controller": {"host": "x", "port": 1}})
        with self.assertRaisesRegex(ValueError, "static_private_key"):
            Controller({"users": {}, "devices": {}}, quiet=True)

    def test_file_notifier_writes_json_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "notifications.log")
            notify = controller_module.make_file_notifier(path)
            with contextlib.redirect_stdout(io.StringIO()):
                notify("UNLOCK_ACCEPTED", "door1 unlocked by hari")
            record = json.loads(open(path).read().splitlines()[0])
            self.assertEqual((record["kind"], record["detail"]),
                             ("UNLOCK_ACCEPTED", "door1 unlocked by hari"))


class TestScenarios(unittest.TestCase):
    def test_all_attack_scenarios(self):
        tb = demo.Testbed(quiet=True)
        try:
            for fn in demo.SCENARIOS:
                r = fn(tb)
                self.assertTrue(r["passed"], "%s failed: %s" % (r["name"], r["observed"]))
        finally:
            tb.stop()


if __name__ == "__main__":
    unittest.main(verbosity=2)
