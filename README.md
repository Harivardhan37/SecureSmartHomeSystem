# Secure Smart Home Protocol (smarthome-v2)

A working, testable prototype of a secure protocol for a smart-home system. Users control
IoT devices (a light and a door lock) through a trusted home controller. Everything is
simulated in Python, so no hardware is needed.

**Security goals:** mutual authentication, confidentiality, integrity, freshness, replay
protection, authorization, forward secrecy, **user anonymity and untraceability**,
**non-repudiation**, **resistance to stolen config files / offline PIN guessing**, and
**protection against a compromised controller forging commands**.

```
 User / App  <== secure channel A ==>  Controller  <== secure channel B ==>  Device
 (user.py)    PIN + K_UC + Ed25519   (controller.py)        K_CD           (device.py)
                                     static key s, S pinned by all
       \_____________ every command signed by the user, verified by the device ____/
                         ^
                         |  attacker.py: sniff / replay / tamper / impersonate /
                         |               leaked-PSK impostor / stolen-config PIN guessing
```

## Project requirements and how this design meets them

| Requirement | Answer in this project |
|---|---|
| **1. Entities** | **User** (owner `hari`, `guest`) with a phone app; **home controller / gateway** (trusted hub); **smart devices** (light `light1`, door lock `door1`); **owner** (local pairing console that approves new users); **attacker** (network, stolen phone, compromised hub). |
| **2. Authentication parameters** | **User:** user ID (never sent in clear) + **PIN** (something you know) + device-bound 256-bit **PSK** and **Ed25519 key** in a PIN-wrapped config file (something you have); PIN re-entry for `UNLOCK` (step-up). **Device:** device ID + 256-bit PSK. **Controller:** the same PSK **plus** a static X25519 key pinned by every user and device. **Enrollment:** a one-time pairing code from the owner. |
| **3. Services** | **Confidentiality:** X25519 + HKDF + AES-256-GCM, fixed-size frames. **Integrity:** GCM tags, HMAC transcript binding, hash-chained audit log. **Authentication:** mutual, transcript-bound, forward-secret handshake. **Authorization:** per-command ACL at the controller *and* at the device. **Non-repudiation:** Ed25519 signature on every command, stored as verifiable evidence. **Privacy:** encrypted, unlinkable identities. |
| **4. Attack model / testing** | Dolev-Yao network attacker plus a leaked PSK, a later full key leak, a stolen config, a compromised controller and a malicious insider (`docs/THREAT_MODEL.md`). Tested by **15 executable attack scenarios** (`demo.py`), **57 unit/integration tests**, a separate-process smoke run, and **ProVerif** proofs with 9 control variants. |

## Quick start

Requires Python 3.9+ and one dependency.

```bash
pip install -r requirements.txt
python demo.py              # normal use + 15 attack scenarios, automatically
python -m unittest discover -s tests -t . -v     # 57 automated tests
python scripts/live_smoke.py                     # separate processes + real CLIs
python formal/run_formal.py                      # ProVerif proofs (needs `proverif` on PATH)
```

## Live demo in separate terminals

```bash
python provision.py           # creates keys; asks each user's PIN (8+ characters)

# Terminal 1                       # Terminal 2                          # Terminal 3
python controller.py --pairing-console
                                   python device.py config/device_light1.json
                                   python device.py config/device_door1.json

# Terminal 4 - the user (asks for the PIN at login, and again for UNLOCK)
python user.py config/user_hari.json
python user.py config/user_guest.json                # guest only sees light controls
python user.py config/user_hari.json --rotate-key    # rotates K_UC (asks for the PIN)

# Terminal 5 - the attacker
python attacker.py proxy --mode eavesdrop --listen 9100 --target 9000
python user.py config/user_hari.json --port 9100     # traffic now goes via attacker
#   other modes: --mode replay   --mode tamper
python attacker.py fake-user hari                    # login attempt without the key
python attacker.py fake-device light1
python attacker.py rogue-controller --listen 9200    # then: user.py ... --port 9200
python attacker.py rogue-controller --listen 9200 --leaked-psk-from config/controller.json
python attacker.py stolen-config config/user_guest.json 00000000 12345678 password
```

The controller writes every security event to `audit.log`.
`python controller.py --verify-audit` verifies the hash chain **and** re-verifies the
user signature on every logged command.

### Owner-approved user enrollment

Start the controller with `--pairing-console`. At its prompt, enter the new user ID and an
ACL in JSON, for example `{"light1":["TURN_ON","TURN_OFF","STATUS"]}`. The controller prints
a one-use **pairing code** (token + controller public key) that is valid for five minutes.
On the new user's machine:

```bash
python user.py --enroll-user alice --output config/user_alice.json
```

The new user enters the pairing code and sets an 8+ character PIN. Share the code only through
a trusted channel. Newly enrolled users cannot receive `UNLOCK`.

## Project layout

| File | Role |
|---|---|
| `common.py` | Framing, identity-hiding handshake, key schedule, encrypted `Channel`, PIN wrap, signed-command format |
| `controller.py` | Gateway: ACL, signature verification, audit evidence, guessing lockout, enrollment, revocation, rotation |
| `device.py` | Simulated light/lock: device ACL, end-to-end signature + nonce check, signed `UNLOCK`, auto-relock |
| `user.py` | User app: PIN unlock, signs every command, step-up PIN, enrollment, PSK rotation |
| `attacker.py` | MITM proxy, fake user/device, rogue controller (optionally with leaked PSK), stolen-config guessing |
| `provision.py` | Creates the controller static key, PSKs, signing keys and PIN-wrapped user configs |
| `demo.py` | One-command demo of normal use + all 15 attacks |
| `tests/` | Unit + integration tests |
| `formal/` | ProVerif models (handshake; stolen config) and runner with control variants |
| `docs/` | Protocol spec, architecture, threat model, and test report |

## Documentation

1. [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md): components, trust model, data flow
2. [`docs/PROTOCOL.md`](docs/PROTOCOL.md): exact messages, key schedule, security properties
3. [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md): attacker classes, attacks vs. defences, formal results
4. [`docs/TESTING.md`](docs/TESTING.md): test plan and actual results

Sequence diagram: [`docs/protocol-sequence.svg`](docs/protocol-sequence.svg).

## Security notes

* This is an educational protocol built from standard primitives (X25519, HKDF-SHA256,
  HMAC-SHA256, AES-256-GCM, Ed25519, Scrypt). Its structure is close to Noise `IKpsk2`. For a
  product, use a vetted implementation (Noise, TLS 1.3, Matter).
* Device PSKs and the controller's static private key are still plaintext JSON (file mode
  0600). Only user secrets are PIN-wrapped.
* The ProVerif models cover the handshake and the stolen-config guessing property. They do not
  cover the record layer, timestamps, signed commands at the device, or implementation bugs.
  Those are covered by tests.
