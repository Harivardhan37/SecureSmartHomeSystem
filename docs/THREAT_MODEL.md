# Threat Model and Security Analysis (smarthome-v2)

## 1. Scope and attacker

**Network attacker (Dolev-Yao).** The attacker can read, modify, delete, delay, replay and
inject frames; open connections; and knows all protocol details and all *public* values,
including the controller's static public key. The following stronger attackers are also considered:

| Attacker | Has | Must still not be able to |
|---|---|---|
| A1 Eavesdropper | all traffic | read commands, learn who logs in, link two logins |
| A2 Active MITM | full network control | forge, replay, reorder, delay or drop commands unnoticed |
| A3 Leaked PSK | a user's long-term PSK | impersonate the controller to that user; decrypt past sessions |
| A4 Later full leak | PSK **and** controller static key, after the fact | decrypt sessions recorded earlier |
| A5 Stolen config / phone | the user's config file, not the PIN | test PIN guesses offline; log in without the PIN in a handful of online tries |
| A6 Compromised controller | everything the controller holds | forge or replay commands for provisioned users at the device; forge non-repudiable evidence |
| A7 Malicious insider | write access to the audit log | alter a logged command undetectably |

Out of scope: malware on the user's phone while unlocked, physical attacks on devices, network
saturation, and an owner who is tricked into issuing a pairing code.

The attack script is a demonstration, not a proof. The ProVerif models are abstract and were
executed with ProVerif 2.00 (`formal/run_formal.py`).

## 2. Assets

* Physical safety and privacy: the door-lock state and light state, and presence (who is home and when).
* Long-term user/device PSKs, the controller static key, and user signing keys.
* Command integrity, authorization decisions, and audit evidence.

## 3. Threats, mechanisms, and evidence

| # | Threat (attacker) | Mechanism / residual risk | Evidence |
|---|---|---|---|
| 1 | Eavesdropping, modification (A1/A2) | AES-256-GCM channel with fixed 1024-byte payloads. Timing and frequency remain visible. | demo 2, 4; `TestChannel` |
| 2 | Identity disclosure / tracking (A1) | ID encrypted under `DH(x, S)`, padded to a fixed size, fresh ephemeral per login. The IP address is still visible; anonymity is against the protocol content, not traffic analysis. | demo 11; ProVerif anonymity query; identity test |
| 3 | Same/cross-session replay (A2) | Sequence numbers, per-session keys, signed-command nonces at the device, one-use `UNLOCK` challenge | demo 3, 10, 13; device tests |
| 4 | Delay attack (A2) | 30 s window on channel `ts` and on signed `issued_at` | demo 9; controller/device stale tests |
| 5 | Fake user/device (A2) | PSK-keyed FINISH MAC over the transcript | demo 5, 6; ProVerif Q1 |
| 6 | Fake controller (A2, A3) | READY requires `K` **and** the static key `s` | demo 7, 12; ProVerif Q2 with PSK leaked; positive-control test |
| 7 | Recorded traffic + later key leak (A4) | Ephemeral `ee` in the key schedule | ProVerif phase-1 leak of PSK and `s`; FS test |
| 8 | Stolen config, offline PIN guessing (A5) | Tagless Scrypt wrap, no public key in the file, peer proves first, `es` in keys | demo 15; ProVerif `weaksecret pin`; wrap test |
| 9 | Stolen config, online PIN guessing (A5) | 5 failures then exponential lockout (1 s … 300 s) per identity, plus an owner alert. Residual: an attacker who knows a user ID can keep that user locked out (bounded DoS). | demo 15; lockout test; live smoke |
| 10 | Compromised controller forges/replays commands (A6) | Device verifies the user's Ed25519 signature, freshness and nonce for users with pinned keys. Residual: a controller can still deny service, and can command on behalf of users enrolled after provisioning (no pinned key; never `UNLOCK`). | demo 13; device signature test |
| 11 | Compromised controller escalates privileges (A6) | Device per-command ACL; pinned keys cannot be replaced | escalation and pinned-key tests |
| 12 | Repudiation ("I never unlocked the door") | Every forwarded command is logged with the user's signature; `--verify-audit` re-verifies it | demo 14; evidence test; live smoke |
| 13 | Audit tampering (A7) | Hash chain detects edits and reordering; signatures detect altered commands even if the chain is rebuilt. Residual: deleting whole entries is detectable only with external checkpoints. | audit-chain test; evidence-forgery test |
| 14 | Identity enumeration | Identical path and error for unknown, locked and wrong-key attempts | demo 5; timing smoke test |
| 15 | Connection exhaustion | Bounded pool, connection cap, 3 s pre-auth timeout, per-IP cooldown | controller tests |
| 16 | Duplicate login / stale device session | Duplicate users rejected; a dead device session is replaced after a heartbeat probe | duplicate and restart tests |
| 17 | Unauthorized command, guest occupancy inference | Controller ACL plus device ACL; the guest has no `door1:STATUS` | demo 8 |
| 18 | Forgotten unlock / brute-forced step-up | 30 s auto-relock; 5 challenges per user per minute; PIN step-up | device tests |
| 19 | Low-order / invalid DH points | X25519 exchange rejects an all-zero shared secret (`ProtocolError`) | randomized handshake test |

## 4. Key management and lifecycle

| Area | Implemented behaviour | Remaining risk |
|---|---|---|
| Controller static key | Generated by `provision.py`, pinned in every user/device config and in each pairing code | Stored in plaintext in `controller.json`. If it leaks, future (not past) logins can be de-anonymised. There is no rotation flow for it. |
| User secrets | PSK and Ed25519 seed are XOR-wrapped with Scrypt(PIN), with no tag or public key, file mode 0600 | An 8-character minimum PIN; online guessing is throttled but not impossible. |
| Device secrets | PSK in plaintext in the device config | Should live in a secure element in a product. There is no device enrollment flow. |
| Enrollment | One-use pairing code (token || `S`), 5 minutes, ACL fixed by the owner, never `UNLOCK` | Volatile (lost on controller restart). New users' keys are not pinned on devices. |
| Rotation | `KEY_ROTATE` after PIN re-entry; re-wrapped with a fresh salt | Not crash-safe two-phase. |
| Revocation | Persisted; live session closed; devices updated | No signed revocation ledger. |
| Audit | Hash chain plus per-command signatures | Truncation needs external checkpoints. |

## 5. Formal analysis

`python formal/run_formal.py` (ProVerif 2.00) checks two models:

**`smarthome_handshake.pv`**: unbounded sessions, one compromised identity, and the honest
user's PSK **and** the controller static key leaked after the sessions:

| Property | Result |
|---|---|
| Protocol completes (sanity; the queries are not vacuous) | reachable |
| Controller authenticates peer (injective agreement) | true |
| Peer authenticates controller and key confirmation (injective) | true |
| Secrecy and forward secrecy of first messages, both directions | true |
| Anonymity: the honest identity is never derivable (phase 0) | true |

**`stolen_config.pv`**: the attacker holds the stolen wrapped config and controls the network:

| Property | Result |
|---|---|
| `weaksecret pin`: no offline guessing of the PIN | true |

**Control variants** (each must flip exactly the expected result):

| Variant | Expected and observed |
|---|---|
| No ephemeral DH | forward secrecy **broken** |
| Controller skips the FINISH check | peer authentication **broken** |
| Peer skips the READY check | controller authentication **broken** |
| Identity in clear (v1) | anonymity **broken** |
| Victim's PSK and ID known to the attacker | peer authentication broken (expected), controller authentication **still holds** |
| PSK known and `es` removed | controller authentication **broken** |
| Controller proves first (v1 order) | offline PIN guessing **found** |
| `es` removed from the key schedule | offline PIN guessing **found** |

Not covered by the models: AES-GCM sequence numbers and timestamps, padding, session expiry,
signed commands at the device, rate limits, and implementation bugs. Those are covered by tests
only.

This educational prototype should not replace Matter, TLS 1.3, or a vetted Noise
implementation in a product. v2 is structurally close to Noise `IKpsk2` with the peer
authenticated by the PSK only.
