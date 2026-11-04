# Testing and Results (smarthome-v2)

## Test plan
| Layer | What is checked | Where |
|---|---|---|
| Unit: Channel | round trip, tamper, replay, stale timestamp, dropped message, reflection, ciphertext uniqueness, fixed-size padding, session expiry, malformed frames | `TestChannel` |
| Unit: Handshake | success, wrong/unknown key, wrong pinned controller key, fresh keys, clock skew, **identity encrypted / fixed size / unlinkable**, **CHALLENGE has no key-dependent value**, **leaked PSK cannot impersonate controller (with positive control)**, **forward secrecy after PSK + static key leak**, **tagless PIN wrap gives no offline oracle**, timing smoke test | `TestHandshake` |
| Unit: Device | fail-closed ACL, per-command ACL, ACL update validation, signed one-use `UNLOCK`, **user signature / staleness / nonce replay on every command**, unpinned-user fallback, challenge rate limit, auto-relock, pinned keys not replaceable | `TestDevice` |
| Unit: Controller | duplicate sessions, dead-device replacement, revocation, connection cap, failed-handshake cooldown, pre-auth timeout, enrollment with pairing code, key rotation, audit chain | `TestController` |
| Hardening | compromised-controller escalation, **wrong login PIN + per-identity lockout + reset**, **controller rejects unsigned / altered / stale commands**, **audit evidence verifies and detects insider edits**, **rotation needs the PIN**, wrong step-up PIN, v1 config refused, owner notifications | `TestHardening` |
| Integration | controller + 2 devices + users + attacker (15 scenarios) | `TestScenarios`, `demo.py` |
| End-to-end | separate OS processes and real CLIs: PIN login, step-up, wrong PINs, stolen-config attack, audit + signature verification, owner alerts | `python scripts/live_smoke.py` |
| Formal | ProVerif 2.00: authentication, key confirmation, forward secrecy, anonymity, no offline PIN guessing + 9 control variants | `python formal/run_formal.py` |

Run: `python -m unittest discover -s tests -t . -v`

## Unit/integration test output

Run three times in a row on this revision, all passing:
```
Ran 57 tests in 11.8s
OK
```
ResourceWarnings from socket-based tests may appear; they are harmless.

## Formal verification output (`python formal/run_formal.py`, ProVerif 2.00)
```
== real model: smarthome_handshake.pv ==
  protocol can complete (CtrlAccepts reachable)    false  ok
  protocol can complete (PeerReady reachable)      false  ok
  controller authenticates peer (injective)        true   ok
  peer authenticates controller + key confirm      true   ok
  forward secrecy controller->peer                 true   ok
  forward secrecy peer->controller                 true   ok
  anonymity: identity never revealed               true   ok
== broken: no ephemeral DH (keys from PSK + static DH only) ==
  forward secrecy controller->peer                 false  attack found, as intended
  forward secrecy peer->controller                 false  attack found, as intended
== broken: controller does not check FINISH ==
  controller authenticates peer (injective)        false  attack found, as intended
== broken: peer does not check READY ==
  peer authenticates controller + key confirm      false  attack found, as intended
== broken: identity sent in clear (v1 behaviour) ==
  anonymity: identity never revealed               false  attack found, as intended
== stronger attacker: good_id and its PSK known from the start ==
  controller authenticates peer (injective)        false  attack found, as intended
  peer authenticates controller + key confirm      true   still holds
== broken: PSK leaked AND static DH es dropped from the key schedule ==
  peer authenticates controller + key confirm      false  attack found, as intended
== real model: stolen_config.pv ==
  no offline PIN guessing with stolen config       true   ok
== broken: controller proves first (MAC in CHALLENGE, as in v1) ==
  no offline PIN guessing with stolen config       false  attack found, as intended
== broken: static DH es dropped from the key schedule ==
  no offline PIN guessing with stolen config       false  attack found, as intended

ALL AS EXPECTED
```
The "control variants" deliberately break one mechanism, or strengthen the attacker, and must
flip exactly the expected result. This shows each query can actually fail, and so is not
vacuously true.

## Attack demonstration output (`python demo.py`)
```
============================================================ 
SECURE SMART HOME - PROTOCOL & ATTACK DEMONSTRATION
============================================================
controller up on port 50327, devices registered: ['door1', 'light1']

[1/15] Legitimate use
   attack  : none (normal operation)
   expected: mutual auth succeeds, commands executed
   observed: light=ON, door unlocked then relocked
   result  : ✓ PASS

[2/15] Eavesdropping
   attack  : passive sniffing of all traffic
   expected: attacker sees only ciphertext
   observed: 8 frames captured, command/device names found in them: False
   result  : ✓ PASS

[3/15] Replay attack
   attack  : attacker re-injects a captured command packet
   expected: duplicate rejected, command runs exactly once
   observed: REPLAY detected: True, device executed command 1 time(s)
   result  : ✓ PASS

[4/15] Message modification
   attack  : attacker flips a bit in a command in transit
   expected: integrity check fails, command dropped
   observed: TAMPER detected: True, session aborted, device executed 0 command(s)
   result  : ✓ PASS

[5/15] Fake user
   attack  : login as 'hari' without key / as unknown user
   expected: authentication fails, identical error for both
   observed: known-ID: rejected: authentication failed | unknown-ID: rejected: authentication failed
   result  : ✓ PASS

[6/15] Fake device
   attack  : rogue device registers as 'light1'
   expected: rejected; real light1 session untouched
   observed: rejected: authentication failed; real device still answers: OK
   result  : ✓ PASS

[7/15] Fake controller
   attack  : attacker impersonates the controller to the user
   expected: user rejects key confirmation (READY) and sends no command
   observed: controller authentication failed
   result  : ✓ PASS

[8/15] Unauthorized command
   attack  : authenticated 'guest' tries UNLOCK on door1
   expected: access denied by ACL, door stays locked
   observed: status=DENIED, door=LOCKED
   result  : ✓ PASS

[9/15] Delayed / stale message
   attack  : valid command held back and delivered an hour late
   expected: timestamp check rejects it
   observed: STALE detected: True, device executed 0
   result  : ✓ PASS

[10/15] Cross-session replay
   attack  : packet captured earlier is injected into a new session
   expected: rejected: session keys differ (fresh nonces + ephemeral DH)
   observed: rejected: True, device executed 0
   result  : ✓ PASS

[11/15] User anonymity / untraceability
   attack  : eavesdropper watches hari log in twice
   expected: identity never on the wire; two logins cannot be linked
   observed: 2 HELLOs captured, identity visible: False, ciphertexts repeat: False, sizes: [224]
   result  : ✓ PASS

[12/15] Fake controller with leaked PSK
   attack  : attacker knows hari's long-term PSK and impersonates the controller
   expected: still rejected: controller must also prove its static X25519 key
   observed: controller authentication failed
   result  : ✓ PASS

[13/15] Compromised controller forges / replays
   attack  : controller injects an unsigned TURN_ON for hari, alters a signed one, and replays an old signed one
   expected: device verifies hari's own signature and nonce; all three refused
   observed: legit=OK; unsigned=user signature missing or stale, altered=user signature verification failed, replayed=replayed signed command; executed 0
   result  : ✓ PASS

[14/15] Repudiation / forged evidence
   attack  : hari denies a command; insider edits the logged command
   expected: each logged command carries hari's verifiable signature; edits are detected
   observed: genuine evidence verified: 11 (invalid 0); edited evidence invalid: 3
   result  : ✓ PASS

[15/15] Stolen config file + PIN guessing
   attack  : attacker copies guest's config and tries PINs
   expected: no offline test; online guesses throttled, owner alerted
   observed: 6 guesses gave 6 distinct plausible keys offline; online: 5 rejected, then locked (right PIN refused: True); owner notified: True; after lockout guest: OK
   result  : ✓ PASS

============================================================ 
SUMMARY: 15/15 scenarios behaved as designed
```

## Requirements-to-evidence map

| Security goal | Mechanism | Attack / failure case | Evidence |
|---|---|---|---|
| Mutual authentication | PSK + DH key schedule, FINISH MAC, READY confirmation | fake user, device, controller | demo 5–7; ProVerif Q1/Q2 |
| Controller authentication under PSK leak | static-ephemeral DH `es` | rogue controller with the real PSK | demo 12; ProVerif stronger-attacker variant; positive-control test |
| Confidentiality + forward secrecy | AES-GCM, ephemeral X25519, HKDF | eavesdrop; later PSK + static-key leak | demo 2; ProVerif; FS test |
| Anonymity / untraceability | encrypted fixed-size identity, fresh per login | eavesdropper links logins | demo 11; ProVerif anonymity; identity test |
| Stolen config | tagless PIN wrap, peer-first, lockout | offline + online PIN guessing | demo 15; ProVerif `weaksecret`; lockout test; live smoke |
| Integrity / replay | GCM tag, sequence numbers, signed nonces | tamper, replay, cross-session replay | demo 3, 4, 10, 13 |
| Freshness | channel `ts` and signed `issued_at` windows | delayed message | demo 9; stale-command tests |
| End-to-end command authenticity | device verifies user's Ed25519 signature | compromised controller forges/replays | demo 13; device signature test |
| Non-repudiation | signed evidence in audit log | user denies; insider edits log | demo 14; evidence test; `--verify-audit` |
| Authorization | controller ACL + device ACL + step-up | guest `UNLOCK` / door status | demo 8; ACL tests |
| Availability controls | connection cap, pre-auth timeout, per-IP cooldown | idle-socket / failed-handshake floods | controller tests |

## Separate-process CLI smoke run

`python scripts/live_smoke.py` starts the controller and both devices as separate OS
processes with freshly generated configs, then drives the real CLIs. All 11 checks passed on
this revision; run the smoke test locally to capture current output.
No screenshots were captured (the CLI has no GUI).
