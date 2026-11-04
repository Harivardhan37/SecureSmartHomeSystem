# Architecture

## 1. Components

| Component | Description | Secrets it holds |
|---|---|---|
| **User app** | Unlocks its keys with the PIN, signs **every** command, re-asks the PIN for `UNLOCK`. | `K_UC` and Ed25519 seed, both PIN-wrapped (no tag); pinned controller public key `S` |
| **Controller** | Trusted gateway. Authenticates everyone, decrypts hidden identities, checks the ACL and user signatures, relays commands, throttles PIN guessing, supports owner-approved enrollment/revocation/rotation, and keeps a hash-chained audit log with signed evidence. | static X25519 private key `s`; all user/device PSKs; user signing public keys |
| **Device** | Executes commands, enforces its own per-user, per-command ACL, and verifies the user's own signature, freshness and nonce on every command. | its own `K_CD`; pinned `S`; user signing public keys pinned at provisioning |
| **Attacker** | Controls the network (read, modify, drop, inject). Used for testing only. | nothing |

`K_UC` is a 256-bit key shared between one user and the controller. Initial setup generates
it locally; runtime user enrollment uses a short-lived, one-use owner-approved token to protect
the enrollment exchange. `K_CD` is a 256-bit key shared between one device
and the controller (provisioned at device pairing). Users and devices **never share a key**.

## 2. Why the controller sits in the middle

The original idea had the user talk directly to the device with a key known to the controller,
the user *and* the device. That means anyone holding the key can impersonate either side.
Here the controller terminates two independent secure channels:

```
User ==[session keys A]==> Controller ==[session keys B]==> Device
```

* A compromised device cannot forge user messages (it never sees keys A).
* The ACL is enforced in one trusted place.
* Constrained devices only keep one key and one connection (outbound to the controller,
  which also works behind NAT).

## 3. Trust model

* The controller is trusted for availability and authorization decisions, but **not** for
  command authenticity: devices check the user's own signature for users with pinned keys,
  so a compromised controller cannot forge or replay those users' commands, and the audit
  evidence it stores is verifiable without trusting it.
* Users and devices pin the controller's static public key `S`. The controller must prove
  knowledge of both `s` and the shared PSK, so a leaked PSK is not enough to impersonate it.
* The network (Wi-Fi, internet, LAN) is completely untrusted, including for privacy: user
  and device identities are never sent in clear.

## 4. Data flow of one command

```
1. User app    : build {user_id, device_id, command, nonce, issued_at}, sign it with Ed25519,
                 add timestamp, encrypt with key A (AES-GCM, seq n)
2. Controller  : decrypt+verify tag, check seq (replay), check timestamp (freshness),
                 check user_id == authenticated user, check ACL, verify user signature,
                 log {payload, signature} as audit evidence
3. Controller  : re-encrypt {device_id, command, on_behalf_of, nonce, issued_at, signature}
                 with key B (own seq counter)
4. Device      : decrypt+verify, seq, timestamp, device-side per-command ACL, supported
                 command, user signature + issued_at window + one-time nonce
5. Device      : execute, send encrypted ACK {status, state}
6. Controller  : forward result to user, encrypted with key A
```
Every hop fails closed: any integrity, replay or freshness failure drops the session.
`UNLOCK` adds a device-generated one-use challenge; the user signs it after locally unwrapping
their Ed25519 key with a PIN. Both controller and device verify the signature. The device
auto-relocks after the configured delay.

## 5. Session and lifecycle controls

The controller admits at most 64 active connections in a bounded thread pool, applies a temporary
per-IP cooldown after repeated failed handshakes, and applies a 3-second pre-authentication
timeout. A user/device identity has at most one active connection; a new device login probes the
incumbent with a heartbeat and replaces it if the connection is dead. Sessions expire after
15 minutes or 10,000 messages in one
direction; user connections additionally expire after five minutes of inactivity. Users reconnect
before issuing another command and devices reconnect automatically.
The controller adjusts freshness checks using the controller time in READY. DATA payloads have a
fixed encrypted size, but traffic timing/frequency are visible.

## 6. Code structure

* `common.py`: `initiator_handshake` / `responder_handshake` (authentication + key agreement) and
  `Channel` (encrypt, decrypt, sequence numbers, timestamps, size padding, expiry). Used by all parties,
  so the security logic exists in exactly one place.
* `controller.py`: bounded worker pool. Devices stay connected and are kept in a registry;
  user requests are relayed to the device connection under a lock (request/response).
* Wire format: 4-byte length prefix + JSON. All handshake fields are hex strings.

## 7. Persistent key caveat

User PSKs and signing seeds are XOR-wrapped with a Scrypt(PIN) pad, with no tag and no stored
public key, so a stolen user file gives no offline way to test PIN guesses. Online guesses are
throttled per identity. Device PSKs and the controller's static private key remain plaintext
JSON protected only by file permissions; a product would keep them in a secure element / TPM.
