# MTL Lock — Immediate Acquisition-Triggered Moving Target Lock

MTL Lock is a defensive moving-target control layer. When a protected resource is "acquired"
by an untrusted or suspicious access event, MTL immediately rotates the externally visible
resource identity while preserving a stable internal object.

## Defensive goals

- Rotate aliases and session secrets on suspicious acquisition attempts.
- Route stale/invalid aliases to decoys rather than the protected resource.
- Keep the real resource ID stable and unreachable from external callers.
- Cryptographically bind each issued lease to generation, alias, expiry, and policy.
- Rate-limit rotations to prevent an attacker from causing uncontrolled churn.
- Produce an append-only audit trail.
- Support deterministic test mode and cryptographically random production mode.

## Core state machine

```
LOCKED
  |
  | issue authorized lease
  v
EXPOSED(generation=N, alias=A, lease=L)
  |
  | suspicious acquisition / canary / invalid lease threshold
  v
ROTATING
  |
  +--> revoke generation N
  +--> issue generation N+1
  +--> move old alias to DECOY
  v
EXPOSED(generation=N+1, alias=B)
```

## Trigger examples

- Invalid capability token.
- Expired capability presented repeatedly.
- Canary alias accessed.
- Access outside an allow-listed principal/session.
- Excessive failed attempts in the trigger window.
- Manual defender-triggered rotation.

MTL Lock is deliberately defensive. It does not exploit, probe, persist in, or interfere with
third-party systems.

## Quick start

```bash
python -m mtl.cli demo
python -m unittest discover -s tests -v
```

## Security properties

1. External aliases are ephemeral.
2. A lease is bound to one generation.
3. A generation cannot be replayed after rotation.
4. Old aliases resolve only to a decoy marker.
5. Rotation is throttled by policy.
6. Audit records are hash-chained.

## Production integration

Wire `MovingTargetLock.acquire()` into your reverse proxy, API gateway, artifact service, or
deployment controller. On `AccessDecision.ROTATE`, atomically:
- remove the old public route,
- publish the new alias,
- rotate any session-scoped secret,
- invalidate the prior lease generation,
- send the old route to a harmless decoy/canary service.

Do not use the decoy as an attack surface. It should be inert, isolated, and non-sensitive.

## Intellectual property and use rights

Copyright © 2026 Matthew Blake Ward / Nine1Eight / 918 Technologies.

The original MTL Lock architecture and implementation are retained as the owner's intellectual
property and are released under the Apache License 2.0. That license grants others broad rights to
use, reproduce, modify, distribute, sublicense, and build on the software, subject to its attribution,
notice, and other terms. See `LICENSE` and `NOTICE`.
