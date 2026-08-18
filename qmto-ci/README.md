# QMTO Docker Regtest CI

This directory runs the Quantum Moving Target Output (QMTO) acquisition-state proof model and a real Bitcoin Core regtest integration on GitHub-hosted Ubuntu runners.

The CI gate checks Lamport one-time authorization, transaction-tamper rejection, generation chaining, stale authorization rejection, trusted/invalid/canary acquisition behavior, the full 120-sequence acquisition sweep for lengths 1–4, 100 consecutive state rotations, and a Dockerized Bitcoin Core 29.0 scenario that mines 101 maturity blocks, anchors C0, rotates the moving-target generation, rejects the stale authorization, anchors C1, and confirms a final height of 103.

The Docker service exposes no RPC or P2P ports to the host; all RPC calls occur through `docker compose exec` inside the isolated regtest service.

**Scope:** A 100% test result means 100% of these defined proof and integration checks passed. It is not a claim of universal quantum safety or 100% real-world cybersecurity.

Copyright © 2026 Matthew Blake Ward / Nine1Eight / 918 Technologies. Intended to be used under the repository's applicable open-source license and attribution terms.
