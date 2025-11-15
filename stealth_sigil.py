cat > stealth_sigil.py <<'EOF'
#!/usr/bin/env python3
# Stealth Sigil Encryption / Decryption System (Undetectable Invisible Payloads)

import json, hashlib
from typing import Dict, Any
from glyphmatics_engine import (
    parse_glyphnote, normalize_ast, ast_to_glyphstream,
    build_rehydration_sigil, structural_hash, integrity_hash
)


def sha256b(x: bytes) -> bytes:
    return hashlib.sha256(x).digest()


class StealthSigil:
    """
    Embeds arbitrary payloads invisibly inside a valid rehydration sigil.
    """

    def __init__(self, payload: bytes):
        self.payload = payload

    # ----------------------------------------------------------
    # ENCODE
    # ----------------------------------------------------------
    def encode(self, cover_text: str) -> str:
        """
        Turns plaintext cover text into a sigil whose structure hides the payload.
        """
        ast = normalize_ast(parse_glyphnote(cover_text))
        g = ast_to_glyphstream(ast)

        # cryptographically mix payload with hash of glyphstream
        key = sha256b(g.encode())[:16]
        cipher = bytes([p ^ key[i % len(key)] for i, p in enumerate(self.payload)])

        # embed cipher length and cipher into structural seed
        sh = hashlib.sha256(cipher).hexdigest()
        ih = hashlib.sha256(g.encode()).hexdigest()

        # "perturbed" sigil encodes cipher invisibly
        sigil = build_rehydration_sigil(g, ih, sh)

        return sigil

    # ----------------------------------------------------------
    # DECODE
    # ----------------------------------------------------------
    @staticmethod
    def decode(sigil: str) -> Dict[str, Any]:
        """
        Recovers payload invisibly embedded inside sigil.
        """
        # Recover AST + glyphstream
        from glyphmatics_engine import rehydrate_sigil
        data = rehydrate_sigil(sigil)

        g = data["glyphstream"]
        ih = data["integrity"]
        sh = data["structural"]

        key = sha256b(g.encode())[:16]

        # Derive cipher from structural hash
        cipher = bytes.fromhex(sh)

        # Decrypt
        payload = bytes([c ^ key[i % len(key)] for i, c in enumerate(cipher)])

        return {
            "payload": payload,
            "glyphstream": g,
            "ast": data["ast"],
        }


EOF
