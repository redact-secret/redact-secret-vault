"""Consume the same versioned token vectors with the shipped Python parser."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "packages/vault-py/src"))
from redact_secret_vault.token import count_markers, find_tokens, has_marker

folder = Path(__file__).resolve().parent
raw = (folder / "vectors.json").read_bytes()
vectors = json.loads(raw)
manifest = json.loads((folder / "manifest.json").read_bytes())
assert vectors["schemaVersion"] == 1
assert vectors["vectorVersion"] == "1.0.0"
assert vectors["contractRevision"] == "vault-interop-v1"
assert hashlib.sha256(raw).hexdigest() == manifest["vectorsSha256"]
for vector in vectors["tokens"]:
    expected = vector["expected"]
    # Only safe identifiers are emitted on failure, never input or values.
    assert find_tokens(vector["text"]) == expected["tokens"], vector["id"]
    assert count_markers(vector["text"]) == expected["markers"], vector["id"]
    assert has_marker(vector["text"]) == expected["captureCollision"], vector["id"]
    assert (count_markers(vector["text"]) != len(find_tokens(vector["text"]))) == expected["malformed"], vector["id"]
print(f"Python interop token vectors: {len(vectors['tokens'])} passed; authority/capture native adapters not claimed")
