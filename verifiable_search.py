"""Deterministic Merkle membership proofs for searchable-result metadata."""

import hashlib
import json
from typing import Any, Iterable

from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa


def normalize_keyword(keyword: str) -> str:
    if not isinstance(keyword, str):
        raise TypeError("keyword must be a string")
    return keyword.strip().lower()


def _canonical_leaf(leaf: list[Any]) -> bytes:
    if (
        not isinstance(leaf, list)
        or len(leaf) != 4
        or isinstance(leaf[0], bool)
        or not isinstance(leaf[0], int)
        or not isinstance(leaf[1], str)
        or isinstance(leaf[2], bool)
        or not isinstance(leaf[2], int)
        or isinstance(leaf[3], bool)
        or not isinstance(leaf[3], int)
    ):
        raise ValueError("invalid Merkle leaf")
    if leaf[1] != normalize_keyword(leaf[1]) or not leaf[1]:
        raise ValueError("Merkle keyword must be normalized")
    return json.dumps(
        leaf, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def _leaf_hash(leaf: list[Any]) -> bytes:
    return hashlib.sha256(b"\x00" + _canonical_leaf(leaf)).digest()


def _parent_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


class MerkleTree:
    """Merkle tree over unique, canonically sorted public search-result leaves."""

    def __init__(self, leaves: Iterable[list[Any]]):
        canonical_leaves = {}
        for leaf in leaves:
            normalized_leaf = [leaf[0], normalize_keyword(leaf[1]), leaf[2], leaf[3]]
            canonical = _canonical_leaf(normalized_leaf)
            canonical_leaves[canonical] = normalized_leaf
        self.leaves = [
            canonical_leaves[key] for key in sorted(canonical_leaves)
        ]
        self.layers = [
            [_leaf_hash(leaf) for leaf in self.leaves]
        ] if self.leaves else []
        while self.layers and len(self.layers[-1]) > 1:
            current = self.layers[-1]
            next_layer = []
            for position in range(0, len(current), 2):
                left = current[position]
                right = current[position + 1] if position + 1 < len(current) else left
                next_layer.append(_parent_hash(left, right))
            self.layers.append(next_layer)

    @property
    def root(self) -> str:
        if not self.layers:
            return hashlib.sha256(b"\x02").hexdigest()
        return self.layers[-1][0].hex()

    @property
    def leaf_count(self) -> int:
        return len(self.leaves)

    def proof_for(self, leaf: list[Any]) -> dict[str, Any]:
        canonical = _canonical_leaf(leaf)
        try:
            position = next(
                index
                for index, candidate in enumerate(self.leaves)
                if _canonical_leaf(candidate) == canonical
            )
        except StopIteration as exc:
            raise ValueError("leaf is not present in this Merkle tree") from exc

        siblings = []
        for layer in self.layers[:-1]:
            sibling_position = position - 1 if position % 2 else position + 1
            if sibling_position >= len(layer):
                sibling_position = position
            siblings.append(
                {
                    "side": "left" if sibling_position < position else "right",
                    "hash": layer[sibling_position].hex(),
                }
            )
            position //= 2
        return {"leaf": leaf, "siblings": siblings}


def _manifest_payload(
    root: str, key_version: int, leaf_count: int, user_scope: int | str
) -> bytes:
    return b"search-result-manifest-v1:" + json.dumps(
        [user_scope, key_version, leaf_count, root],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def signed_manifest(
    tree: MerkleTree,
    signing_key: ECC.EccKey,
    key_version: int,
    user_scope: int | str,
) -> dict[str, Any]:
    payload = _manifest_payload(
        tree.root, key_version, tree.leaf_count, user_scope
    )
    return {
        "algorithm": "SHA-256 Merkle membership with Ed25519 root signature",
        "root": tree.root,
        "root_signature": eddsa.new(signing_key, "rfc8032").sign(payload).hex(),
        "public_key": signing_key.public_key().export_key(format="raw").hex(),
        "key_version": key_version,
        "leaf_count": tree.leaf_count,
        "user_scope": user_scope,
        "completeness_verified": False,
    }


def verify_result_proof(
    manifest: dict[str, Any],
    proof: dict[str, Any],
    trusted_public_key: str,
    expected_user_id: int | None,
    expected_key_version: int,
) -> bool:
    """Verify a signed root and membership proof; fail closed on malformed data."""
    try:
        if not isinstance(manifest, dict) or not isinstance(proof, dict):
            return False
        version = manifest["key_version"]
        leaf_count = manifest["leaf_count"]
        root = manifest["root"]
        signature = bytes.fromhex(manifest["root_signature"])
        public_key_bytes = bytes.fromhex(trusted_public_key)
        if (
            isinstance(version, bool)
            or not isinstance(version, int)
            or version != expected_key_version
            or isinstance(leaf_count, bool)
            or not isinstance(leaf_count, int)
            or leaf_count < 1
            or not isinstance(root, str)
            or len(bytes.fromhex(root)) != 32
            or public_key_bytes != bytes.fromhex(manifest["public_key"])
        ):
            return False
        scope = manifest["user_scope"]
        if scope != "all" and expected_user_id is not None and scope != expected_user_id:
            return False
        if scope == "all" and expected_user_id is None:
            return False
        public_key = eddsa.import_public_key(public_key_bytes)
        payload = _manifest_payload(root, version, leaf_count, scope)
        eddsa.new(public_key, "rfc8032").verify(payload, signature)

        leaf = proof["leaf"]
        if expected_user_id is not None and leaf[0] != expected_user_id:
            return False
        if leaf[3] != expected_key_version:
            return False
        if proof.get("result_id") != leaf[2]:
            return False
        siblings = proof["siblings"]
        if not isinstance(siblings, list):
            return False
        expected_sibling_count = 0
        remaining_leaves = leaf_count
        while remaining_leaves > 1:
            expected_sibling_count += 1
            remaining_leaves = (remaining_leaves + 1) // 2
        if len(siblings) != expected_sibling_count:
            return False
        current = _leaf_hash(leaf)
        for sibling in siblings:
            if not isinstance(sibling, dict) or sibling.get("side") not in (
                "left",
                "right",
            ):
                return False
            sibling_hash = bytes.fromhex(sibling["hash"])
            if len(sibling_hash) != 32:
                return False
            current = (
                _parent_hash(sibling_hash, current)
                if sibling["side"] == "left"
                else _parent_hash(current, sibling_hash)
            )
        return current.hex() == root
    except (KeyError, TypeError, ValueError, OverflowError):
        return False
