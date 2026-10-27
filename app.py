import os
import re
import sqlite3
import hashlib
import hmac
import base64
import datetime
import json
import time
import threading
from io import BytesIO
from uuid import uuid4

from flask import (
    Flask,
    g,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    send_file,
    jsonify,
)
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes

from cube import CUBEIndex
from performance import PerformanceTracker
from semantic_search import expand_query
from verifiable_search import MerkleTree, normalize_keyword, signed_manifest

try:
    from PyPDF2 import PdfReader
except ImportError:
    PdfReader = None

try:
    import docx
except ImportError:
    docx = None

try:
    import nltk
    from nltk.corpus import stopwords
except ImportError:
    nltk = None
    stopwords = None

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
except ImportError:
    TfidfVectorizer = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
ENCRYPTED_FOLDER = os.path.join(BASE_DIR, "encrypted_docs")
DATABASE = os.path.join(BASE_DIR, "database.db")
INSTANCE_FOLDER = os.path.join(BASE_DIR, ".instance")
ALLOWED_EXTENSIONS = {"pdf", "docx", "txt"}


def load_or_create_secret(env_name: str, filename: str, length: int) -> bytes:
    """Load an explicitly configured secret or create a stable local one."""
    configured = os.environ.get(env_name)
    if configured:
        secret = configured.encode("utf-8")
    else:
        os.makedirs(INSTANCE_FOLDER, exist_ok=True)
        secret_path = os.path.join(INSTANCE_FOLDER, filename)
        try:
            descriptor = os.open(
                secret_path,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                0o600,
            )
        except FileExistsError:
            secret = b""
            for _ in range(100):
                try:
                    with open(secret_path, "rb") as secret_file:
                        secret = secret_file.read()
                except FileNotFoundError:
                    pass
                if len(secret) == length:
                    break
                time.sleep(0.01)
            if len(secret) != length:
                raise RuntimeError(f"Could not read complete secret file: {filename}")
        else:
            secret = get_random_bytes(length)
            with os.fdopen(descriptor, "wb") as secret_file:
                secret_file.write(secret)

    if length == 32 and configured:
        if len(secret) < length:
            raise RuntimeError(
                f"{env_name} must contain at least {length} bytes of key material"
            )
        secret = secret[:length]
    if not secret:
        raise RuntimeError(f"{env_name} must not be empty")
    return secret


SECRET_KEY = load_or_create_secret("FLASK_SECRET_KEY", "flask_secret_key", 32)
SEARCH_KEY = load_or_create_secret("SEARCH_KEY", "search_key", 32)
VERIFICATION_SIGNING_KEY = ECC.construct(
    curve="Ed25519",
    seed=load_or_create_secret(
        "VERIFICATION_SIGNING_KEY", "verification_signing_key", 32
    ),
)

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["ENCRYPTED_FOLDER"] = ENCRYPTED_FOLDER
app.config["DATABASE"] = DATABASE
app.secret_key = SECRET_KEY

# Global CUBE and performance tracker instances
cube_index = None
performance_tracker = None
key_lifecycle_lock = threading.RLock()


class SearchIndexRecoveryError(RuntimeError):
    """Raised when a safe searchable-index recovery cannot be completed."""


def _key_file_path(key_version: int) -> str:
    return os.path.join(
        INSTANCE_FOLDER, "search_keys", f"key-v{key_version}.bin"
    )


def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _store_versioned_key(key_version: int, key: bytes) -> str:
    path = _key_file_path(key_version)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temporary_path = f"{path}.{uuid4().hex}.tmp"
    descriptor = os.open(
        temporary_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600
    )
    try:
        with os.fdopen(descriptor, "wb") as key_file:
            key_file.write(key)
            key_file.flush()
            os.fsync(key_file.fileno())
        os.replace(temporary_path, path)
    except Exception:
        try:
            os.remove(temporary_path)
        except OSError:
            app.logger.exception("Could not remove a temporary search-key file")
        raise
    return path


def _index_integrity_tag(db, key: bytes) -> str:
    rows = {}
    for table in ("cube_lcic", "cube_hki", "cube_vkic", "cube_dic"):
        rows[table] = [
            list(row)
            for row in db.execute(f"SELECT * FROM {table} ORDER BY id").fetchall()
        ]
    rows["authoritative_documents"] = [
        list(row)
        for row in db.execute(
            "SELECT id, owner FROM documents ORDER BY id"
        ).fetchall()
    ]
    rows["authoritative_keywords"] = [
        list(row)
        for row in db.execute(
            "SELECT document_id, keyword FROM keywords ORDER BY document_id, id"
        ).fetchall()
    ]
    payload = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(key, b"cube-index-v1:" + payload, hashlib.sha256).hexdigest()


def _state_integrity_tag(row, key: bytes) -> str:
    state = {
        "key_version": row["key_version"],
        "key_status": row["key_status"],
        "search_key_hash": row["search_key_hash"],
        "index_mac": row["index_mac"],
        "last_rotation_at": row["last_rotation_at"],
        "last_recovery_at": row["last_recovery_at"],
        "last_reconstruction_status": row["last_reconstruction_status"],
        "last_reconstruction_at": row["last_reconstruction_at"],
    }
    payload = json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(key, b"cube-state-v1:" + payload, hashlib.sha256).hexdigest()


def _write_state_mac(db, key: bytes) -> None:
    row = db.execute("SELECT * FROM cube_config WHERE id = 1").fetchone()
    db.execute(
        "UPDATE cube_config SET state_mac = ? WHERE id = 1",
        (_state_integrity_tag(row, key),),
    )


def _record_lifecycle_event(
    db, event_type: str, status: str, from_version, to_version, details: str = ""
) -> None:
    db.execute(
        """
        INSERT INTO key_lifecycle_events
        (event_type, status, from_version, to_version, occurred_at, details)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            event_type,
            status,
            from_version,
            to_version,
            _utc_now_iso(),
            details,
        ),
    )


def _refresh_index_integrity(db) -> None:
    index_mac = _index_integrity_tag(db, SEARCH_KEY)
    db.execute(
        "UPDATE cube_config SET index_mac = ? WHERE id = 1", (index_mac,)
    )
    _write_state_mac(db, SEARCH_KEY)


def _verify_reconstructed_index(index: CUBEIndex, db) -> None:
    """Validate all four rebuilt structures against authoritative keyword rows."""
    source_rows = db.execute(
        """
        SELECT d.id AS document_id, d.owner, k.keyword
        FROM documents d
        JOIN keywords k ON k.document_id = d.id
        ORDER BY d.id, k.id
        """
    ).fetchall()
    expected_pairs = {
        (index.generate_search_token(row["keyword"].lower()), row["document_id"])
        for row in source_rows
    }
    expected_tokens = {token for token, _ in expected_pairs}
    expected_counts = {}
    for token, _ in expected_pairs:
        expected_counts[token] = expected_counts.get(token, 0) + 1

    def active_pairs(table: str, token_column: str = "keyword_token") -> set:
        query = (
            f"SELECT {token_column}, document_id FROM {table} "
            "WHERE key_version = ?"
        )
        if table == "cube_vkic":
            query += " AND state = 'active'"
        return {
            (row[0], row[1])
            for row in db.execute(query, (index.key_version,)).fetchall()
        }

    hki_pairs = active_pairs("cube_hki")
    dic_pairs = active_pairs("cube_dic")
    vkic_pairs = active_pairs("cube_vkic")
    if hki_pairs != expected_pairs or dic_pairs != expected_pairs:
        raise SearchIndexRecoveryError("Reconstructed CUBE mappings did not validate")
    if vkic_pairs != expected_pairs:
        raise SearchIndexRecoveryError("Reconstructed CUBE version chain did not validate")
    for table in ("cube_hki", "cube_dic", "cube_vkic"):
        count = db.execute(
            f"SELECT COUNT(*) FROM {table} WHERE key_version = ?"
            + (" AND state = 'active'" if table == "cube_vkic" else ""),
            (index.key_version,),
        ).fetchone()[0]
        if count != len(expected_pairs):
            raise SearchIndexRecoveryError("Reconstructed CUBE contains duplicate entries")

    lcic_rows = db.execute(
        "SELECT keyword_token, counter FROM cube_lcic WHERE key_version = ?",
        (index.key_version,),
    ).fetchall()
    lcic_counters = {row["keyword_token"]: row["counter"] for row in lcic_rows}
    if set(lcic_counters) != expected_tokens:
        raise SearchIndexRecoveryError("Reconstructed CUBE counter chain did not validate")
    if any(lcic_counters[token] != count - 1 for token, count in expected_counts.items()):
        raise SearchIndexRecoveryError("Reconstructed CUBE counter values did not validate")

    by_keyword = {}
    by_document = {}
    for row in source_rows:
        keyword = row["keyword"].lower()
        by_keyword.setdefault(keyword, set()).add(row["document_id"])
        by_document.setdefault(row["document_id"], set()).add(keyword)

    for keyword, expected_ids in by_keyword.items():
        if set(index.search_single_keyword(keyword)) != expected_ids:
            raise SearchIndexRecoveryError("Single-keyword search validation failed")

    conjunctions = set()
    for keywords in by_document.values():
        ordered_keywords = sorted(keywords)
        for left_index, left in enumerate(ordered_keywords):
            for right in ordered_keywords[left_index + 1:]:
                conjunctions.add((left, right))
    for left, right in conjunctions:
        expected_ids = by_keyword[left] & by_keyword[right]
        if set(index.search_conjunctive([left, right])) != expected_ids:
            raise SearchIndexRecoveryError("AND-search validation failed")

    document_ids = {
        row[0] for row in db.execute("SELECT id FROM documents").fetchall()
    }
    if any(document_id not in document_ids for _, document_id in hki_pairs):
        raise SearchIndexRecoveryError("Reconstructed index contains orphaned documents")

    owners = {
        row["id"]: row["owner"]
        for row in db.execute("SELECT id, owner FROM documents").fetchall()
    }
    owner_ids = set(owners.values())
    for owner_id in owner_ids:
        for keyword, expected_ids in by_keyword.items():
            authorized_ids = {
                document_id
                for document_id in index.search_single_keyword(keyword)
                if owners.get(document_id) == owner_id
            }
            expected_owned = {
                document_id
                for document_id in expected_ids
                if owners.get(document_id) == owner_id
            }
            if authorized_ids != expected_owned:
                raise SearchIndexRecoveryError("User-isolation validation failed")


def _set_lifecycle_status(db, status: str, key: bytes) -> None:
    db.execute("UPDATE cube_config SET key_status = ? WHERE id = 1", (status,))
    _write_state_mac(db, key)


def reencrypt_documents_for_recovery(new_key: bytes) -> int:
    """Re-encrypt document payloads with the new active AES material after a rotation."""
    db = get_db()
    rows = db.execute(
        """
        SELECT id, encrypted_path, aes_key, filename
        FROM documents
        WHERE encrypted_path IS NOT NULL AND aes_key IS NOT NULL
        ORDER BY id
        """
    ).fetchall()
    reencrypted = 0
    for row in rows:
        encrypted_path = row["encrypted_path"]
        if not encrypted_path or not os.path.isfile(encrypted_path):
            continue
        with open(encrypted_path, "rb") as encrypted_file:
            ciphertext = encrypted_file.read()
        try:
            plaintext = decrypt_bytes(ciphertext, row["aes_key"])
        except (ValueError, TypeError):
            raise SearchIndexRecoveryError(
                f"Could not decrypt document {row['id']} during recovery"
            )
        new_key_b64 = base64.b64encode(new_key).decode("utf-8")
        rotated_path = os.path.join(
            app.config["ENCRYPTED_FOLDER"],
            f"doc-{row['id']}-{uuid4().hex}.enc",
        )
        cipher = AES.new(new_key, AES.MODE_GCM)
        encrypted_payload, tag = cipher.encrypt_and_digest(plaintext)
        with open(rotated_path, "wb") as rotated_file:
            rotated_file.write(cipher.nonce)
            rotated_file.write(tag)
            rotated_file.write(encrypted_payload)
        db.execute(
            "UPDATE documents SET encrypted_path = ?, aes_key = ? WHERE id = ?",
            (rotated_path, new_key_b64, row["id"]),
        )
        if encrypted_path != rotated_path:
            try:
                os.remove(encrypted_path)
            except OSError:
                app.logger.exception(
                    "Could not remove a legacy encrypted document during recovery"
                )
        reencrypted += 1
    db.execute(
        "UPDATE cube_config SET documents_reencrypted = ? WHERE id = 1",
        (reencrypted,),
    )
    return reencrypted


def rotate_security_keys(recovery: bool = False, force: bool = False) -> int:
    """Compatibility wrapper for the prototype's explicit security recovery action."""
    return rotate_search_key(recovery=recovery, force=force)


def rotate_search_key(recovery: bool = False, force: bool = False) -> int:
    """Rotate the search key and atomically replace all four CUBE structures."""
    global SEARCH_KEY, cube_index

    with key_lifecycle_lock:
        db = get_db()
        old_key = SEARCH_KEY
        config = None
        old_version = 0
        new_version = 1
        key_path = None
        started_at = _utc_now_iso()

        try:
            db.execute("BEGIN IMMEDIATE")
            config = db.execute(
                "SELECT * FROM cube_config WHERE id = 1"
            ).fetchone()
            if config is None:
                raise SearchIndexRecoveryError("Search-key state is not initialized")
            old_version = config["key_version"]
            if not isinstance(old_version, int) or old_version < 1:
                old_version = 0
            active_key_path = (
                _key_file_path(old_version) if old_version else ""
            )
            if active_key_path and os.path.isfile(active_key_path):
                with open(active_key_path, "rb") as active_key_file:
                    persisted_key = active_key_file.read()
                if len(persisted_key) == 32:
                    old_key = persisted_key
                    SEARCH_KEY = persisted_key
                    cube_index = CUBEIndex(
                        get_db, persisted_key, key_version=old_version
                    )
            if recovery and not force and config["key_status"] == "ACTIVE":
                active_index_mac = _index_integrity_tag(db, old_key)
                state_valid = hmac.compare_digest(
                    _state_integrity_tag(config, old_key),
                    config["state_mac"] or "",
                )
                if (
                    hmac.compare_digest(
                        active_index_mac, config["index_mac"] or ""
                    )
                    and state_valid
                    and hashlib.sha256(old_key).hexdigest()
                    == config["search_key_hash"]
                ):
                    db.rollback()
                    return old_version
            new_version = old_version + 1
            new_key = get_random_bytes(32)
            _set_lifecycle_status(
                db, "RECOVERING" if recovery else "ROTATING", old_key
            )
            _record_lifecycle_event(
                db, "RECOVERY" if recovery else "ROTATION", "STARTED",
                old_version, new_version,
            )
            reencrypted_count = reencrypt_documents_for_recovery(new_key)
            key_path = _store_versioned_key(new_version, new_key)
            candidate = CUBEIndex(get_db, new_key, key_version=new_version)
            for table in ("cube_hki", "cube_vkic", "cube_dic", "cube_lcic"):
                db.execute(f"DELETE FROM {table}")
            documents = {}
            for row in db.execute(
                """
                SELECT d.id AS document_id, k.keyword
                FROM documents d JOIN keywords k ON k.document_id = d.id
                ORDER BY d.id, k.id
                """
            ).fetchall():
                documents.setdefault(row["document_id"], []).append(
                    row["keyword"].lower()
                )
            for document_id, keywords in documents.items():
                candidate.add_document_index(
                    document_id,
                    list(dict.fromkeys(keywords)),
                    started_at,
                    commit=False,
                )
            _verify_reconstructed_index(candidate, db)

            index_mac = _index_integrity_tag(db, new_key)
            now = _utc_now_iso()
            db.execute(
                """
                UPDATE cube_config
                SET previous_key_version = ?, previous_key_status = ?,
                    key_version = ?, key_status = 'ACTIVE',
                    search_key_hash = ?, index_mac = ?,
                    recovery_status = 'COMPLETED',
                    recovery_timestamp = CASE WHEN ? THEN ? ELSE recovery_timestamp END,
                    verification_refresh_status = 'REFRESHED',
                    documents_reencrypted = ?,
                    last_rotation_at = ?,
                    last_recovery_at = CASE WHEN ? THEN ? ELSE last_recovery_at END,
                    last_reconstruction_status = 'SUCCESS',
                    last_reconstruction_at = ?
                WHERE id = 1
                """,
                (
                    old_version,
                    config["key_status"] if config else "ACTIVE",
                    new_version,
                    hashlib.sha256(new_key).hexdigest(),
                    index_mac,
                    int(recovery),
                    now,
                    reencrypted_count,
                    now,
                    int(recovery),
                    now,
                    now,
                ),
            )
            _write_state_mac(db, new_key)
            _record_lifecycle_event(
                db, "RECOVERY" if recovery else "ROTATION", "SUCCESS",
                old_version, new_version,
            )
            _record_lifecycle_event(
                db, "RECONSTRUCTION", "SUCCESS", old_version, new_version
            )
            db.commit()

            SEARCH_KEY = new_key
            cube_index = candidate
            try:
                for filename in os.listdir(os.path.dirname(key_path)):
                    if filename.startswith("key-v") and filename.endswith(".bin"):
                        candidate_path = os.path.join(
                            os.path.dirname(key_path), filename
                        )
                        if candidate_path != key_path:
                            os.remove(candidate_path)
            except OSError:
                app.logger.exception("Could not remove a retired search-key file")
            legacy_key_path = os.path.join(INSTANCE_FOLDER, "search_key")
            try:
                if os.path.isfile(legacy_key_path):
                    os.remove(legacy_key_path)
            except OSError:
                app.logger.exception("Could not remove the legacy search-key file")
            return new_version
        except Exception as exc:
            db.rollback()
            if key_path:
                try:
                    os.remove(key_path)
                except OSError:
                    app.logger.exception("Could not remove an unused search-key file")
            try:
                config = db.execute(
                    "SELECT * FROM cube_config WHERE id = 1"
                ).fetchone()
                db.execute("BEGIN IMMEDIATE")
                db.execute(
                    """
                    UPDATE cube_config
                    SET previous_key_version = ?, previous_key_status = ?,
                        recovery_status = 'FAILED',
                        verification_refresh_status = 'FAILED',
                        key_status = 'COMPROMISED',
                        last_reconstruction_status = 'FAILED',
                        last_reconstruction_at = ?
                    WHERE id = 1
                    """,
                    (
                        config["key_version"] if config and config["key_version"] is not None else old_version,
                        (config["key_status"] if config else "ACTIVE"),
                        _utc_now_iso(),
                    ),
                )
                _write_state_mac(db, old_key)
                _record_lifecycle_event(
                    db, "RECOVERY" if recovery else "ROTATION", "FAILED",
                    config["key_version"] if config else old_version,
                    new_version,
                    "Reconstruction or activation failed",
                )
                db.commit()
            except sqlite3.Error:
                db.rollback()
                app.logger.exception("Could not persist search-index recovery failure")
            app.logger.exception("Search-key rotation or CUBE reconstruction failed")
            raise SearchIndexRecoveryError(
                "Search-index recovery failed; the previous index was not activated"
            ) from exc


def search_document_ids(keywords, user_id=None):
    """Search the CUBE and return only documents authorized for this user."""
    if not cube_index:
        return []
    matched_ids = cube_index.search_conjunctive(keywords)
    if not matched_ids:
        return []
    db = get_db()
    placeholders = ",".join("?" for _ in matched_ids)
    sql = f"SELECT id FROM documents WHERE id IN ({placeholders})"
    parameters = list(matched_ids)
    if user_id is not None:
        sql += " AND owner = ?"
        parameters.append(user_id)
    return [row["id"] for row in db.execute(sql, parameters).fetchall()]


def _parse_search_keywords(query: str) -> list[str]:
    return [
        keyword.strip().lower()
        for keyword in re.split(r"\s+AND\s+|\s+and\s+", query)
        if keyword.strip()
    ]


def _expand_search_terms(query: str, exact_keywords: list[str]):
    """Expand natural-language queries; preserve explicit AND as exact search."""
    if re.search(r"\s+AND\s+|\s+and\s+", query):
        return exact_keywords, False, "conjunctive"
    try:
        expanded = expand_query(query)
        if not expanded:
            return exact_keywords, False, "exact"
        return expanded, True, "semantic"
    except Exception:
        app.logger.warning(
            "Semantic query expansion failed; falling back to exact search"
        )
        return exact_keywords, False, "exact"


def _build_search_verification(matched_doc_ids, search_terms, user_id, role):
    """Build a scoped Merkle manifest and proofs from trusted keyword records."""
    db = get_db()
    config = db.execute(
        "SELECT key_version FROM cube_config WHERE id = 1"
    ).fetchone()
    if config is None:
        raise SearchIndexRecoveryError("Search-key state is not initialized")
    key_version = config["key_version"]
    user_scope = "all" if role == "admin" else user_id
    rows = db.execute(
        """
        SELECT d.owner, d.id AS document_id, k.keyword
        FROM documents d
        JOIN keywords k ON k.document_id = d.id
        WHERE (? = 1 OR d.owner = ?)
        ORDER BY d.owner, d.id, k.id
        """,
        (int(role == "admin"), user_id),
    ).fetchall()
    leaf_by_document_keyword = {}
    leaves = []
    for row in rows:
        keyword = normalize_keyword(row["keyword"])
        if not keyword:
            continue
        leaves.append([row["owner"], keyword, row["document_id"], key_version])
        leaf_by_document_keyword.setdefault(row["document_id"], set()).add(keyword)

    tree = MerkleTree(leaves)
    manifest = signed_manifest(
        tree, VERIFICATION_SIGNING_KEY, key_version, user_scope
    )
    term_matches = {
        normalize_keyword(term): set(cube_index.search_single_keyword(term))
        for term in search_terms
    }
    proofs = []
    for document_id in matched_doc_ids:
        document = db.execute(
            "SELECT owner FROM documents WHERE id = ?", (document_id,)
        ).fetchone()
        if document is None or (
            role != "admin" and document["owner"] != user_id
        ):
            continue
        for keyword, term_document_ids in term_matches.items():
            if (
                document_id in term_document_ids
                and keyword in leaf_by_document_keyword.get(document_id, set())
            ):
                leaf = [
                    document["owner"],
                    keyword,
                    document_id,
                    key_version,
                ]
                proof = tree.proof_for(leaf)
                proof["result_id"] = document_id
                proofs.append(proof)
    manifest["proofs"] = proofs
    return manifest


def _search_terms(terms: list[str], user_id=None, semantic=False) -> list[int]:
    if not cube_index:
        return []
    if not semantic:
        return search_document_ids(terms, user_id)

    matched_ids = set()
    for term in terms:
        matched_ids.update(search_document_ids([term], user_id))
    return sorted(matched_ids)


def ensure_search_index_trustworthy() -> bool:
    """Authenticate key metadata and all CUBE rows; recover on any mismatch."""
    global SEARCH_KEY, cube_index

    with key_lifecycle_lock:
        db = get_db()
        try:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM cube_config WHERE id = 1"
            ).fetchone()
            if row is None:
                db.rollback()
                raise SearchIndexRecoveryError(
                    "Search-key state is not initialized"
                )
            version = row["key_version"]
            key_status = row["key_status"]
            version_valid = isinstance(version, int) and version >= 1
            key_path = _key_file_path(version) if version_valid else ""
            try:
                if key_path:
                    with open(key_path, "rb") as key_file:
                        disk_key = key_file.read()
                else:
                    disk_key = b""
            except OSError:
                disk_key = b""
            if version_valid and len(disk_key) == 32:
                SEARCH_KEY = disk_key
                cube_index = CUBEIndex(get_db, disk_key, key_version=version)
            key_matches = (
                len(disk_key) == 32
                and hmac.compare_digest(
                    hashlib.sha256(disk_key).hexdigest(),
                    row["search_key_hash"] or "",
                )
            )
            try:
                expected_index_mac = _index_integrity_tag(db, SEARCH_KEY)
                index_matches = hmac.compare_digest(
                    expected_index_mac, row["index_mac"] or ""
                )
                state_matches = hmac.compare_digest(
                    _state_integrity_tag(row, SEARCH_KEY), row["state_mac"] or ""
                )
                version_matches = version_valid and all(
                    db.execute(
                        f"SELECT COUNT(*) FROM {table} WHERE key_version != ?",
                        (version,),
                    ).fetchone()[0] == 0
                    for table in ("cube_lcic", "cube_hki", "cube_vkic", "cube_dic")
                )
            except (TypeError, ValueError, sqlite3.Error):
                index_matches = state_matches = version_matches = False
            if (
                version_valid
                and key_status == "ACTIVE"
                and key_matches
                and index_matches
                and state_matches
                and version_matches
            ):
                db.rollback()
                return False

            db.execute(
                """
                UPDATE cube_config
                SET key_status = 'COMPROMISED'
                WHERE id = 1
                """
            )
            _write_state_mac(db, SEARCH_KEY)
            _record_lifecycle_event(
                db,
                "COMPROMISE_DETECTED",
                "DETECTED",
                version if isinstance(version, int) else None,
                version if isinstance(version, int) else None,
                "Authenticated key or CUBE state validation failed",
            )
            db.commit()
        except SearchIndexRecoveryError:
            if db.in_transaction:
                db.rollback()
            raise
        except sqlite3.Error as exc:
            if db.in_transaction:
                db.rollback()
            app.logger.exception("Could not validate search-index integrity")
            raise SearchIndexRecoveryError(
                "Search-index integrity could not be validated"
            ) from exc
        rotate_search_key(recovery=True)
        return True


def ensure_directories():
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)


def get_db():
    db = getattr(g, "db", None)
    if db is None:
        db = sqlite3.connect(app.config["DATABASE"])
        db.row_factory = sqlite3.Row
        g.db = db
    return db


@app.teardown_appcontext
def close_db(error=None):
    db = getattr(g, "db", None)
    if db is not None:
        db.close()


def create_tables():
    global cube_index, performance_tracker, SEARCH_KEY

    db = get_db()
    db.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, role TEXT)"
    )
    db.execute(
        "CREATE TABLE IF NOT EXISTS documents (id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, owner INTEGER, upload_date TEXT, encrypted_path TEXT, aes_key TEXT, FOREIGN KEY(owner) REFERENCES users(id))"
    )
    db.execute(
        "CREATE TABLE IF NOT EXISTS keywords (id INTEGER PRIMARY KEY AUTOINCREMENT, document_id INTEGER, keyword TEXT, FOREIGN KEY(document_id) REFERENCES documents(id))"
    )
    db.commit()

    cube_index = CUBEIndex(get_db, SEARCH_KEY)
    cube_index.create_tables()
    performance_tracker = PerformanceTracker(get_db)
    performance_tracker.create_tables()

    config_columns = {
        row[1] for row in db.execute("PRAGMA table_info(cube_config)").fetchall()
    }
    had_lifecycle_state = "key_version" in config_columns
    lifecycle_columns = {
        "key_version": "INTEGER NOT NULL DEFAULT 1",
        "key_status": "TEXT NOT NULL DEFAULT 'ACTIVE'",
        "previous_key_version": "INTEGER",
        "previous_key_status": "TEXT",
        "recovery_status": "TEXT NOT NULL DEFAULT 'NOT_STARTED'",
        "recovery_timestamp": "TEXT",
        "documents_reencrypted": "INTEGER NOT NULL DEFAULT 0",
        "verification_refresh_status": "TEXT NOT NULL DEFAULT 'NOT_STARTED'",
        "index_mac": "TEXT",
        "state_mac": "TEXT",
        "last_rotation_at": "TEXT",
        "last_recovery_at": "TEXT",
        "last_reconstruction_status": "TEXT",
        "last_reconstruction_at": "TEXT",
    }
    for column, definition in lifecycle_columns.items():
        if column not in config_columns:
            db.execute(f"ALTER TABLE cube_config ADD COLUMN {column} {definition}")
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS key_lifecycle_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            status TEXT NOT NULL,
            from_version INTEGER,
            to_version INTEGER,
            occurred_at TEXT NOT NULL,
            details TEXT NOT NULL DEFAULT ''
        )
        """
    )

    if not had_lifecycle_state:
        key_path = _key_file_path(1)
        if os.path.isfile(key_path):
            with open(key_path, "rb") as key_file:
                persisted_key = key_file.read()
            if len(persisted_key) == 32:
                SEARCH_KEY = persisted_key
        cube_index = CUBEIndex(get_db, SEARCH_KEY, key_version=1)
        cube_index.create_tables()
        current_key_hash = hashlib.sha256(SEARCH_KEY).hexdigest()
        db.execute("BEGIN IMMEDIATE")
        for table in ("cube_hki", "cube_vkic", "cube_dic", "cube_lcic"):
            db.execute(f"DELETE FROM {table}")
        grouped = {}
        for row in db.execute(
            """
            SELECT d.id AS document_id, k.keyword
            FROM documents d JOIN keywords k ON k.document_id = d.id
            ORDER BY d.id, k.id
            """
        ).fetchall():
            grouped.setdefault(row["document_id"], []).append(
                row["keyword"].lower()
            )
        for document_id, keywords in grouped.items():
            cube_index.add_document_index(
                document_id,
                list(dict.fromkeys(keywords)),
                _utc_now_iso(),
                commit=False,
            )
        _verify_reconstructed_index(cube_index, db)
        now = _utc_now_iso()
        db.execute(
            """
            INSERT INTO cube_config
            (id, search_key_hash, created_at, key_version, key_status,
             previous_key_version, previous_key_status, recovery_status,
             recovery_timestamp, documents_reencrypted,
             verification_refresh_status, index_mac, state_mac,
             last_rotation_at, last_recovery_at,
             last_reconstruction_status, last_reconstruction_at)
            VALUES (1, ?, ?, 1, 'ACTIVE', NULL, NULL, 'COMPLETED', ?, 0,
                    'REFRESHED', '', '', NULL, NULL, 'SUCCESS', ?)
            ON CONFLICT(id) DO UPDATE SET
                search_key_hash = excluded.search_key_hash,
                key_version = 1,
                key_status = 'ACTIVE',
                previous_key_version = excluded.previous_key_version,
                previous_key_status = excluded.previous_key_status,
                recovery_status = excluded.recovery_status,
                recovery_timestamp = excluded.recovery_timestamp,
                documents_reencrypted = excluded.documents_reencrypted,
                verification_refresh_status = excluded.verification_refresh_status,
                last_reconstruction_status = 'SUCCESS',
                last_reconstruction_at = excluded.last_reconstruction_at
            """,
            (current_key_hash, now, now, now),
        )
        db.commit()
        if not os.path.isfile(key_path):
            _store_versioned_key(1, SEARCH_KEY)
        _refresh_index_integrity(db)
        db.commit()
    else:
        config = db.execute("SELECT * FROM cube_config WHERE id = 1").fetchone()
        if config is None:
            raise SearchIndexRecoveryError("Search-key state is missing")
        version = config["key_version"]
        if not isinstance(version, int) or version < 1:
            version = 0
        key_path = _key_file_path(version) if version else ""
        if key_path and os.path.isfile(key_path):
            with open(key_path, "rb") as key_file:
                persisted_key = key_file.read()
            if len(persisted_key) == 32:
                SEARCH_KEY = persisted_key
        cube_index = CUBEIndex(
            get_db, SEARCH_KEY, key_version=version if version > 0 else 1
        )

    legacy_key_path = os.path.join(INSTANCE_FOLDER, "search_key")
    active_key_path = _key_file_path(cube_index.key_version)
    if os.path.isfile(active_key_path) and os.path.isfile(legacy_key_path):
        try:
            os.remove(legacy_key_path)
        except OSError:
            app.logger.exception("Could not remove the legacy search-key file")

    if had_lifecycle_state:
        ensure_search_index_trustworthy()


def hash_password(password: str) -> str:
    return generate_password_hash(password)


def verify_password(stored_password: str, password: str) -> tuple[bool, bool]:
    """Return whether a password matches and whether the hash needs upgrading."""
    if re.fullmatch(r"[0-9a-fA-F]{64}", stored_password or ""):
        legacy_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
        return (hmac.compare_digest(stored_password, legacy_hash), True)
    try:
        return (check_password_hash(stored_password, password), False)
    except (TypeError, ValueError):
        return (False, False)


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def extract_pdf_text(path: str) -> str:
    if PdfReader is None:
        return ""
    text = []
    with open(path, "rb") as f:
        reader = PdfReader(f)
        for page in reader.pages:
            text.append(page.extract_text() or "")
    return "\n".join(text)


def extract_docx_text(path: str) -> str:
    if docx is None:
        return ""
    document = docx.Document(path)
    return "\n".join(paragraph.text for paragraph in document.paragraphs)


def extract_txt_text(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def extract_text(path: str) -> str:
    ext = path.rsplit(".", 1)[-1].lower()
    if ext == "pdf":
        return extract_pdf_text(path)
    if ext == "docx":
        return extract_docx_text(path)
    if ext == "txt":
        return extract_txt_text(path)
    return ""


def build_stopwords() -> set:
    if stopwords is not None:
        try:
            nltk.data.find("corpora/stopwords")
        except LookupError:
            nltk.download("stopwords")
        return set(stopwords.words("english"))
    return {
        "a", "an", "and", "are", "as", "at", "be", "by", "for", "from",
        "has", "he", "in", "is", "it", "its", "of", "on", "that", "the",
        "to", "was", "were", "will", "with",
    }


def tokenize_text(text: str) -> list[str]:
    words = re.findall(r"\b[a-zA-Z]{3,}\b", text.lower())
    stop_words = build_stopwords()
    return [word for word in words if word not in stop_words]


def extract_keywords(text: str, top_n: int = 8) -> list[str]:
    if not text.strip() or TfidfVectorizer is None:
        tokens = tokenize_text(text)
        return sorted(set(tokens), key=tokens.index)[:top_n]

    tokens = tokenize_text(text)
    if not tokens:
        return []
    try:
        vectorizer = TfidfVectorizer(stop_words="english", max_features=1000)
        matrix = vectorizer.fit_transform([text])
        feature_names = vectorizer.get_feature_names_out()
        scores = matrix.toarray()[0]
        scored = sorted(
            ((feature_names[i], scores[i]) for i in range(len(feature_names)) if scores[i] > 0),
            key=lambda x: -x[1],
        )
        return [keyword for keyword, _ in scored[:top_n]]
    except Exception:
        return sorted(set(tokens), key=tokens.index)[:top_n]


def encrypt_file(input_path: str, output_path: str) -> str:
    key = get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_GCM)
    with open(input_path, "rb") as f:
        plaintext = f.read()
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    with open(output_path, "wb") as out_file:
        out_file.write(cipher.nonce)
        out_file.write(tag)
        out_file.write(ciphertext)
    return base64.b64encode(key).decode("utf-8")


def decrypt_bytes(encrypted_bytes: bytes, key_b64: str) -> bytes:
    key = base64.b64decode(key_b64)
    nonce = encrypted_bytes[:16]
    tag = encrypted_bytes[16:32]
    ciphertext = encrypted_bytes[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


def cleanup_legacy_plaintext_uploads() -> None:
    """Remove only old staging files proven to duplicate a stored encrypted file."""
    upload_folder = app.config["UPLOAD_FOLDER"]
    encrypted_folder = app.config["ENCRYPTED_FOLDER"]
    db = get_db()
    cutoff = time.time() - 24 * 60 * 60

    for staged_name in os.listdir(upload_folder):
        staged_path = os.path.join(upload_folder, staged_name)
        try:
            if not os.path.isfile(staged_path):
                continue
            if staged_name.startswith(".staging-"):
                if os.path.getmtime(staged_path) <= cutoff:
                    os.remove(staged_path)
                continue
        except OSError:
            app.logger.exception("Could not inspect a legacy plaintext staging file")
            continue

        match = re.fullmatch(r"[0-9a-fA-F]{32}_(.+)", staged_name)
        if not match:
            continue
        filename = match.group(1)
        records = db.execute(
            """
            SELECT encrypted_path, aes_key FROM documents
            WHERE filename = ? AND encrypted_path IS NOT NULL
            """,
            (filename,),
        ).fetchall()
        try:
            with open(staged_path, "rb") as staged_file:
                staged_digest = hashlib.sha256(staged_file.read()).digest()
            duplicate_found = False
            for record in records:
                encrypted_name = record["encrypted_path"]
                if os.path.basename(encrypted_name) != encrypted_name:
                    continue
                encrypted_path = os.path.join(encrypted_folder, encrypted_name)
                if not os.path.isfile(encrypted_path):
                    continue
                with open(encrypted_path, "rb") as encrypted_file:
                    plaintext = decrypt_bytes(encrypted_file.read(), record["aes_key"])
                if hmac.compare_digest(
                    staged_digest, hashlib.sha256(plaintext).digest()
                ):
                    duplicate_found = True
                    break
            if duplicate_found:
                os.remove(staged_path)
        except (OSError, ValueError, TypeError):
            app.logger.exception(
                "Could not verify or remove a legacy plaintext staging file"
            )


def login_required(view):
    def wrapped_view(**kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(**kwargs)
    wrapped_view.__name__ = view.__name__
    return wrapped_view


def admin_required(view):
    @login_required
    def wrapped_view(**kwargs):
        if session.get("role") != "admin":
            return "Forbidden", 403
        return view(**kwargs)
    wrapped_view.__name__ = view.__name__
    return wrapped_view


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        requested_role = request.form.get("role", "student")
        role = requested_role if requested_role in {"student", "doctor"} else "student"

        if not username or not password:
            flash("Please provide both username and password.", "warning")
            return render_template("register.html")

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username, hash_password(password), role),
            )
            db.commit()
            flash("Registration successful. Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already exists. Choose another.", "danger")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if user:
            password_matches, needs_upgrade = verify_password(
                user["password"], password
            )
        else:
            password_matches, needs_upgrade = False, False
        if user and password_matches:
            if needs_upgrade:
                db.execute(
                    "UPDATE users SET password = ? WHERE id = ?",
                    (hash_password(password), user["id"]),
                )
                db.commit()
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            flash(f"Welcome back, {user['username']}!", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid credentials.", "danger")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    global cube_index
    try:
        ensure_search_index_trustworthy()
    except SearchIndexRecoveryError:
        app.logger.exception("Search-index recovery failed while loading dashboard")
        flash("Search is temporarily unavailable while index recovery is attempted.", "danger")

    db = get_db()
    user_id = session["user_id"]
    role = session.get("role")
    if role == "admin":
        documents = db.execute(
            "SELECT * FROM documents ORDER BY upload_date DESC"
        ).fetchall()
    else:
        documents = db.execute(
            "SELECT * FROM documents WHERE owner = ? ORDER BY upload_date DESC",
            (user_id,),
        ).fetchall()
    
    # Review 2: Get CUBE statistics
    cube_stats = {}
    if cube_index:
        cube_stats = cube_index.get_cube_stats(
            None if role == "admin" else user_id
        )
    
    return render_template(
        "dashboard.html",
        documents=documents,
        cube_stats=cube_stats,
    )


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    global cube_index, performance_tracker

    try:
        ensure_search_index_trustworthy()
    except SearchIndexRecoveryError:
        app.logger.exception("Search-index recovery failed before document upload")
        flash("Document upload is unavailable while index recovery is attempted.", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        file = request.files.get("document")
        if not file or file.filename == "":
            flash("Please select a file to upload.", "warning")
            return redirect(request.url)

        if not allowed_file(file.filename):
            flash("Only PDF, DOCX, and TXT files are allowed.", "danger")
            return redirect(request.url)

        filename = secure_filename(file.filename)
        unique_name = f".staging-{uuid4().hex}_{filename}"
        upload_path = os.path.join(app.config["UPLOAD_FOLDER"], unique_name)
        encrypted_name = f"{uuid4().hex}_{filename}.enc"
        encrypted_path = os.path.join(app.config["ENCRYPTED_FOLDER"], encrypted_name)
        db = get_db()
        upload_succeeded = False
        plaintext_cleanup_failed = False
        try:
            file.save(upload_path)
            extracted_text = extract_text(upload_path)
            keywords = extract_keywords(extracted_text)

            enc_start = time.time()
            aes_key = encrypt_file(upload_path, encrypted_path)
            enc_duration_ms = (time.time() - enc_start) * 1000

            cursor = db.execute(
                "INSERT INTO documents (filename, owner, upload_date, encrypted_path, aes_key) VALUES (?, ?, ?, ?, ?)",
                (
                    filename,
                    session["user_id"],
                    datetime.datetime.utcnow().isoformat(),
                    encrypted_name,
                    aes_key,
                ),
            )
            document_id = cursor.lastrowid
            db.executemany(
                "INSERT INTO keywords (document_id, keyword) VALUES (?, ?)",
                [(document_id, kw) for kw in keywords],
            )
            if cube_index:
                cube_start = time.time()
                cube_index.add_document_index(
                    document_id,
                    keywords,
                    datetime.datetime.utcnow().isoformat(),
                    commit=False,
                )
                cube_duration_ms = (time.time() - cube_start) * 1000
            _refresh_index_integrity(db)
            db.commit()
            upload_succeeded = True
        except Exception:
            db.rollback()
            if os.path.exists(encrypted_path):
                try:
                    os.remove(encrypted_path)
                except OSError:
                    app.logger.exception("Could not remove failed encrypted upload")
            raise
        finally:
            try:
                if os.path.exists(upload_path):
                    os.remove(upload_path)
            except OSError:
                plaintext_cleanup_failed = True
                app.logger.exception("Could not remove temporary plaintext upload")

        performance_logging_failed = False
        if upload_succeeded and performance_tracker:
            try:
                performance_tracker.log_operation(
                    "encryption", enc_duration_ms, filename, session["user_id"]
                )
                if cube_index:
                    performance_tracker.log_operation(
                        "cube_index_update",
                        cube_duration_ms,
                        f"doc={document_id},keywords={len(keywords)}",
                        session["user_id"],
                    )
            except sqlite3.Error:
                performance_logging_failed = True
                app.logger.exception("Could not record document upload performance")
        if plaintext_cleanup_failed:
            flash(
                "Document was encrypted, but its temporary plaintext file could not "
                "be removed. Contact the administrator to remove the leftover file.",
                "warning",
            )
        elif performance_logging_failed:
            flash(
                "Document was uploaded and encrypted, but its performance metrics "
                "could not be recorded.",
                "warning",
            )
        elif cube_index:
            flash(
                f"Document uploaded and encrypted successfully. "
                f"CUBE index updated: {len(keywords)} keywords indexed.",
                "success",
            )
        else:
            flash("Document uploaded and encrypted successfully.", "success")
        
        return redirect(url_for("document_detail", document_id=document_id))

    return render_template("upload.html")


@app.route("/documents")
@login_required
def documents():
    db = get_db()
    user_id = session["user_id"]
    role = session.get("role")
    if role == "admin":
        documents = db.execute("SELECT * FROM documents ORDER BY upload_date DESC").fetchall()
    else:
        documents = db.execute(
            "SELECT * FROM documents WHERE owner = ? ORDER BY upload_date DESC",
            (user_id,),
        ).fetchall()
    return render_template("documents.html", documents=documents)


@app.route("/documents/<int:document_id>")
@login_required
def document_detail(document_id):
    db = get_db()
    document = db.execute(
        "SELECT * FROM documents WHERE id = ?",
        (document_id,),
    ).fetchone()
    if document is None:
        flash("Document not found.", "danger")
        return redirect(url_for("dashboard"))

    if document["owner"] != session["user_id"] and session.get("role") != "admin":
        flash("You do not have permission to view this document.", "danger")
        return redirect(url_for("dashboard"))

    encrypted_path = os.path.join(
        app.config["ENCRYPTED_FOLDER"], document["encrypted_path"]
    )
    extracted_text = ""
    if os.path.exists(encrypted_path):
        try:
            with open(encrypted_path, "rb") as f:
                decrypted = decrypt_bytes(f.read(), document["aes_key"])
                extracted_text = decrypted.decode("utf-8", errors="ignore")
        except Exception:
            extracted_text = "Unable to show full text after decryption."

    keywords = db.execute(
        "SELECT keyword FROM keywords WHERE document_id = ?",
        (document_id,),
    ).fetchall()
    return render_template(
        "document_detail.html",
        document={
            "id": document["id"],
            "filename": document["filename"],
            "owner": document["owner"],
            "upload_date": document["upload_date"],
        },
        keywords=[row["keyword"] for row in keywords],
        extracted_text=extracted_text,
    )


@app.route("/decrypt/<int:document_id>")
@login_required
def decrypt(document_id):
    db = get_db()
    document = db.execute("SELECT * FROM documents WHERE id = ?", (document_id,)).fetchone()
    if document is None:
        flash("Document not found.", "danger")
        return redirect(url_for("dashboard"))
    if document["owner"] != session["user_id"] and session.get("role") != "admin":
        flash("You do not have permission to decrypt this document.", "danger")
        return redirect(url_for("dashboard"))

    encrypted_path = os.path.join(app.config["ENCRYPTED_FOLDER"], document["encrypted_path"])
    if not os.path.exists(encrypted_path):
        flash("Encrypted file is missing.", "danger")
        return redirect(url_for("dashboard"))

    with open(encrypted_path, "rb") as f:
        plaintext = decrypt_bytes(f.read(), document["aes_key"])

    return send_file(
        BytesIO(plaintext),
        download_name=document["filename"],
        as_attachment=True,
    )


# ============================================================================
# REVIEW 2: SEARCHABLE ENCRYPTION ROUTES
# ============================================================================

@app.route("/search", methods=["GET", "POST"])
@login_required
def search():
    """Search page for secure document search."""
    if request.method == "POST":
        query = request.form.get("query", "").strip()
        if not query:
            flash("Please enter a search query.", "warning")
            return render_template("search.html", query="")
        
        # Parse query (simple AND/OR logic)
        keywords = [kw.strip().lower() for kw in re.split(r'\s+AND\s+|\s+and\s+', query)]
        keywords = [kw for kw in keywords if kw]
        
        if not keywords:
            flash("Invalid search query.", "warning")
            return render_template("search.html", query=query)

        semantic_enabled = request.form.get("semantic_search") == "true"
        verification_enabled = request.form.get("verify_search") == "true"
        return redirect(
            url_for(
                "search_results",
                query=query,
                semantic="true" if semantic_enabled else "false",
                verify="true" if verification_enabled else "false",
            )
        )
    
    return render_template("search.html", query="")


@app.route("/search/results")
@login_required
def search_results():
    """Display search results."""
    global cube_index, performance_tracker
    
    query = request.args.get("query", "").strip()
    verification_requested = request.args.get("verify") == "true"
    if not query:
        return redirect(url_for("search"))
    
    # Parse keywords from query
    keywords = _parse_search_keywords(query)
    semantic_requested = request.args.get("semantic") == "true"
    search_terms = keywords
    semantic_used = False
    search_mode = "conjunctive" if len(keywords) > 1 else "exact"
    if semantic_requested and keywords:
        search_terms, semantic_used, search_mode = _expand_search_terms(query, keywords)
    
    if not keywords or not cube_index:
        return render_template(
            "search_results.html",
            query=query,
            keywords=keywords,
            results=[],
            result_count=0,
            search_time_ms=0
        )
    
    # Perform search
    search_start = time.time()
    search_succeeded = False
    role = session.get("role")
    user_id = session["user_id"]
    try:
        ensure_search_index_trustworthy()
        db = get_db()
        matched_doc_ids = _search_terms(
            search_terms,
            None if role == "admin" else user_id,
            semantic=semantic_used,
        )
        search_succeeded = True
    except Exception:
        app.logger.exception("Search failed")
        flash("Search failed; no results were returned.", "danger")
        matched_doc_ids = []
    
    search_duration_ms = (time.time() - search_start) * 1000
    
    # Log search if performance tracker available
    db = get_db()

    if performance_tracker:
        performance_tracker.log_search(
            user_id,
            query,
            len(search_terms),
            len(matched_doc_ids),
            search_duration_ms,
            search_mode,
        )
    
    # Fetch matched documents (respect access control)
    results = []
    for doc_id in matched_doc_ids:
        doc = db.execute(
            "SELECT * FROM documents WHERE id = ?",
            (doc_id,)
        ).fetchone()
        
        if doc and (doc["owner"] == user_id or role == "admin"):
            # Get matched keywords from CUBE
            matched_keywords = []
            for kw in search_terms:
                kw_results = db.execute(
                    "SELECT keyword FROM keywords WHERE document_id = ? AND keyword LIKE ?",
                    (doc_id, f"%{kw}%")
                ).fetchall()
                if kw_results:
                    matched_keywords.extend([row[0] for row in kw_results])
            
            results.append({
                'id': doc['id'],
                'filename': doc['filename'],
                'upload_date': doc['upload_date'],
                'matched_keywords': list(set(matched_keywords))
            })

    verification_bundle = None
    if verification_requested and search_succeeded:
        try:
            verification_bundle = _build_search_verification(
                matched_doc_ids, search_terms, user_id, role
            )
            proofs_by_document = {}
            for proof in verification_bundle["proofs"]:
                proofs_by_document.setdefault(proof["result_id"], []).append(proof)
            for result in results:
                result["verification_proofs"] = proofs_by_document.get(
                    result["id"], []
                )
        except Exception:
            app.logger.exception("Could not create search-result verification data")

    return render_template(
        "search_results.html",
        query=query,
        keywords=keywords,
        results=results,
        result_count=len(results),
        search_time_ms=round(search_duration_ms, 2),
        search_type=search_mode,
        semantic_enabled=semantic_requested,
        semantic_used=semantic_used,
        expanded_terms=search_terms if semantic_used else [],
        verification_requested=verification_requested,
        verification_bundle=verification_bundle,
        verification_expected_user_id=(
            None if role == "admin" else user_id
        ),
    )


@app.route("/api/search", methods=["POST"])
@login_required
def api_search():
    """API endpoint for search requests."""
    global cube_index, performance_tracker
    
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("query"), str):
        return jsonify({"error": "A JSON object with a string query is required"}), 400
    query = data["query"].strip()
    semantic_value = data.get("semantic", False)
    if not isinstance(semantic_value, bool):
        return jsonify({"error": "semantic must be a boolean"}), 400
    semantic_requested = semantic_value
    verification_requested = data.get("verify", False)
    if not isinstance(verification_requested, bool):
        return jsonify({"error": "verify must be a boolean"}), 400
    
    if not query or not cube_index:
        return jsonify({'error': 'Invalid query or search unavailable'}), 400

    requested_key_version = data.get("key_version")
    if requested_key_version is not None:
        try:
            requested_key_version = int(requested_key_version)
        except (TypeError, ValueError):
            return jsonify({"error": "key_version must be an integer"}), 400
        current_key_version = get_db().execute(
            "SELECT key_version FROM cube_config WHERE id = 1"
        ).fetchone()
        if not current_key_version or requested_key_version != current_key_version["key_version"]:
            return jsonify({"error": "Search credentials from a revoked key version were rejected."}), 401
    
    # Parse keywords
    keywords = _parse_search_keywords(query)
    if not keywords:
        return jsonify({"error": "A non-empty search query is required"}), 400
    search_terms = keywords
    semantic_used = False
    search_mode = "conjunctive" if len(keywords) > 1 else "exact"
    if semantic_requested:
        search_terms, semantic_used, search_mode = _expand_search_terms(
            query, keywords
        )
    
    # Perform search
    search_start = time.time()
    try:
        ensure_search_index_trustworthy()
        user_id = session["user_id"]
        role = session.get("role")
        matched_doc_ids = _search_terms(
            search_terms,
            None if role == "admin" else user_id,
            semantic=semantic_used,
        )
    except Exception:
        app.logger.exception("API search failed")
        return jsonify({"error": "Search is temporarily unavailable"}), 500
    
    search_duration_ms = (time.time() - search_start) * 1000
    
    # Log only results visible to this user.
    if performance_tracker:
        performance_tracker.log_search(
            user_id,
            query,
            len(search_terms),
            len(matched_doc_ids),
            search_duration_ms,
            search_mode,
        )
    
    response_data = {
        'query': query,
        'keywords': keywords,
        'semantic_enabled': semantic_requested,
        'semantic_used': semantic_used,
        'expanded_terms': search_terms if semantic_used else [],
        'search_mode': search_mode,
        'matched_document_ids': matched_doc_ids,
        'result_count': len(matched_doc_ids),
        'search_time_ms': round(search_duration_ms, 2)
    }
    if verification_requested:
        try:
            response_data["verification"] = _build_search_verification(
                matched_doc_ids, search_terms, user_id, role
            )
        except Exception:
            app.logger.exception("Could not create API search verification data")
            return jsonify(
                {"error": "Search verification is temporarily unavailable"}
            ), 500
    return jsonify(response_data)


def _build_cube_visualization(user_id):
    """Load safe, current-version CUBE rows and their real relational links."""
    db = get_db()
    version = cube_index.key_version
    scope_sql = "" if user_id is None else " AND d.owner = ?"
    scope_parameters = () if user_id is None else (user_id,)

    hki_rows = db.execute(
        """
        SELECT h.id, h.keyword_token, h.document_id, d.filename
        FROM cube_hki h
        JOIN documents d ON d.id = h.document_id
        WHERE h.key_version = ?""" + scope_sql + """
        ORDER BY h.id
        """,
        (version, *scope_parameters),
    ).fetchall()
    vkic_rows = db.execute(
        """
        SELECT v.id, v.keyword_token, v.document_id, d.filename,
               v.version, v.state
        FROM cube_vkic v
        JOIN documents d ON d.id = v.document_id
        WHERE v.key_version = ?""" + scope_sql + """
        ORDER BY v.id
        """,
        (version, *scope_parameters),
    ).fetchall()
    dic_rows = db.execute(
        """
        SELECT x.id, x.keyword_token, x.document_id, d.filename
        FROM cube_dic x
        JOIN documents d ON d.id = x.document_id
        WHERE x.key_version = ?""" + scope_sql + """
        ORDER BY x.id
        """,
        (version, *scope_parameters),
    ).fetchall()

    visible_tokens = {row["keyword_token"] for row in hki_rows}
    lcic_rows = db.execute(
        """
        SELECT id, keyword_token, counter, updated_at
        FROM cube_lcic
        WHERE key_version = ?
        ORDER BY id
        """,
        (version,),
    ).fetchall()
    lcic_rows = [
        row for row in lcic_rows if row["keyword_token"] in visible_tokens
    ]
    visible_tokens.update(row["keyword_token"] for row in vkic_rows)
    visible_tokens.update(row["keyword_token"] for row in dic_rows)

    keyword_rows = db.execute(
        """
        SELECT d.id AS document_id, d.owner, k.keyword
        FROM documents d
        JOIN keywords k ON k.document_id = d.id
        WHERE (? IS NULL OR d.owner = ?)
        ORDER BY d.id, k.id
        """,
        (user_id, user_id),
    ).fetchall()
    keyword_by_token = {}
    for row in keyword_rows:
        token = cube_index.generate_search_token(row["keyword"])
        if token in visible_tokens:
            keyword_by_token.setdefault(token, row["keyword"])

    query = request.args.get("query", "").strip()
    query_terms = _parse_search_keywords(query) if query else []
    matching_pairs = set()
    matching_document_ids = set()
    if query_terms:
        matching_document_ids = set(
            search_document_ids(query_terms, user_id=user_id)
        )
        matching_pairs = {
            (term, document_id)
            for term in query_terms
            for document_id in cube_index.search_single_keyword(term)
            if document_id in matching_document_ids
        }

    lcic = []
    hki = []
    vkic = []
    dic = []
    documents = {}
    lcic_by_token = {}
    hki_by_pair = {}
    vkic_by_pair = {}
    dic_by_pair = {}

    for row in lcic_rows:
        node_id = f"lcic-{row['id']}"
        token = row["keyword_token"]
        lcic_by_token[token] = node_id
        lcic.append({
            "id": node_id,
            "keyword": keyword_by_token.get(token, "Keyword unavailable"),
            "counter": row["counter"],
            "updated_at": row["updated_at"],
            "hki_ids": [],
            "highlighted": False,
        })

    for row in hki_rows:
        token = row["keyword_token"]
        document_id = row["document_id"]
        node_id = f"hki-{row['id']}"
        pair = (token, document_id)
        hki_by_pair.setdefault(pair, []).append(node_id)
        documents[document_id] = row["filename"]
        hki.append({
            "id": node_id,
            "keyword": keyword_by_token.get(token, "Keyword unavailable"),
            "document_id": document_id,
            "filename": row["filename"],
            "lcic_id": lcic_by_token.get(token),
            "vkic_ids": [],
            "highlighted": (
                (keyword_by_token.get(token, "").strip().lower(), document_id)
                in matching_pairs
            ),
        })

    for row in vkic_rows:
        pair = (row["keyword_token"], row["document_id"])
        node_id = f"vkic-{row['id']}"
        vkic_by_pair.setdefault(pair, []).append(node_id)
        vkic.append({
            "id": node_id,
            "keyword": keyword_by_token.get(
                row["keyword_token"], "Keyword unavailable"
            ),
            "document_id": row["document_id"],
            "filename": row["filename"],
            "version": row["version"],
            "state": row["state"],
            "dic_ids": [],
            "highlighted": (
                (
                    keyword_by_token.get(
                        row["keyword_token"], ""
                    ).strip().lower(),
                    row["document_id"],
                )
                in matching_pairs
            ),
        })

    for row in dic_rows:
        pair = (row["keyword_token"], row["document_id"])
        node_id = f"dic-{row['id']}"
        dic_by_pair.setdefault(pair, []).append(node_id)
        dic.append({
            "id": node_id,
            "keyword": keyword_by_token.get(
                row["keyword_token"], "Keyword unavailable"
            ),
            "document_id": row["document_id"],
            "filename": row["filename"],
            "highlighted": (
                (
                    keyword_by_token.get(
                        row["keyword_token"], ""
                    ).strip().lower(),
                    row["document_id"],
                )
                in matching_pairs
            ),
        })

    for entry in hki:
        token = next(
            row["keyword_token"]
            for row in hki_rows
            if f"hki-{row['id']}" == entry["id"]
        )
        if entry["lcic_id"]:
            lcic_node = next(node for node in lcic if node["id"] == entry["lcic_id"])
            lcic_node["hki_ids"].append(entry["id"])
            lcic_node["highlighted"] = (
                lcic_node["highlighted"] or entry["highlighted"]
            )
        entry["vkic_ids"] = vkic_by_pair.get((token, entry["document_id"]), [])

    for entry in vkic:
        row = next(
            row for row in vkic_rows if f"vkic-{row['id']}" == entry["id"]
        )
        entry["dic_ids"] = dic_by_pair.get(
            (row["keyword_token"], entry["document_id"]), []
        )

    return {
        "version": version,
        "query": query,
        "query_terms": query_terms,
        "matching_document_ids": sorted(matching_document_ids),
        "lcic": lcic,
        "hki": hki,
        "vkic": vkic,
        "dic": dic,
        "documents": [
            {"id": document_id, "filename": filename}
            for document_id, filename in sorted(documents.items())
        ],
    }


@app.route("/cube-dashboard")
@login_required
def cube_dashboard():
    """Visualize current, authorized CUBE records without exposing token values."""
    global cube_index

    try:
        ensure_search_index_trustworthy()
    except SearchIndexRecoveryError:
        app.logger.exception("Search-index recovery failed before CUBE dashboard")
        flash("CUBE status is temporarily unavailable.", "danger")
        return redirect(url_for("dashboard"))

    user_id = None if session.get("role") == "admin" else session["user_id"]
    cube_stats = cube_index.get_cube_stats(user_id=user_id) if cube_index else {}
    cube_data = _build_cube_visualization(user_id) if cube_index else {
        "version": None,
        "query": "",
        "query_terms": [],
        "matching_document_ids": [],
        "lcic": [],
        "hki": [],
        "vkic": [],
        "dic": [],
        "documents": [],
    }
    return render_template(
        "cube_visualization.html",
        cube_stats=cube_stats,
        cube_data=cube_data,
    )


@app.route("/admin/key-status", methods=["GET"])
@admin_required
def admin_key_status():
    try:
        ensure_search_index_trustworthy()
    except SearchIndexRecoveryError:
        app.logger.exception("Automatic search-index recovery failed")
        flash("Recovery failed. The current index was not activated.", "danger")
    state = get_db().execute(
        """
        SELECT key_version, key_status, previous_key_version, previous_key_status,
               recovery_status, recovery_timestamp, documents_reencrypted,
               verification_refresh_status, last_rotation_at, last_recovery_at,
               last_reconstruction_status, last_reconstruction_at
        FROM cube_config WHERE id = 1
        """
    ).fetchone()
    events = get_db().execute(
        """
        SELECT event_type, status, from_version, to_version, occurred_at
        FROM key_lifecycle_events ORDER BY id DESC LIMIT 20
        """
    ).fetchall()
    return render_template(
        "admin_key_status.html", state=state, events=events
    )


@app.route("/admin/security/recover", methods=["POST"])
@admin_required
def trigger_security_recovery():
    """Admin-only compromise trigger for the prototype recovery workflow."""
    try:
        new_version = rotate_search_key(recovery=True, force=True)
    except SearchIndexRecoveryError:
        flash("Security recovery failed. The current index was not activated.", "danger")
    else:
        flash(
            f"Security recovery triggered. Key version advanced to {new_version}.",
            "success",
        )
    return redirect(url_for("admin_key_status"))


@app.route("/admin/key-status/recover", methods=["POST"])
@admin_required
def admin_recover_search_index():
    return trigger_security_recovery()


@app.route("/performance")
@login_required
def performance():
    """Performance metrics dashboard."""
    global performance_tracker
    
    perf_summary = {}
    recent_searches = []
    
    if performance_tracker:
        user_id = None if session.get("role") == "admin" else session["user_id"]
        perf_summary = performance_tracker.get_performance_summary(user_id=user_id)
        recent_searches = performance_tracker.get_search_stats(
            limit=20, user_id=user_id
        )
    
    return render_template(
        "performance.html",
        perf_summary=perf_summary,
        recent_searches=recent_searches
    )


@app.route("/document/<int:document_id>/delete", methods=["POST"])
@login_required
def delete_document(document_id):
    """Delete document and remove from CUBE index."""
    global cube_index, performance_tracker

    try:
        ensure_search_index_trustworthy()
    except SearchIndexRecoveryError:
        app.logger.exception("Search-index recovery failed before document deletion")
        flash("Document deletion is unavailable while index recovery is attempted.", "danger")
        return redirect(url_for("dashboard"))
    
    db = get_db()
    document = db.execute(
        "SELECT * FROM documents WHERE id = ?",
        (document_id,)
    ).fetchone()
    
    if not document:
        flash("Document not found.", "danger")
        return redirect(url_for("dashboard"))
    
    # Check authorization
    if document["owner"] != session["user_id"] and session.get("role") != "admin":
        flash("You do not have permission to delete this document.", "danger")
        return redirect(url_for("dashboard"))
    
    encrypted_path = os.path.join(
        app.config["ENCRYPTED_FOLDER"], document["encrypted_path"]
    )
    quarantine_path = None
    if os.path.exists(encrypted_path):
        quarantine_path = f"{encrypted_path}.deleting-{uuid4().hex}"
        try:
            os.replace(encrypted_path, quarantine_path)
        except OSError:
            app.logger.exception("Could not stage encrypted document for deletion")
            flash("Document deletion failed; the document was not removed.", "danger")
            return redirect(url_for("dashboard"))

    try:
        del_start = time.time()
        if cube_index:
            cube_index.remove_document_index(
                document_id,
                datetime.datetime.utcnow().isoformat(),
                commit=False,
            )
        db.execute("DELETE FROM keywords WHERE document_id = ?", (document_id,))
        db.execute("DELETE FROM documents WHERE id = ?", (document_id,))
        _refresh_index_integrity(db)
        db.commit()
        del_duration_ms = (time.time() - del_start) * 1000
    except Exception:
        db.rollback()
        restoration_failed = False
        if quarantine_path and os.path.exists(quarantine_path):
            try:
                os.replace(quarantine_path, encrypted_path)
            except OSError:
                restoration_failed = True
                app.logger.exception("Could not restore encrypted document after deletion failure")
        app.logger.exception("Document deletion transaction failed")
        if restoration_failed:
            flash(
                "Deletion failed and the encrypted file could not be restored. "
                "The document record remains, but administrator recovery is required.",
                "danger",
            )
        else:
            flash("Document deletion failed; the document was not removed.", "danger")
        return redirect(url_for("dashboard"))

    if quarantine_path:
        try:
            os.remove(quarantine_path)
        except OSError:
            app.logger.exception("Could not remove quarantined encrypted document")
            flash(
                "The document record was removed, but encrypted-file cleanup failed. "
                "An administrator must remove the quarantined file.",
                "danger",
            )
            return redirect(url_for("dashboard"))

    if performance_tracker:
        try:
            performance_tracker.log_operation(
                "cube_index_deletion",
                del_duration_ms,
                f"doc={document_id}",
                session["user_id"],
            )
        except sqlite3.Error:
            app.logger.exception("Could not record document deletion performance")
    flash("Document deleted successfully.", "success")
    return redirect(url_for("dashboard"))


ensure_directories()
with app.app_context():
    create_tables()
    cleanup_legacy_plaintext_uploads()


if __name__ == "__main__":
    app.run(debug=False)
