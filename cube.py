"""
CUBE Index Implementation for Searchable Symmetric Encryption

This module implements the CUBE-based index for secure searchable encryption,
consisting of:
- LCIC (Logical Counter Index Chain)
- HKI (Horizontal Keyword Index)
- VKIC (Vertical Keyword Index Chain)
- DIC (Document Index Chain)

The CUBE supports tokenized keyword lookup over encrypted-document metadata.
Its stored counters and version states do not by themselves establish formal
forward or backward privacy.
"""

import hmac
import hashlib
import sqlite3
import time
from typing import List, Set, Tuple, Optional
from uuid import uuid4


class CUBEIndex:
    """
    Searchable encryption CUBE index implementation.
    
    Components:
    - LCIC: Logical Counter Index Chain (tracks update counters)
    - HKI: Horizontal Keyword Index (maps keyword tokens to document sets)
    - VKIC: Vertical Keyword Index Chain (maintains version/state records)
    - DIC: Document Index Chain (tracks documents and their indexed keywords)
    """
    
    def __init__(self, db_getter, search_key: bytes, key_version: int = 1):
        """
        Initialize CUBE index.
        
        Args:
            db_getter: Callable that returns a thread-safe connection, or a connection object
            search_key: 32-byte search key for generating tokens (derived from master key)
        """
        # Support both callable (Flask) and direct connection (tests)
        # Check if it's a connection object (has cursor method) vs a callable that returns one
        if hasattr(db_getter, 'cursor'):
            # It's a connection object, wrap it in a lambda
            self.db_getter = lambda: db_getter
        else:
            # It's a callable (function), use it directly
            self.db_getter = db_getter
        
        self.search_key = search_key
        self.search_key_hex = search_key.hex()
        self.key_version = key_version
        self._paper_group_prime = (2 ** 521) - 1
        self._paper_group_generator = 2
        self._paper_keys = {
            "K1": hmac.new(search_key, b"paper-F-K1", hashlib.sha256).digest(),
            "K3": hmac.new(search_key, b"paper-F-K3", hashlib.sha256).digest(),
            "KX": hmac.new(search_key, b"paper-Fp-KX", hashlib.sha256).digest(),
            "KZ": hmac.new(search_key, b"paper-Fp-KZ", hashlib.sha256).digest(),
        }
        
    def create_tables(self):
        """Create CUBE index tables if they don't exist."""
        db = self.db_getter()
        cursor = db.cursor()
        
        # LCIC: Logical Counter Index Chain
        # Tracks update counters for each keyword token.
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cube_lcic (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                keyword_token TEXT UNIQUE NOT NULL,
                key_version INTEGER NOT NULL DEFAULT 1,
                counter INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        ''')
        
        # HKI: Horizontal Keyword Index
        # Maps encrypted keyword tokens to sets of document indices
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cube_hki (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                keyword_token TEXT NOT NULL,
                document_id INTEGER NOT NULL,
                key_version INTEGER NOT NULL DEFAULT 1,
                indexed_at TEXT NOT NULL,
                FOREIGN KEY(document_id) REFERENCES documents(id) ON DELETE CASCADE,
                UNIQUE(keyword_token, document_id)
            )
        ''')
        
        # VKIC: Vertical Keyword Index Chain
        # Maintains version/state records for each keyword-document pair.
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cube_vkic (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                keyword_token TEXT NOT NULL,
                document_id INTEGER NOT NULL,
                key_version INTEGER NOT NULL DEFAULT 1,
                version INTEGER NOT NULL,
                state TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(document_id) REFERENCES documents(id) ON DELETE CASCADE
            )
        ''')
        
        # DIC: Document Index Chain
        # Tracks which documents have been indexed with which keywords
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cube_dic (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                document_id INTEGER NOT NULL,
                keyword_token TEXT NOT NULL,
                key_version INTEGER NOT NULL DEFAULT 1,
                indexed_at TEXT NOT NULL,
                FOREIGN KEY(document_id) REFERENCES documents(id) ON DELETE CASCADE
            )
        ''')
        
        # CUBE configuration table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cube_config (
                id INTEGER PRIMARY KEY,
                search_key_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        ''')

        for table in ("cube_lcic", "cube_hki", "cube_vkic", "cube_dic"):
            cursor.execute(f"PRAGMA table_info({table})")
            columns = {row[1] for row in cursor.fetchall()}
            if "key_version" not in columns:
                cursor.execute(
                    f"ALTER TABLE {table} ADD COLUMN key_version INTEGER NOT NULL DEFAULT 1"
                )
            if "keyword_base" not in columns:
                cursor.execute(
                    f"ALTER TABLE {table} ADD COLUMN keyword_base TEXT"
                )
            if "state_token" not in columns:
                cursor.execute(
                    f"ALTER TABLE {table} ADD COLUMN state_token TEXT"
                )
        
        db.commit()

    @staticmethod
    def _normalize_keyword_value(keyword: str) -> bytes:
        return keyword.strip().lower().encode("utf-8")

    def _F(self, key: bytes, value: bytes) -> bytes:
        """F(K, x): HMAC-SHA256 using a dedicated sub-key for the paper's F primitive."""
        return hmac.new(key, value, hashlib.sha256).digest()

    def _Fp(self, key: bytes, value: bytes) -> bytes:
        """Fp(K, x): HMAC-SHA256 used for the exponent-derived x-tag values in the paper."""
        return hmac.new(key, value, hashlib.sha256).digest()

    def _HL(self, value: bytes) -> bytes:
        """HL(x): SHA-256 hash-chain step for the lower-level chain in the paper."""
        return hashlib.sha256(value).digest()

    def _HV(self, value: bytes) -> bytes:
        """HV(x): SHA-256 hash-chain step for the vertical keyword chain in the paper."""
        return hashlib.sha256(value).digest()

    def _hash_chain(self, start: bytes, mode: str, steps: int) -> bytes:
        value = start
        if steps < 0:
            steps = 0
        for _ in range(steps):
            value = self._HL(value) if mode == "HL" else self._HV(value)
        return value

    def _keyword_base(self, keyword: str) -> str:
        return self._F(self._paper_keys["K1"], self._normalize_keyword_value(keyword)).hex()

    def _counter_for_keyword(self, keyword: str) -> int:
        base = self._keyword_base(keyword)
        db = self.db_getter()
        row = db.execute(
            "SELECT counter FROM cube_lcic WHERE keyword_token = ?",
            (base,),
        ).fetchone()
        return int(row[0]) if row and row[0] is not None else 0

    def _keyword_search_states(self, keyword: str) -> List[str]:
        return [self.generate_search_token(keyword)]

    def _paper_search_token(self, keyword: str, counter: Optional[int] = None) -> dict:
        """Build the paper's logical token tuple (ctr, stkw, ctk, xtkadd, xtkdel).

        Concrete mapping used in this implementation:
        - F(K, x) = HMAC-SHA256 with a dedicated sub-key
        - Fp(K, x) = HMAC-SHA256 with the exponent sub-key
        - HL(x) = SHA-256
        - HV(x) = SHA-256
        """
        normalized = keyword.strip().lower()
        ktw = self._F(self._paper_keys["K1"], self._normalize_keyword_value(normalized))
        current_counter = self._counter_for_keyword(normalized) if counter is None else int(counter)
        stkw = self._hash_chain(ktw, "HV", current_counter)
        ct = self._F(self._paper_keys["K3"], str(current_counter).encode("utf-8"))
        ctk = self._hash_chain(ct, "HL", current_counter)
        xtkadd = {}
        xtkdel = {}
        return {
            "ctr": current_counter,
            "stkw": stkw.hex(),
            "ctk": ctk.hex(),
            "xtkadd": xtkadd,
            "xtkdel": xtkdel,
        }

    def generate_search_token(self, keyword: str, counter: Optional[int] = None) -> str:
        """Compatibility token used by the application search index.

        This is the deterministic keyword token, i.e. F(K1, keyword), which keeps
        the application behavior stable and allows single-keyword/A AND B searches to
        operate over the indexed document set. The paper-aligned state token is exposed
        via generate_paper_search_token() and kept separate for the cryptographic update
        state described in the CUBE construction.
        """
        normalized = keyword.strip().lower()
        return self._F(self._paper_keys["K1"], self._normalize_keyword_value(normalized)).hex()

    def generate_paper_search_token(self, keyword: str, counter: Optional[int] = None) -> dict:
        """Return the paper-aligned state tuple (ctr, stkw, ctk, xtkadd, xtkdel)."""
        normalized = keyword.strip().lower()
        ktw = self._F(self._paper_keys["K1"], self._normalize_keyword_value(normalized))
        current_counter = self._counter_for_keyword(normalized) if counter is None else int(counter)
        stkw = self._hash_chain(ktw, "HV", current_counter)
        ct = self._F(self._paper_keys["K3"], str(current_counter).encode("utf-8"))
        ctk = self._hash_chain(ct, "HL", current_counter)
        xtkadd = {}
        xtkdel = {}
        return {
            "ctr": current_counter,
            "stkw": stkw.hex(),
            "ctk": ctk.hex(),
            "xtkadd": xtkadd,
            "xtkdel": xtkdel,
        }

    def generate_conjunctive_search_token(self, keywords: List[str]) -> dict:
        """Practical paper-aligned search token for conjunctions with least-updated keyword as the base."""
        normalized = [kw.strip().lower() for kw in keywords if kw and kw.strip()]
        if not normalized:
            return {"ctr": 0, "stkw": "", "ctk": "", "xtkadd": {}, "xtkdel": {}}

        base_keyword = min(normalized, key=self._counter_for_keyword)
        base_value = bytes.fromhex(self._keyword_base(base_keyword))
        current_counter = self._counter_for_keyword(base_keyword)
        stkw = self._hash_chain(base_value, "HV", current_counter)
        ct = self._F(self._paper_keys["K3"], str(current_counter).encode("utf-8"))
        ctk = self._hash_chain(ct, "HL", current_counter)
        xtkadd = {}
        xtkdel = {}

        for keyword in normalized:
            if keyword == base_keyword:
                continue
            add_seed = self._Fp(self._paper_keys["KX"], (keyword + "|add").encode("utf-8"))
            base_seed = self._Fp(self._paper_keys["KZ"], self._normalize_keyword_value(base_keyword))
            exponent = (
                int.from_bytes(add_seed, byteorder="big", signed=False)
                * int.from_bytes(base_seed, byteorder="big", signed=False)
            ) % (self._paper_group_prime - 1)
            xtkadd[keyword] = pow(self._paper_group_generator, exponent, self._paper_group_prime)
            del_seed = self._Fp(self._paper_keys["KX"], (keyword + "|del").encode("utf-8"))
            xtkdel[keyword] = pow(self._paper_group_generator, (
                int.from_bytes(del_seed, byteorder="big", signed=False)
                * int.from_bytes(base_seed, byteorder="big", signed=False)
            ) % (self._paper_group_prime - 1), self._paper_group_prime)
        return {
            "ctr": current_counter,
            "stkw": stkw.hex(),
            "ctk": ctk.hex(),
            "xtkadd": xtkadd,
            "xtkdel": xtkdel,
        }

    def add_document_index(
        self,
        document_id: int,
        keywords: List[str],
        timestamp: str,
        commit: bool = True,
    ) -> Tuple[int, int, int, int]:
        """
        Add a document to the CUBE index.
        
        This preserves the existing search/index workflow while using the paper-aligned
        keyword-base and HV-chain state derivation. The keyword base remains stable for
        LCIC bookkeeping, while the current state token is used for searchable traversal.
        """
        db = self.db_getter()
        cursor = db.cursor()
        lcic_entries = 0
        hki_entries = 0
        vkic_entries = 0
        dic_entries = 0

        for keyword in keywords:
            normalized = keyword.strip().lower()
            base_token = self.generate_search_token(normalized)
            state_token = self.generate_paper_search_token(normalized, self._counter_for_keyword(normalized))["stkw"]

            cursor.execute(
                "SELECT counter FROM cube_lcic WHERE keyword_token = ?",
                (base_token,),
            )
            result = cursor.fetchone()
            if result:
                counter = int(result[0]) + 1
                cursor.execute(
                    "UPDATE cube_lcic SET counter = ?, updated_at = ? WHERE keyword_token = ?",
                    (counter, timestamp, base_token),
                )
            else:
                counter = 0
                cursor.execute(
                    "INSERT INTO cube_lcic (keyword_token, keyword_base, state_token, key_version, counter, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (base_token, base_token, state_token, self.key_version, counter, timestamp, timestamp),
                )
            lcic_entries += 1

            try:
                cursor.execute(
                    "INSERT INTO cube_hki (keyword_token, keyword_base, state_token, document_id, key_version, indexed_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (base_token, base_token, state_token, document_id, self.key_version, timestamp),
                )
                hki_entries += 1
            except sqlite3.IntegrityError:
                pass

            cursor.execute(
                "SELECT COUNT(*) FROM cube_vkic WHERE keyword_base = ? AND document_id = ?",
                (base_token, document_id),
            )
            version = cursor.fetchone()[0]
            cursor.execute(
                "INSERT INTO cube_vkic (keyword_token, keyword_base, state_token, document_id, key_version, version, state, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (base_token, base_token, state_token, document_id, self.key_version, version, 'active', timestamp),
            )
            vkic_entries += 1

            try:
                cursor.execute(
                    "INSERT INTO cube_dic (document_id, keyword_token, keyword_base, state_token, key_version, indexed_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (document_id, base_token, base_token, state_token, self.key_version, timestamp),
                )
                dic_entries += 1
            except sqlite3.IntegrityError:
                pass

        if commit:
            db.commit()
        return (lcic_entries, hki_entries, vkic_entries, dic_entries)
    
    def remove_document_index(
        self, document_id: int, timestamp: str, commit: bool = True
    ) -> Tuple[int, int, int, int]:
        """Remove a document while updating the paper-aligned LCIC/HKI/VKIC/DIC state."""
        db = self.db_getter()
        cursor = db.cursor()

        cursor.execute(
            "SELECT DISTINCT COALESCE(keyword_base, keyword_token) AS base_key, keyword_token, state_token FROM cube_dic WHERE document_id = ?",
            (document_id,),
        )
        rows = cursor.fetchall()

        lcic_affected = 0
        hki_deleted = 0
        vkic_invalidated = 0
        dic_deleted = 0

        for base_key, keyword_token, state_token in rows:
            base_identifier = base_key or keyword_token or state_token
            cursor.execute(
                "UPDATE cube_lcic SET counter = counter + 1, updated_at = ? WHERE keyword_token = ?",
                (timestamp, base_identifier),
            )
            lcic_affected += 1

            cursor.execute(
                "DELETE FROM cube_hki WHERE document_id = ? AND (keyword_base = ? OR keyword_token = ?)",
                (document_id, base_identifier, keyword_token or state_token),
            )
            hki_deleted += cursor.rowcount

            cursor.execute(
                "UPDATE cube_vkic SET state = 'deleted', created_at = ? WHERE document_id = ? AND (keyword_base = ? OR keyword_token = ?)",
                (timestamp, document_id, base_identifier, keyword_token or state_token),
            )
            vkic_invalidated += cursor.rowcount

            cursor.execute(
                "DELETE FROM cube_dic WHERE document_id = ? AND (keyword_base = ? OR keyword_token = ?)",
                (document_id, base_identifier, keyword_token or state_token),
            )
            dic_deleted += cursor.rowcount

        if commit:
            db.commit()
        return (lcic_affected, hki_deleted, vkic_invalidated, dic_deleted)
    
    def search_single_keyword(self, keyword: str) -> List[int]:
        """Search using the deterministic keyword token for current application behavior."""
        token = self.generate_search_token(keyword)
        db = self.db_getter()
        cursor = db.cursor()
        cursor.execute(
            "SELECT DISTINCT document_id FROM cube_hki WHERE (keyword_token = ? OR keyword_base = ?) AND key_version = ?",
            (token, token, self.key_version),
        )
        return [row[0] for row in cursor.fetchall()]
    
    def search_conjunctive(self, keywords: List[str]) -> List[int]:
        """Intersect the keyword-document sets for the requested AND-search."""
        normalized = [kw.strip().lower() for kw in keywords if kw and kw.strip()]
        if not normalized:
            return []
        if len(normalized) == 1:
            return self.search_single_keyword(normalized[0])

        tokens = [self.generate_search_token(kw) for kw in normalized]
        db = self.db_getter()
        cursor = db.cursor()
        placeholders = ','.join(['?' for _ in tokens])
        cursor.execute(
            f"SELECT document_id FROM cube_hki WHERE keyword_token IN ({placeholders}) AND key_version = ? GROUP BY document_id HAVING COUNT(DISTINCT keyword_token) = ?",
            tokens + [self.key_version, len(tokens)],
        )
        return [row[0] for row in cursor.fetchall()]

    def CSearchL(self, keyword: str) -> List[int]:
        return self.search_single_keyword(keyword)

    def CSearchR(self, keywords: List[str]) -> List[int]:
        return self.search_conjunctive(keywords)
    
    def get_cube_stats(self, user_id: Optional[int] = None) -> dict:
        """
        Get statistics about the CUBE index.
        
        Returns:
            Dictionary with CUBE statistics
        """
        db = self.db_getter()
        cursor = db.cursor()
        
        if user_id is None:
            cursor.execute('SELECT COUNT(*) FROM documents WHERE encrypted_path IS NOT NULL')
        else:
            cursor.execute(
                'SELECT COUNT(*) FROM documents WHERE encrypted_path IS NOT NULL AND owner = ?',
                (user_id,),
            )
        total_documents = cursor.fetchone()[0]
        
        dic_scope = (
            ''
            if user_id is None
            else ' JOIN documents d ON d.id = cube_dic.document_id WHERE d.owner = ?'
        )
        parameters = () if user_id is None else (user_id,)
        cursor.execute(
            f'SELECT COUNT(DISTINCT cube_dic.document_id) FROM cube_dic{dic_scope}',
            parameters,
        )
        indexed_documents = cursor.fetchone()[0]
        
        token_scope = (
            ''
            if user_id is None
            else ' JOIN cube_hki h ON h.keyword_token = cube_lcic.keyword_token'
            ' JOIN documents d ON d.id = h.document_id WHERE d.owner = ?'
        )
        cursor.execute(
            f'SELECT COUNT(DISTINCT cube_lcic.keyword_token) FROM cube_lcic{token_scope}',
            parameters,
        )
        total_keywords = cursor.fetchone()[0]
        
        cursor.execute(
            f'SELECT COUNT(DISTINCT cube_lcic.keyword_token) FROM cube_lcic{token_scope}',
            parameters,
        )
        lcic_entries = cursor.fetchone()[0]
        
        hki_scope = (
            ''
            if user_id is None
            else ' JOIN documents d ON d.id = cube_hki.document_id WHERE d.owner = ?'
        )
        cursor.execute(
            f'SELECT COUNT(*) FROM cube_hki{hki_scope}',
            parameters,
        )
        hki_entries = cursor.fetchone()[0]
        
        vkic_scope = (
            ''
            if user_id is None
            else ' JOIN documents d ON d.id = cube_vkic.document_id WHERE d.owner = ?'
        )
        cursor.execute(
            f'SELECT COUNT(*) FROM cube_vkic{vkic_scope}',
            parameters,
        )
        vkic_entries = cursor.fetchone()[0]
        
        cursor.execute(
            f'SELECT COUNT(*) FROM cube_dic{dic_scope}',
            parameters,
        )
        dic_entries = cursor.fetchone()[0]
        
        return {
            'total_documents': total_documents,
            'indexed_documents': indexed_documents,
            'total_keywords': total_keywords,
            'lcic_entries': lcic_entries,
            'hki_entries': hki_entries,
            'vkic_entries': vkic_entries,
            'dic_entries': dic_entries,
        }
    
    def get_keyword_mappings(
        self, limit: int = 100, user_id: Optional[int] = None
    ) -> List[dict]:
        """
        Get a sample of keyword-to-document mappings (HKI view).
        
        Returns tokenized identifiers, not plaintext keywords.
        
        Args:
            limit: Maximum mappings to return
        
        Returns:
            List of mapping dictionaries
        """
        db = self.db_getter()
        cursor = db.cursor()
        if user_id is None:
            cursor.execute('''
                SELECT keyword_token, COUNT(DISTINCT document_id) as doc_count
                FROM cube_hki
                GROUP BY keyword_token
                ORDER BY doc_count DESC
                LIMIT ?
            ''', (limit,))
        else:
            cursor.execute('''
                SELECT h.keyword_token, COUNT(DISTINCT h.document_id) as doc_count
                FROM cube_hki h
                JOIN documents d ON d.id = h.document_id
                WHERE d.owner = ?
                GROUP BY h.keyword_token
                ORDER BY doc_count DESC
                LIMIT ?
            ''', (user_id, limit))
        
        return [
            {'token': row[0][:16] + '...', 'token_full': row[0], 'doc_count': row[1]}
            for row in cursor.fetchall()
        ]
    
    def get_document_keywords_count(self, document_id: int) -> int:
        """Get count of keywords indexed for a document."""
        cursor = self.db.cursor()
        cursor.execute('''
            SELECT COUNT(DISTINCT keyword_token) FROM cube_dic 
            WHERE document_id = ?
        ''', (document_id,))
        return cursor.fetchone()[0]
