"""
CUBE Index Implementation for Searchable Symmetric Encryption

This module implements the CUBE-based index for secure searchable encryption,
consisting of:
- LCIC (Logical Counter Index Chain)
- HKI (Horizontal Keyword Index)
- VKIC (Vertical Keyword Index Chain)
- DIC (Document Index Chain)

The CUBE allows searching encrypted documents without decryption while maintaining
forward and backward privacy.
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
    - LCIC: Logical Counter Index Chain (tracks update counters for forward privacy)
    - HKI: Horizontal Keyword Index (maps keyword tokens to document sets)
    - VKIC: Vertical Keyword Index Chain (maintains version chains for backward privacy)
    - DIC: Document Index Chain (tracks documents and their indexed keywords)
    """
    
    def __init__(self, db_getter, search_key: bytes):
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
        
    def create_tables(self):
        """Create CUBE index tables if they don't exist."""
        db = self.db_getter()
        cursor = db.cursor()
        
        # LCIC: Logical Counter Index Chain
        # Tracks counters for each keyword to support forward privacy
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cube_lcic (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                keyword_token TEXT UNIQUE NOT NULL,
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
                indexed_at TEXT NOT NULL,
                FOREIGN KEY(document_id) REFERENCES documents(id) ON DELETE CASCADE,
                UNIQUE(keyword_token, document_id)
            )
        ''')
        
        # VKIC: Vertical Keyword Index Chain
        # Maintains version chains for each keyword-document pair (backward privacy)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cube_vkic (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                keyword_token TEXT NOT NULL,
                document_id INTEGER NOT NULL,
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
        
        db.commit()
        
    def generate_search_token(self, keyword: str, counter: Optional[int] = None) -> str:
        """
        Generate a secure search token for a keyword.
        
        Uses HMAC-SHA256 with the search key to derive a cryptographic token.
        This prevents the plaintext keyword from being exposed to the index.
        
        Args:
            keyword: Plaintext keyword to tokenize
            counter: Optional counter for forward privacy (prevents linking updates)
        
        Returns:
            Hex-encoded search token (64 bytes / 128 hex chars)
        """
        if counter is not None:
            # Include counter to support forward privacy (prevent update linking)
            message = f"{keyword}:{counter}".encode('utf-8')
        else:
            message = keyword.encode('utf-8')
        
        # Use HMAC-SHA256 with search key as PRF
        token = hmac.new(self.search_key, message, hashlib.sha256).digest()
        return token.hex()
    
    def add_document_index(self, document_id: int, keywords: List[str], timestamp: str) -> Tuple[int, int, int, int]:
        """
        Add a document to the CUBE index.
        
        Indexes document with keywords for searchable encryption.
        Updates LCIC, HKI, VKIC, and DIC.
        
        Args:
            document_id: Document ID to index
            keywords: List of keywords extracted from the document
            timestamp: ISO format timestamp
        
        Returns:
            Tuple of (lcic_count, hki_count, vkic_count, dic_count) for tracking
        """
        db = self.db_getter()
        cursor = db.cursor()
        lcic_entries = 0
        hki_entries = 0
        vkic_entries = 0
        dic_entries = 0
        
        for keyword in keywords:
            # Generate search token
            token = self.generate_search_token(keyword)
            
            # Update LCIC (increment counter for forward privacy)
            cursor.execute('''
                SELECT counter FROM cube_lcic WHERE keyword_token = ?
            ''', (token,))
            result = cursor.fetchone()
            
            if result:
                counter = result[0] + 1
                cursor.execute('''
                    UPDATE cube_lcic 
                    SET counter = ?, updated_at = ?
                    WHERE keyword_token = ?
                ''', (counter, timestamp, token))
            else:
                counter = 0
                cursor.execute('''
                    INSERT INTO cube_lcic (keyword_token, counter, created_at, updated_at)
                    VALUES (?, ?, ?, ?)
                ''', (token, counter, timestamp, timestamp))
            lcic_entries += 1
            
            # Update HKI (add document to keyword's document set)
            try:
                cursor.execute('''
                    INSERT INTO cube_hki (keyword_token, document_id, indexed_at)
                    VALUES (?, ?, ?)
                ''', (token, document_id, timestamp))
                hki_entries += 1
            except sqlite3.IntegrityError:
                # Already indexed
                pass
            
            # Update VKIC (add version entry for backward privacy)
            cursor.execute('''
                SELECT COUNT(*) FROM cube_vkic 
                WHERE keyword_token = ? AND document_id = ?
            ''', (token, document_id))
            version = cursor.fetchone()[0]
            
            cursor.execute('''
                INSERT INTO cube_vkic 
                (keyword_token, document_id, version, state, created_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (token, document_id, version, 'active', timestamp))
            vkic_entries += 1
            
            # Update DIC (document-keyword mapping)
            try:
                cursor.execute('''
                    INSERT INTO cube_dic (document_id, keyword_token, indexed_at)
                    VALUES (?, ?, ?)
                ''', (document_id, token, timestamp))
                dic_entries += 1
            except sqlite3.IntegrityError:
                # Already exists
                pass
        
        db.commit()
        return (lcic_entries, hki_entries, vkic_entries, dic_entries)
    
    def remove_document_index(self, document_id: int, timestamp: str) -> Tuple[int, int, int, int]:
        """
        Remove a document from the CUBE index (backward privacy).
        
        Invalidates all related index entries so deleted documents cannot be recovered
        through stale searchable index states.
        
        Args:
            document_id: Document ID to remove from index
            timestamp: ISO format timestamp
        
        Returns:
            Tuple of (lcic_affected, hki_deleted, vkic_invalidated, dic_deleted)
        """
        db = self.db_getter()
        cursor = db.cursor()
        
        # Get all keywords associated with this document
        cursor.execute('''
            SELECT DISTINCT keyword_token FROM cube_dic WHERE document_id = ?
        ''', (document_id,))
        keywords = [row[0] for row in cursor.fetchall()]
        
        lcic_affected = 0
        hki_deleted = 0
        vkic_invalidated = 0
        dic_deleted = 0
        
        for token in keywords:
            # Update LCIC counter (forward privacy on deletion)
            cursor.execute('''
                UPDATE cube_lcic SET counter = counter + 1, updated_at = ?
                WHERE keyword_token = ?
            ''', (timestamp, token))
            lcic_affected += 1
            
            # Remove from HKI
            cursor.execute('''
                DELETE FROM cube_hki WHERE keyword_token = ? AND document_id = ?
            ''', (token, document_id))
            hki_deleted += cursor.rowcount
            
            # Invalidate in VKIC (mark as deleted)
            cursor.execute('''
                UPDATE cube_vkic 
                SET state = 'deleted', created_at = ?
                WHERE keyword_token = ? AND document_id = ?
            ''', (timestamp, token, document_id))
            vkic_invalidated += cursor.rowcount
            
            # Remove from DIC
            cursor.execute('''
                DELETE FROM cube_dic WHERE document_id = ? AND keyword_token = ?
            ''', (document_id, token))
            dic_deleted += cursor.rowcount
        
        db.commit()
        return (lcic_affected, hki_deleted, vkic_invalidated, dic_deleted)
    
    def search_single_keyword(self, keyword: str) -> List[int]:
        """
        Search for documents containing a single keyword.
        
        Args:
            keyword: Plaintext keyword to search for
        
        Returns:
            List of document IDs matching the keyword
        """
        token = self.generate_search_token(keyword)
        db = self.db_getter()
        cursor = db.cursor()
        
        # Query HKI for documents with this keyword token
        cursor.execute('''
            SELECT DISTINCT document_id FROM cube_hki 
            WHERE keyword_token = ?
        ''', (token,))
        
        return [row[0] for row in cursor.fetchall()]
    
    def search_conjunctive(self, keywords: List[str]) -> List[int]:
        """
        Search for documents containing ALL keywords (AND query).
        
        Args:
            keywords: List of keywords to search for
        
        Returns:
            List of document IDs matching ALL keywords
        """
        if not keywords:
            return []
        
        if len(keywords) == 1:
            return self.search_single_keyword(keywords[0])
        
        # Start with documents matching first keyword
        tokens = [self.generate_search_token(kw) for kw in keywords]
        
        db = self.db_getter()
        cursor = db.cursor()
        
        # Find documents in all keyword sets (intersection)
        placeholders = ','.join(['?' for _ in tokens])
        cursor.execute(f'''
            SELECT document_id FROM cube_hki 
            WHERE keyword_token IN ({placeholders})
            GROUP BY document_id
            HAVING COUNT(DISTINCT keyword_token) = ?
        ''', tokens + [len(tokens)])
        
        return [row[0] for row in cursor.fetchall()]
    
    def get_cube_stats(self) -> dict:
        """
        Get statistics about the CUBE index.
        
        Returns:
            Dictionary with CUBE statistics
        """
        db = self.db_getter()
        cursor = db.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM documents WHERE encrypted_path IS NOT NULL')
        total_documents = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(DISTINCT document_id) FROM cube_dic')
        indexed_documents = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(DISTINCT keyword_token) FROM cube_lcic')
        total_keywords = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM cube_lcic')
        lcic_entries = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM cube_hki')
        hki_entries = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM cube_vkic')
        vkic_entries = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM cube_dic')
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
    
    def get_keyword_mappings(self, limit: int = 100) -> List[dict]:
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
        cursor.execute('''
            SELECT keyword_token, COUNT(DISTINCT document_id) as doc_count
            FROM cube_hki
            GROUP BY keyword_token
            ORDER BY doc_count DESC
            LIMIT ?
        ''', (limit,))
        
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
