"""
Performance measurement utilities for DSSE operations.

Tracks timing for:
- AES encryption/decryption
- CUBE index construction/updates
- Search operations
- Dynamic insertion/deletion
"""

import time
import sqlite3
from typing import Dict, Optional
from functools import wraps
from contextlib import contextmanager


class PerformanceTracker:
    """Track and store performance metrics."""
    
    def __init__(self, db_getter):
        """Initialize performance tracker.
        
        Args:
            db_getter: Callable that returns a thread-safe connection, or a connection object
        """
        # Support both callable (Flask) and direct connection (tests)
        # Check if it's a connection object (has cursor method) vs a callable that returns one
        if hasattr(db_getter, 'cursor'):
            # It's a connection object, wrap it in a lambda
            self.db_getter = lambda: db_getter
        else:
            # It's a callable (function), use it directly
            self.db_getter = db_getter
        
        self._current_measurements = {}
    
    def create_tables(self):
        """Create performance logging tables."""
        db = self.db_getter()
        cursor = db.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS performance_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                operation TEXT NOT NULL,
                duration_ms REAL NOT NULL,
                details TEXT,
                timestamp TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS search_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                query TEXT NOT NULL,
                keyword_count INTEGER NOT NULL,
                result_count INTEGER NOT NULL,
                duration_ms REAL NOT NULL,
                search_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        
        db.commit()
    
    @contextmanager
    def measure_operation(self, operation_name: str, details: Optional[str] = None):
        """
        Context manager to measure operation duration.
        
        Usage:
            with tracker.measure_operation('encryption', 'document_123'):
                # perform operation
        """
        start_time = time.time()
        try:
            yield
        finally:
            duration_ms = (time.time() - start_time) * 1000
            self.log_operation(operation_name, duration_ms, details)
    
    def log_operation(self, operation: str, duration_ms: float, details: Optional[str] = None):
        """Log an operation's performance."""
        from datetime import datetime
        timestamp = datetime.utcnow().isoformat()
        
        db = self.db_getter()
        cursor = db.cursor()
        cursor.execute('''
            INSERT INTO performance_log 
            (operation, duration_ms, details, timestamp, created_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (operation, duration_ms, details, timestamp, timestamp))
        db.commit()
        
        self._current_measurements[operation] = {
            'duration_ms': duration_ms,
            'timestamp': timestamp
        }
    
    def log_search(self, user_id: int, query: str, keyword_count: int, 
                   result_count: int, duration_ms: float, search_type: str = 'keyword'):
        """Log a search operation."""
        from datetime import datetime
        timestamp = datetime.utcnow().isoformat()
        
        db = self.db_getter()
        cursor = db.cursor()
        cursor.execute('''
            INSERT INTO search_log 
            (user_id, query, keyword_count, result_count, duration_ms, search_type, timestamp, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, query, keyword_count, result_count, duration_ms, search_type, timestamp, timestamp))
        db.commit()
    
    def get_operation_stats(self, operation: str, limit: int = 100) -> list:
        """Get performance stats for a specific operation."""
        db = self.db_getter()
        cursor = db.cursor()
        cursor.execute('''
            SELECT duration_ms, timestamp, details 
            FROM performance_log
            WHERE operation = ?
            ORDER BY created_at DESC
            LIMIT ?
        ''', (operation, limit))
        
        stats = [
            {
                'duration_ms': row[0],
                'timestamp': row[1],
                'details': row[2]
            }
            for row in cursor.fetchall()
        ]
        
        if stats:
            durations = [s['duration_ms'] for s in stats]
            return {
                'operation': operation,
                'samples': len(durations),
                'avg_ms': sum(durations) / len(durations),
                'min_ms': min(durations),
                'max_ms': max(durations),
                'recent': stats[:5]
            }
        return {'operation': operation, 'samples': 0}
    
    def get_search_stats(self, limit: int = 50) -> list:
        """Get recent search statistics."""
        db = self.db_getter()
        cursor = db.cursor()
        cursor.execute('''
            SELECT query, keyword_count, result_count, duration_ms, search_type, timestamp
            FROM search_log
            ORDER BY created_at DESC
            LIMIT ?
        ''', (limit,))
        
        return [
            {
                'query': row[0],
                'keyword_count': row[1],
                'result_count': row[2],
                'duration_ms': row[3],
                'search_type': row[4],
                'timestamp': row[5]
            }
            for row in cursor.fetchall()
        ]
    
    def get_average_search_time(self) -> Optional[float]:
        """Get average search time across all searches."""
        db = self.db_getter()
        cursor = db.cursor()
        cursor.execute('SELECT AVG(duration_ms) FROM search_log')
        result = cursor.fetchone()
        return result[0] if result and result[0] else None
    
    def get_performance_summary(self) -> dict:
        """Get overall performance summary."""
        db = self.db_getter()
        cursor = db.cursor()
        
        # Encryption stats
        cursor.execute('''
            SELECT COUNT(*), AVG(duration_ms), MIN(duration_ms), MAX(duration_ms)
            FROM performance_log
            WHERE operation = 'encryption'
        ''')
        enc_result = cursor.fetchone()
        
        # Search stats
        cursor.execute('''
            SELECT COUNT(*), AVG(duration_ms)
            FROM search_log
        ''')
        search_result = cursor.fetchone()
        
        # CUBE update stats
        cursor.execute('''
            SELECT COUNT(*), AVG(duration_ms)
            FROM performance_log
            WHERE operation = 'cube_index_update'
        ''')
        cube_result = cursor.fetchone()
        
        return {
            'encryption': {
                'count': enc_result[0] if enc_result else 0,
                'avg_ms': enc_result[1] if enc_result and enc_result[1] else 0,
                'min_ms': enc_result[2] if enc_result and enc_result[2] else 0,
                'max_ms': enc_result[3] if enc_result and enc_result[3] else 0,
            },
            'search': {
                'count': search_result[0] if search_result else 0,
                'avg_ms': search_result[1] if search_result and search_result[1] else 0,
            },
            'cube_update': {
                'count': cube_result[0] if cube_result else 0,
                'avg_ms': cube_result[1] if cube_result and cube_result[1] else 0,
            }
        }
