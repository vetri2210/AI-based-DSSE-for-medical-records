"""
Review-2 Comprehensive Test Suite

Tests for:
- CUBE index construction
- Secure search token generation
- Single keyword search
- Conjunctive search
- Dynamic insertion
- Dynamic deletion
- Backward privacy
- Performance measurement
- API endpoints
"""

import os
import sys
import sqlite3
import datetime
import time
import tempfile
from pathlib import Path

# Add project directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, get_db, create_tables
from cube import CUBEIndex
from performance import PerformanceTracker


class TestRunner:
    """Test runner for Review-2 features."""
    
    def __init__(self):
        self.test_results = []
        self.db = None
        self.cube_index = None
        self.perf_tracker = None
        self.search_key = b'test_search_key_for_dsse_testing'
        
    def setup(self):
        """Set up test environment."""
        print("=" * 70)
        print("REVIEW-2 TEST SUITE - SEARCHABLE SYMMETRIC ENCRYPTION")
        print("=" * 70)
        
        # Use in-memory SQLite for testing
        self.db = sqlite3.connect(':memory:')
        self.db.row_factory = sqlite3.Row
        
        # Create tables
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, role TEXT)"
        )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS documents (id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, owner INTEGER, upload_date TEXT, encrypted_path TEXT, aes_key TEXT, FOREIGN KEY(owner) REFERENCES users(id))"
        )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS keywords (id INTEGER PRIMARY KEY AUTOINCREMENT, document_id INTEGER, keyword TEXT, FOREIGN KEY(document_id) REFERENCES documents(id))"
        )
        self.db.commit()
        
        # Initialize CUBE and performance tracker
        self.cube_index = CUBEIndex(self.db, self.search_key)
        self.cube_index.create_tables()
        
        self.perf_tracker = PerformanceTracker(self.db)
        self.perf_tracker.create_tables()
        
        # Insert test user
        self.db.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ('testuser', 'hashedpassword', 'student')
        )
        self.db.commit()
        
        print("\n[PASS] Test environment initialized\n")
    
    def test_cube_initialization(self):
        """Test 1: CUBE index initialization."""
        print("TEST 1: CUBE Index Initialization")
        print("-" * 70)
        
        try:
            stats = self.cube_index.get_cube_stats()
            assert stats['total_documents'] == 0
            assert stats['lcic_entries'] == 0
            assert stats['hki_entries'] == 0
            assert stats['vkic_entries'] == 0
            assert stats['dic_entries'] == 0
            
            self.result("PASS", "CUBE index initialized correctly")
            return True
        except Exception as e:
            self.result("FAIL", f"CUBE initialization failed: {str(e)}")
            return False
    
    def test_search_token_generation(self):
        """Test 2: Secure search token generation."""
        print("TEST 2: Secure Search Token Generation")
        print("-" * 70)
        
        try:
            keyword = "diabetes"
            
            # Generate tokens
            token1 = self.cube_index.generate_search_token(keyword)
            token2 = self.cube_index.generate_search_token(keyword)
            token_diff = self.cube_index.generate_search_token("hypertension")
            
            # Verify tokens are deterministic (same keyword = same token)
            assert token1 == token2, "Same keyword should generate same token"
            
            # Verify different keywords generate different tokens
            assert token1 != token_diff, "Different keywords should generate different tokens"
            
            # Verify tokens are hex-encoded and reasonable length
            assert len(token1) == 64, "Token should be 64 hex characters (256 bits)"
            assert all(c in '0123456789abcdef' for c in token1), "Token should be valid hex"
            
            # Verify plaintext keyword is not exposed
            assert keyword not in token1, "Token should not contain plaintext keyword"
            
            self.result("PASS", f"Search tokens generated securely: {token1[:16]}...")
            return True
        except Exception as e:
            self.result("FAIL", f"Search token generation failed: {str(e)}")
            return False
    
    def test_single_keyword_search(self):
        """Test 3: Single keyword search."""
        print("TEST 3: Single Keyword Search")
        print("-" * 70)
        
        try:
            # Insert test documents
            cursor = self.db.cursor()
            cursor.execute(
                "INSERT INTO documents (filename, owner, upload_date, encrypted_path, aes_key) "
                "VALUES (?, ?, ?, ?, ?)",
                ('doc1.pdf', 1, datetime.datetime.utcnow().isoformat(), 'enc1', 'key1')
            )
            doc_id1 = cursor.lastrowid
            
            cursor.execute(
                "INSERT INTO documents (filename, owner, upload_date, encrypted_path, aes_key) "
                "VALUES (?, ?, ?, ?, ?)",
                ('doc2.pdf', 1, datetime.datetime.utcnow().isoformat(), 'enc2', 'key2')
            )
            doc_id2 = cursor.lastrowid
            self.db.commit()
            
            # Index documents
            keywords1 = ['diabetes', 'hypertension', 'medication']
            keywords2 = ['hypertension', 'chronic', 'disease']
            
            ts = datetime.datetime.utcnow().isoformat()
            self.cube_index.add_document_index(doc_id1, keywords1, ts)
            self.cube_index.add_document_index(doc_id2, keywords2, ts)
            
            # Search for keyword
            results = self.cube_index.search_single_keyword('diabetes')
            
            assert len(results) == 1, "Should find 1 document with 'diabetes'"
            assert doc_id1 in results, "Should find doc1 with 'diabetes'"
            assert doc_id2 not in results, "Should not find doc2 with 'diabetes'"
            
            # Search for keyword present in both
            results = self.cube_index.search_single_keyword('hypertension')
            assert len(results) == 2, "Should find 2 documents with 'hypertension'"
            
            # Search for non-existent keyword
            results = self.cube_index.search_single_keyword('nonexistent')
            assert len(results) == 0, "Should find no documents with 'nonexistent'"
            
            self.result("PASS", "Single keyword search works correctly")
            return True
        except Exception as e:
            self.result("FAIL", f"Single keyword search failed: {str(e)}")
            return False
    
    def test_conjunctive_search(self):
        """Test 4: Conjunctive (AND) search."""
        print("TEST 4: Conjunctive Keyword Search (AND)")
        print("-" * 70)
        
        try:
            # Documents already indexed from previous test
            
            # Search for conjunction
            results = self.cube_index.search_conjunctive(['diabetes', 'hypertension'])
            
            # Only doc1 has both keywords
            assert len(results) == 1, "Should find 1 document with both keywords"
            assert results[0] == 1, "Should find doc1"
            
            # Three-way conjunction
            results = self.cube_index.search_conjunctive(['hypertension', 'chronic', 'disease'])
            assert len(results) == 1, "Should find 1 document with all 3 keywords"
            assert results[0] == 2, "Should find doc2"
            
            # Impossible conjunction
            results = self.cube_index.search_conjunctive(['diabetes', 'chronic'])
            assert len(results) == 0, "Should find no documents with both 'diabetes' and 'chronic'"
            
            self.result("PASS", "Conjunctive search works correctly")
            return True
        except Exception as e:
            self.result("FAIL", f"Conjunctive search failed: {str(e)}")
            return False
    
    def test_dynamic_insertion(self):
        """Test 5: Dynamic document insertion and CUBE update."""
        print("TEST 5: Dynamic Document Insertion")
        print("-" * 70)
        
        try:
            # Get initial stats
            stats_before = self.cube_index.get_cube_stats()
            
            # Insert new document
            cursor = self.db.cursor()
            cursor.execute(
                "INSERT INTO documents (filename, owner, upload_date, encrypted_path, aes_key) "
                "VALUES (?, ?, ?, ?, ?)",
                ('doc3.pdf', 1, datetime.datetime.utcnow().isoformat(), 'enc3', 'key3')
            )
            doc_id3 = cursor.lastrowid
            self.db.commit()
            
            # Index it
            new_keywords = ['diabetes', 'kidney']
            ts = datetime.datetime.utcnow().isoformat()
            self.cube_index.add_document_index(doc_id3, new_keywords, ts)
            
            # Verify CUBE updated
            stats_after = self.cube_index.get_cube_stats()
            assert stats_after['indexed_documents'] > stats_before['indexed_documents'], \
                "Indexed documents count should increase"
            assert stats_after['hki_entries'] > stats_before['hki_entries'], \
                "HKI entries should increase"
            
            # Verify new document is searchable
            results = self.cube_index.search_single_keyword('kidney')
            assert doc_id3 in results, "Newly inserted document should be searchable"
            
            self.result("PASS", "Dynamic insertion and CUBE update works")
            return True
        except Exception as e:
            self.result("FAIL", f"Dynamic insertion failed: {str(e)}")
            return False
    
    def test_dynamic_deletion(self):
        """Test 6: Dynamic document deletion and backward privacy."""
        print("TEST 6: Dynamic Document Deletion (Backward Privacy)")
        print("-" * 70)
        
        try:
            # Verify document is searchable before deletion
            results_before = self.cube_index.search_single_keyword('kidney')
            doc_id3 = 3  # From previous test
            assert doc_id3 in results_before, "Document should be searchable before deletion"
            
            # Delete document
            ts = datetime.datetime.utcnow().isoformat()
            self.cube_index.remove_document_index(doc_id3, ts)
            
            # Verify document is NOT searchable after deletion
            results_after = self.cube_index.search_single_keyword('kidney')
            assert doc_id3 not in results_after, \
                "Document should NOT be searchable after deletion (backward privacy)"
            
            # Verify other documents still work
            results = self.cube_index.search_single_keyword('diabetes')
            assert doc_id3 not in results, "Deleted document should not appear"
            assert 1 in results, "Other documents should still be searchable"
            
            self.result("PASS", "Dynamic deletion and backward privacy enforced")
            return True
        except Exception as e:
            self.result("FAIL", f"Dynamic deletion failed: {str(e)}")
            return False
    
    def test_cube_statistics(self):
        """Test 7: CUBE statistics and status."""
        print("TEST 7: CUBE Statistics")
        print("-" * 70)
        
        try:
            stats = self.cube_index.get_cube_stats()
            
            # Verify all expected keys exist
            required_keys = [
                'total_documents', 'indexed_documents', 'total_keywords',
                'lcic_entries', 'hki_entries', 'vkic_entries', 'dic_entries'
            ]
            for key in required_keys:
                assert key in stats, f"Missing key in stats: {key}"
                assert isinstance(stats[key], int), f"Stats[{key}] should be integer"
            
            # Verify reasonable values
            assert stats['total_documents'] > 0, "Should have documents"
            assert stats['hki_entries'] > 0, "Should have HKI entries"
            
            print(f"\nCUBE Statistics:")
            print(f"  Total Documents:      {stats['total_documents']}")
            print(f"  Indexed Documents:    {stats['indexed_documents']}")
            print(f"  Total Keywords:       {stats['total_keywords']}")
            print(f"  LCIC Entries:         {stats['lcic_entries']}")
            print(f"  HKI Entries:          {stats['hki_entries']}")
            print(f"  VKIC Entries:         {stats['vkic_entries']}")
            print(f"  DIC Entries:          {stats['dic_entries']}")
            
            self.result("PASS", "CUBE statistics available and correct")
            return True
        except Exception as e:
            self.result("FAIL", f"CUBE statistics failed: {str(e)}")
            return False
    
    def test_keyword_mappings(self):
        """Test 8: Keyword-document mappings don't expose plaintext."""
        print("TEST 8: Keyword Mappings Privacy")
        print("-" * 70)
        
        try:
            mappings = self.cube_index.get_keyword_mappings(limit=10)
            
            # Verify mappings are present
            assert len(mappings) > 0, "Should have keyword mappings"
            
            # Verify tokens are encrypted (not plaintext keywords)
            keywords_to_check = ['diabetes', 'hypertension', 'kidney', 'chronic']
            for mapping in mappings:
                for keyword in keywords_to_check:
                    assert keyword not in mapping['token'], \
                        f"Mapping should not expose plaintext keyword '{keyword}'"
            
            print(f"\nSample Keyword Mappings (tokens are encrypted):")
            for i, mapping in enumerate(mappings[:3]):
                print(f"  Token {i+1}: {mapping['token']} -> {mapping['doc_count']} document(s)")
            
            self.result("PASS", "Keyword mappings remain encrypted")
            return True
        except Exception as e:
            self.result("FAIL", f"Keyword mappings test failed: {str(e)}")
            return False
    
    def test_performance_logging(self):
        """Test 9: Performance measurement."""
        print("TEST 9: Performance Measurement")
        print("-" * 70)
        
        try:
            # Log some test operations
            self.perf_tracker.log_operation('encryption', 25.5, 'test_doc.pdf')
            self.perf_tracker.log_operation('encryption', 23.2, 'test_doc2.pdf')
            self.perf_tracker.log_search(1, 'diabetes', 1, 2, 15.3, 'single')
            self.perf_tracker.log_search(1, 'diabetes AND hypertension', 2, 1, 18.5, 'conjunctive')
            
            # Get stats
            perf_summary = self.perf_tracker.get_performance_summary()
            search_stats = self.perf_tracker.get_search_stats()
            
            assert perf_summary['encryption']['count'] == 2, "Should have 2 encryption logs"
            assert perf_summary['search']['count'] == 2, "Should have 2 search logs"
            assert len(search_stats) == 2, "Should retrieve 2 search records"
            
            print(f"\nPerformance Summary:")
            print(f"  Encryption operations: {perf_summary['encryption']['count']}")
            print(f"    Average: {perf_summary['encryption']['avg_ms']:.2f} ms")
            print(f"  Search operations:     {perf_summary['search']['count']}")
            print(f"    Average: {perf_summary['search']['avg_ms']:.2f} ms")
            
            self.result("PASS", "Performance tracking works correctly")
            return True
        except Exception as e:
            self.result("FAIL", f"Performance tracking failed: {str(e)}")
            return False
    
    def test_review1_encryption_still_works(self):
        """Test 10: Verify Review-1 encryption/decryption still works."""
        print("TEST 10: Review-1 Encryption Compatibility")
        print("-" * 70)
        
        try:
            from app import encrypt_file, decrypt_bytes
            import tempfile
            
            # Create test file
            with tempfile.NamedTemporaryFile(delete=False, mode='w') as f:
                f.write("Medical Record: Patient has diabetes and hypertension.")
                test_file = f.name
            
            # Encrypt
            with tempfile.NamedTemporaryFile(delete=False) as f:
                enc_file = f.name
            
            enc_key = encrypt_file(test_file, enc_file)
            
            # Decrypt
            with open(enc_file, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = decrypt_bytes(encrypted_data, enc_key)
            decrypted_text = decrypted_data.decode('utf-8')
            
            assert "Medical Record" in decrypted_text, "Decryption should restore plaintext"
            assert "diabetes" in decrypted_text, "Medical content should be preserved"
            
            # Cleanup
            os.remove(test_file)
            os.remove(enc_file)
            
            self.result("PASS", "Review-1 encryption/decryption still works")
            return True
        except Exception as e:
            self.result("FAIL", f"Encryption compatibility failed: {str(e)}")
            return False
    
    def result(self, status, message):
        """Record test result."""
        self.test_results.append((status, message))
        status_symbol = "[PASS]" if status == "PASS" else "[FAIL]"
        print(f"{status_symbol} {message}\n")
    
    def summary(self):
        """Print test summary."""
        print("=" * 70)
        print("TEST SUMMARY")
        print("=" * 70)
        
        passed = sum(1 for status, _ in self.test_results if status == "PASS")
        failed = sum(1 for status, _ in self.test_results if status == "FAIL")
        total = len(self.test_results)
        
        print(f"\nTotal Tests:  {total}")
        print(f"Passed:       {passed}")
        print(f"Failed:       {failed}")
        print(f"Success Rate: {100*passed/total:.1f}%\n")
        
        if failed > 0:
            print("Failed Tests:")
            for status, message in self.test_results:
                if status == "FAIL":
                    print(f"  [FAIL] {message}")
            print()
        
        return failed == 0


def main():
    """Run all tests."""
    runner = TestRunner()
    runner.setup()
    
    # Run tests
    runner.test_cube_initialization()
    runner.test_search_token_generation()
    runner.test_single_keyword_search()
    runner.test_conjunctive_search()
    runner.test_dynamic_insertion()
    runner.test_dynamic_deletion()
    runner.test_cube_statistics()
    runner.test_keyword_mappings()
    runner.test_performance_logging()
    runner.test_review1_encryption_still_works()
    
    # Print summary
    success = runner.summary()
    
    return 0 if success else 1


if __name__ == '__main__':
    exit_code = main()
    sys.exit(exit_code)
