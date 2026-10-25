import hashlib
import io
import os
import tempfile
import unittest
from unittest.mock import patch

import app as application_module
from app import (
    app,
    cleanup_legacy_plaintext_uploads,
    create_tables,
    encrypt_file,
    get_db,
    hash_password,
)


class PhaseOneSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_config = {
            key: app.config[key]
            for key in ("DATABASE", "UPLOAD_FOLDER", "ENCRYPTED_FOLDER", "TESTING")
        }
        self.original_secret = app.secret_key
        self.original_cube_index = application_module.cube_index
        self.original_performance_tracker = application_module.performance_tracker
        app.config.update(
            DATABASE=os.path.join(self.temp_dir.name, "test.db"),
            UPLOAD_FOLDER=os.path.join(self.temp_dir.name, "uploads"),
            ENCRYPTED_FOLDER=os.path.join(self.temp_dir.name, "encrypted"),
            TESTING=True,
        )
        app.secret_key = b"phase-one-test-session-secret"
        os.makedirs(app.config["UPLOAD_FOLDER"])
        os.makedirs(app.config["ENCRYPTED_FOLDER"])
        with app.app_context():
            create_tables()
        self.client = app.test_client()

    def tearDown(self):
        app.config.update(self.original_config)
        app.secret_key = self.original_secret
        application_module.cube_index = self.original_cube_index
        application_module.performance_tracker = self.original_performance_tracker
        self.temp_dir.cleanup()

    def add_user(self, username, role="student", password="password"):
        with app.app_context():
            db = get_db()
            cursor = db.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username, hash_password(password), role),
            )
            db.commit()
            return cursor.lastrowid

    def add_document(self, owner_id, filename, keyword, encrypted_name=None):
        with app.app_context():
            db = get_db()
            encrypted_name = encrypted_name or f"{filename}.enc"
            cursor = db.execute(
                """
                INSERT INTO documents
                    (filename, owner, upload_date, encrypted_path, aes_key)
                VALUES (?, ?, ?, ?, ?)
                """,
                (filename, owner_id, "2026-10-26", encrypted_name, "not-exposed"),
            )
            document_id = cursor.lastrowid
            db.execute(
                "INSERT INTO keywords (document_id, keyword) VALUES (?, ?)",
                (document_id, keyword),
            )
            application_module.cube_index.add_document_index(
                document_id, [keyword], "2026-10-26"
            )
            application_module._refresh_index_integrity(db)
            db.commit()
            return document_id

    def login_as(self, user_id, role="student"):
        with self.client.session_transaction() as browser_session:
            browser_session["user_id"] = user_id
            browser_session["username"] = f"user-{user_id}"
            browser_session["role"] = role

    def test_user_document_and_dashboard_isolation(self):
        owner_id = self.add_user("owner")
        other_id = self.add_user("other")
        self.add_document(owner_id, "owner-record.txt", "diabetes")
        self.add_document(other_id, "other-record.txt", "diabetes")
        self.login_as(owner_id)

        dashboard = self.client.get("/dashboard")
        results = self.client.get(
            "/search/results", query_string={"query": "diabetes"}
        )
        cube_dashboard = self.client.get("/cube-dashboard")

        self.assertIn(b"owner-record.txt", dashboard.data)
        self.assertNotIn(b"other-record.txt", dashboard.data)
        self.assertIn(b"owner-record.txt", results.data)
        self.assertNotIn(b"other-record.txt", results.data)
        self.assertIn(b"Total Documents</div>\n        <div class=\"h3 mb-0\">1", cube_dashboard.data)
        with app.app_context():
            application_module.performance_tracker.log_search(
                other_id, "private-history-query", 1, 1, 1.0
            )
        performance = self.client.get("/performance")
        self.assertNotIn(b"private-history-query", performance.data)

    def test_registration_cannot_assign_admin_role(self):
        response = self.client.post(
            "/register",
            data={"username": "new-user", "password": "password", "role": "admin"},
        )
        self.assertEqual(response.status_code, 302)
        with app.app_context():
            user = get_db().execute(
                "SELECT role, password FROM users WHERE username = ?",
                ("new-user",),
            ).fetchone()
        self.assertEqual(user["role"], "student")
        self.assertNotEqual(user["password"], hashlib.sha256(b"password").hexdigest())

    def test_user_cannot_open_another_users_document(self):
        owner_id = self.add_user("owner")
        other_id = self.add_user("other")
        document_id = self.add_document(owner_id, "private.txt", "diabetes")
        self.login_as(other_id)

        detail = self.client.get(f"/documents/{document_id}")
        decrypt = self.client.get(f"/decrypt/{document_id}")
        delete = self.client.post(f"/document/{document_id}/delete")

        self.assertEqual(detail.status_code, 302)
        self.assertEqual(decrypt.status_code, 302)
        self.assertEqual(delete.status_code, 302)
        with app.app_context():
            remaining = get_db().execute(
                "SELECT id FROM documents WHERE id = ?", (document_id,)
            ).fetchone()
        self.assertIsNotNone(remaining)

    def test_api_search_only_returns_owned_document_ids(self):
        owner_id = self.add_user("owner")
        other_id = self.add_user("other")
        owned_document = self.add_document(owner_id, "owner.txt", "diabetes")
        self.add_document(other_id, "other.txt", "diabetes")
        self.login_as(owner_id)

        response = self.client.post(
            "/api/search",
            json={"query": "diabetes"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json()["matched_document_ids"], [owned_document]
        )

    def test_api_search_rejects_missing_or_invalid_json(self):
        self.login_as(self.add_user("owner"))
        self.assertEqual(self.client.post("/api/search").status_code, 400)
        self.assertEqual(
            self.client.post(
                "/api/search",
                data='{"query":',
                content_type="application/json",
            ).status_code,
            400,
        )

    def test_password_login_and_legacy_hash_upgrade(self):
        user_id = self.add_user("hashed-user", password="correct-horse")
        response = self.client.post(
            "/login",
            data={"username": "hashed-user", "password": "correct-horse"},
        )
        self.assertEqual(response.status_code, 302)
        with app.app_context():
            upgraded = get_db().execute(
                "SELECT password FROM users WHERE id = ?", (user_id,)
            ).fetchone()["password"]
        self.assertNotEqual(
            upgraded, hashlib.sha256(b"correct-horse").hexdigest()
        )

        with app.app_context():
            db = get_db()
            cursor = db.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (
                    "legacy-user",
                    hashlib.sha256(b"legacy-password").hexdigest(),
                    "student",
                ),
            )
            legacy_id = cursor.lastrowid
            db.commit()
        legacy_login = self.client.post(
            "/login",
            data={"username": "legacy-user", "password": "legacy-password"},
        )
        self.assertEqual(legacy_login.status_code, 302)
        with app.app_context():
            upgraded_legacy = get_db().execute(
                "SELECT password FROM users WHERE id = ?", (legacy_id,)
            ).fetchone()["password"]
        self.assertNotEqual(
            upgraded_legacy, hashlib.sha256(b"legacy-password").hexdigest()
        )

    def test_encrypted_file_deletion_failure_preserves_document(self):
        owner_id = self.add_user("owner")
        document_id = self.add_document(
            owner_id, "medical.txt", "diabetes", "medical.txt.enc"
        )
        encrypted_path = os.path.join(
            app.config["ENCRYPTED_FOLDER"], "medical.txt.enc"
        )
        with open(encrypted_path, "wb") as encrypted_file:
            encrypted_file.write(b"encrypted data")
        self.login_as(owner_id)

        with patch("app.os.replace", side_effect=OSError("simulated filesystem error")):
            response = self.client.post(f"/document/{document_id}/delete")

        self.assertEqual(response.status_code, 302)
        self.assertTrue(os.path.exists(encrypted_path))
        with app.app_context():
            remaining = get_db().execute(
                "SELECT id FROM documents WHERE id = ?", (document_id,)
            ).fetchone()
            active_results = application_module.cube_index.search_single_keyword(
                "diabetes"
            )
        self.assertIsNotNone(remaining)
        self.assertIn(document_id, active_results)
        self.assertNotIn(b"Document deleted successfully", response.data)

    def test_upload_decrypt_and_successful_delete_leave_no_plaintext_stage_file(self):
        owner_id = self.add_user("owner")
        self.login_as(owner_id)
        document_bytes = b"Medical note: diabetes treatment follow-up."

        uploaded = self.client.post(
            "/upload",
            data={
                "document": (io.BytesIO(document_bytes), "record.txt"),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(uploaded.status_code, 302)
        self.assertEqual(os.listdir(app.config["UPLOAD_FOLDER"]), [])

        with app.app_context():
            document = get_db().execute(
                "SELECT id, encrypted_path FROM documents WHERE owner = ?",
                (owner_id,),
            ).fetchone()
        encrypted_path = os.path.join(
            app.config["ENCRYPTED_FOLDER"], document["encrypted_path"]
        )
        self.assertTrue(os.path.isfile(encrypted_path))

        decrypted = self.client.get(f"/decrypt/{document['id']}")
        self.assertEqual(decrypted.status_code, 200)
        self.assertEqual(decrypted.data, document_bytes)

        deleted = self.client.post(f"/document/{document['id']}/delete")
        self.assertEqual(deleted.status_code, 302)
        self.assertFalse(os.path.exists(encrypted_path))
        with app.app_context():
            remaining = get_db().execute(
                "SELECT id FROM documents WHERE id = ?", (document["id"],)
            ).fetchone()
        self.assertIsNone(remaining)

    def test_legacy_plaintext_copy_is_removed_only_after_ciphertext_verification(self):
        owner_id = self.add_user("owner")
        plaintext = b"verified legacy staging document"
        staged_path = os.path.join(
            app.config["UPLOAD_FOLDER"], f"{'a' * 32}_legacy.txt"
        )
        with open(staged_path, "wb") as staged_file:
            staged_file.write(plaintext)
        unmatched_path = os.path.join(
            app.config["UPLOAD_FOLDER"], f"{'b' * 32}_unmatched.txt"
        )
        with open(unmatched_path, "wb") as unmatched_file:
            unmatched_file.write(b"not backed by an encrypted document")
        encrypted_name = "legacy.txt.enc"
        encrypted_path = os.path.join(
            app.config["ENCRYPTED_FOLDER"], encrypted_name
        )
        encryption_source = os.path.join(self.temp_dir.name, "source.txt")
        with open(encryption_source, "wb") as source_file:
            source_file.write(plaintext)
        encryption_key = encrypt_file(encryption_source, encrypted_path)
        with app.app_context():
            db = get_db()
            db.execute(
                """
                INSERT INTO documents
                    (filename, owner, upload_date, encrypted_path, aes_key)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    "legacy.txt",
                    owner_id,
                    "2026-10-26",
                    encrypted_name,
                    encryption_key,
                ),
            )
            db.commit()
        old_time = os.path.getmtime(staged_path) - (48 * 60 * 60)
        os.utime(staged_path, (old_time, old_time))
        os.utime(unmatched_path, (old_time, old_time))

        with app.app_context():
            cleanup_legacy_plaintext_uploads()

        self.assertFalse(os.path.exists(staged_path))
        self.assertTrue(os.path.exists(unmatched_path))


if __name__ == "__main__":
    unittest.main()
