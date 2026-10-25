import os
import tempfile
import unittest
from unittest.mock import patch

import app as application_module
from app import app, create_tables, get_db


class PhaseTwoRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_config = {
            key: app.config[key]
            for key in ("DATABASE", "UPLOAD_FOLDER", "ENCRYPTED_FOLDER", "TESTING")
        }
        self.original_instance_folder = application_module.INSTANCE_FOLDER
        self.original_search_key = application_module.SEARCH_KEY
        self.original_cube_index = application_module.cube_index
        self.original_tracker = application_module.performance_tracker
        self.original_secret = app.secret_key
        root = self.temp_dir.name
        app.config.update(
            DATABASE=os.path.join(root, "test.db"),
            UPLOAD_FOLDER=os.path.join(root, "uploads"),
            ENCRYPTED_FOLDER=os.path.join(root, "encrypted"),
            TESTING=True,
        )
        application_module.INSTANCE_FOLDER = os.path.join(root, "instance")
        app.secret_key = b"phase-two-test-session-secret"
        os.makedirs(app.config["UPLOAD_FOLDER"])
        os.makedirs(app.config["ENCRYPTED_FOLDER"])
        with app.app_context():
            create_tables()
            self.owner = self.add_user("owner")
            self.other_owner = self.add_user("other")
        self.client = app.test_client()

    def tearDown(self):
        app.config.update(self.original_config)
        app.secret_key = self.original_secret
        application_module.INSTANCE_FOLDER = self.original_instance_folder
        application_module.SEARCH_KEY = self.original_search_key
        application_module.cube_index = self.original_cube_index
        application_module.performance_tracker = self.original_tracker
        self.temp_dir.cleanup()

    def add_user(self, username, role="student"):
        db = get_db()
        cursor = db.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, "test-hash", role),
        )
        db.commit()
        return cursor.lastrowid

    def add_document(self, owner, filename, keywords):
        db = get_db()
        cursor = db.execute(
            """
            INSERT INTO documents
                (filename, owner, upload_date, encrypted_path, aes_key)
            VALUES (?, ?, ?, ?, ?)
            """,
            (filename, owner, "2026-10-26", f"{filename}.enc", "document-key"),
        )
        document_id = cursor.lastrowid
        normalized = list(dict.fromkeys(word.lower() for word in keywords))
        db.executemany(
            "INSERT INTO keywords (document_id, keyword) VALUES (?, ?)",
            [(document_id, word) for word in normalized],
        )
        application_module.cube_index.add_document_index(
            document_id, normalized, "2026-10-26", commit=False
        )
        application_module._refresh_index_integrity(db)
        db.commit()
        return document_id

    def get_state(self):
        return get_db().execute(
            "SELECT * FROM cube_config WHERE id = 1"
        ).fetchone()

    def test_initial_key_version_is_one(self):
        with app.app_context():
            self.assertEqual(self.get_state()["key_version"], 1)
            self.assertEqual(self.get_state()["key_status"], "ACTIVE")

    def test_compromise_detection_recovers_tampered_index(self):
        with app.app_context():
            document_id = self.add_document(self.owner, "record.txt", ["diabetes"])
            get_db().execute(
                "UPDATE cube_hki SET keyword_token = ?",
                ("0" * 64,),
            )
            get_db().commit()

            detected = application_module.ensure_search_index_trustworthy()

            self.assertTrue(detected)
            self.assertEqual(self.get_state()["key_version"], 2)
            self.assertEqual(
                application_module.cube_index.search_single_keyword("diabetes"),
                [document_id],
            )
            self.assertEqual(self.get_state()["key_status"], "ACTIVE")

    def test_inconsistent_key_version_metadata_triggers_recovery(self):
        with app.app_context():
            self.add_document(self.owner, "record.txt", ["diabetes"])
            get_db().execute(
                "UPDATE cube_config SET key_version = 77 WHERE id = 1"
            )
            get_db().commit()

            self.assertTrue(application_module.ensure_search_index_trustworthy())
            self.assertEqual(self.get_state()["key_version"], 78)
            self.assertEqual(self.get_state()["key_status"], "ACTIVE")
            event = get_db().execute(
                """
                SELECT status FROM key_lifecycle_events
                WHERE event_type = 'COMPROMISE_DETECTED'
                ORDER BY id DESC LIMIT 1
                """
            ).fetchone()
            self.assertEqual(event["status"], "DETECTED")

    def test_key_rotation_uses_new_key_and_preserves_document_key(self):
        with app.app_context():
            self.add_document(self.owner, "record.txt", ["diabetes"])
            old_search_key = application_module.SEARCH_KEY
            old_document_key = get_db().execute(
                "SELECT aes_key FROM documents"
            ).fetchone()["aes_key"]

            version = application_module.rotate_search_key()

            self.assertEqual(version, 2)
            self.assertNotEqual(application_module.SEARCH_KEY, old_search_key)
            self.assertEqual(
                get_db().execute("SELECT aes_key FROM documents").fetchone()["aes_key"],
                old_document_key,
            )

    def test_key_version_increments_on_each_rotation(self):
        with app.app_context():
            self.assertEqual(application_module.rotate_search_key(), 2)
            self.assertEqual(application_module.rotate_search_key(), 3)

    def test_reconstruction_rebuilds_all_four_cube_structures(self):
        with app.app_context():
            self.add_document(self.owner, "record.txt", ["diabetes", "renal"])
            application_module.rotate_search_key()
            db = get_db()
            for table in ("cube_lcic", "cube_hki", "cube_vkic", "cube_dic"):
                self.assertGreater(
                    db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0], 0
                )
                self.assertEqual(
                    db.execute(
                        f"SELECT COUNT(*) FROM {table} WHERE key_version != 2"
                    ).fetchone()[0],
                    0,
                )

    def test_single_keyword_search_is_correct_after_reconstruction(self):
        with app.app_context():
            expected = self.add_document(self.owner, "record.txt", ["diabetes"])
            self.add_document(self.other_owner, "other.txt", ["renal"])
            application_module.rotate_search_key()
            self.assertEqual(
                set(application_module.cube_index.search_single_keyword("diabetes")),
                {expected},
            )

    def test_and_search_is_correct_after_reconstruction(self):
        with app.app_context():
            expected = self.add_document(
                self.owner, "record.txt", ["diabetes", "renal"]
            )
            self.add_document(self.owner, "other.txt", ["diabetes"])
            application_module.rotate_search_key()
            self.assertEqual(
                application_module.cube_index.search_conjunctive(
                    ["diabetes", "renal"]
                ),
                [expected],
            )

    def test_deleted_document_is_not_returned_after_reconstruction(self):
        with app.app_context():
            deleted_id = self.add_document(self.owner, "deleted.txt", ["diabetes"])
            remaining_id = self.add_document(self.owner, "remaining.txt", ["diabetes"])
            db = get_db()
            application_module.cube_index.remove_document_index(
                deleted_id, "2026-10-27", commit=False
            )
            db.execute("DELETE FROM keywords WHERE document_id = ?", (deleted_id,))
            db.execute("DELETE FROM documents WHERE id = ?", (deleted_id,))
            application_module._refresh_index_integrity(db)
            db.commit()

            application_module.rotate_search_key()

            self.assertEqual(
                application_module.cube_index.search_single_keyword("diabetes"),
                [remaining_id],
            )

    def test_user_isolation_after_reconstruction_and_document_access(self):
        with app.app_context():
            own_id = self.add_document(self.owner, "own.txt", ["diabetes"])
            other_id = self.add_document(
                self.other_owner, "private.txt", ["diabetes"]
            )
            application_module.rotate_search_key()
        with self.client.session_transaction() as browser_session:
            browser_session.update(
                user_id=self.owner, username="owner", role="student"
            )

        response = self.client.post("/api/search", json={"query": "diabetes"})
        self.assertEqual(response.get_json()["matched_document_ids"], [own_id])
        self.assertNotIn(other_id, response.get_json()["matched_document_ids"])
        self.assertEqual(self.client.get(f"/documents/{other_id}").status_code, 302)

    def test_recovery_after_simulated_corruption_is_idempotent(self):
        with app.app_context():
            document_id = self.add_document(self.owner, "record.txt", ["diabetes"])
            get_db().execute("DELETE FROM cube_dic")
            get_db().commit()

            self.assertTrue(application_module.ensure_search_index_trustworthy())
            self.assertEqual(self.get_state()["key_version"], 2)
            entry_count = get_db().execute(
                "SELECT COUNT(*) FROM cube_dic"
            ).fetchone()[0]
            self.assertFalse(application_module.ensure_search_index_trustworthy())
            self.assertEqual(self.get_state()["key_version"], 2)
            self.assertEqual(
                get_db().execute("SELECT COUNT(*) FROM cube_dic").fetchone()[0],
                entry_count,
            )
            self.assertEqual(
                application_module.cube_index.search_single_keyword("diabetes"),
                [document_id],
            )

    def test_repeated_recovery_does_not_duplicate_index_entries(self):
        with app.app_context():
            self.add_document(self.owner, "record.txt", ["diabetes", "renal"])
            get_db().execute("UPDATE cube_hki SET key_version = 55")
            get_db().commit()
            application_module.ensure_search_index_trustworthy()

            counts = {
                table: get_db().execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in ("cube_lcic", "cube_hki", "cube_vkic", "cube_dic")
            }
            application_module.ensure_search_index_trustworthy()
            self.assertEqual(self.get_state()["key_version"], 2)
            self.assertEqual(
                counts,
                {
                    table: get_db().execute(
                        f"SELECT COUNT(*) FROM {table}"
                    ).fetchone()[0]
                    for table in counts
                },
            )

    def test_failed_reconstruction_does_not_replace_previous_index(self):
        with app.app_context():
            self.add_document(self.owner, "record.txt", ["diabetes", "renal"])
            db = get_db()
            before = {
                table: db.execute(
                    f"SELECT * FROM {table} ORDER BY id"
                ).fetchall()
                for table in ("cube_lcic", "cube_hki", "cube_vkic", "cube_dic")
            }
            old_search_key = application_module.SEARCH_KEY.hex()
            with self.assertLogs(application_module.app.logger, level="ERROR") as logs:
                with patch.object(
                    application_module,
                    "_verify_reconstructed_index",
                    side_effect=application_module.SearchIndexRecoveryError(
                        "simulated validation failure"
                    ),
                ):
                    with self.assertRaises(
                        application_module.SearchIndexRecoveryError
                    ):
                        application_module.rotate_search_key()

            self.assertEqual(self.get_state()["key_version"], 1)
            self.assertEqual(self.get_state()["key_status"], "COMPROMISED")
            self.assertNotIn(old_search_key, "\n".join(logs.output))
            for table, rows in before.items():
                self.assertEqual(
                    [tuple(row) for row in rows],
                    [
                        tuple(row)
                        for row in db.execute(
                            f"SELECT * FROM {table} ORDER BY id"
                        ).fetchall()
                    ],
                )

    def test_secret_material_is_not_exposed_in_ui_or_api(self):
        with app.app_context():
            self.add_document(self.owner, "record.txt", ["diabetes"])
            secret = application_module.SEARCH_KEY.hex().encode()
        with self.client.session_transaction() as browser_session:
            browser_session.update(user_id=self.owner, username="owner", role="admin")

        status_response = self.client.get("/admin/key-status")
        search_response = self.client.post("/api/search", json={"query": "diabetes"})
        self.assertEqual(status_response.status_code, 200)
        self.assertEqual(search_response.status_code, 200)
        self.assertNotIn(secret, status_response.data)
        self.assertNotIn(secret, search_response.data)
        self.assertNotIn(b"document-key", status_response.data)
        self.assertNotIn(b"document-key", search_response.data)


if __name__ == "__main__":
    unittest.main()
