import os
import tempfile
import unittest

import app as application_module
import verifiable_search
from app import app, create_tables, get_db


class PhaseThreeBVerifiableSearchTests(unittest.TestCase):
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
        app.secret_key = b"phase-three-b-test-session-secret"
        os.makedirs(app.config["UPLOAD_FOLDER"])
        os.makedirs(app.config["ENCRYPTED_FOLDER"])
        with app.app_context():
            create_tables()
            self.owner_id = self.add_user("proof-owner")
            self.other_id = self.add_user("proof-other")
        self.client = app.test_client()
        self.login(self.owner_id, "student")

    def tearDown(self):
        app.config.update(self.original_config)
        app.secret_key = self.original_secret
        application_module.INSTANCE_FOLDER = self.original_instance_folder
        application_module.SEARCH_KEY = self.original_search_key
        application_module.cube_index = self.original_cube_index
        application_module.performance_tracker = self.original_tracker
        self.temp_dir.cleanup()

    def login(self, user_id, role):
        with self.client.session_transaction() as browser_session:
            browser_session.update(user_id=user_id, username="proof-user", role=role)

    def add_user(self, username):
        cursor = get_db().execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, "test-hash", "student"),
        )
        get_db().commit()
        return cursor.lastrowid

    def add_document(self, owner_id, filename, *keywords):
        with app.app_context():
            db = get_db()
            cursor = db.execute(
                """
                INSERT INTO documents
                    (filename, owner, upload_date, encrypted_path, aes_key)
                VALUES (?, ?, ?, ?, ?)
                """,
                (filename, owner_id, "2026-10-26", f"{filename}.enc", "document-key"),
            )
            document_id = cursor.lastrowid
            normalized = list(dict.fromkeys(word.lower() for word in keywords))
            db.executemany(
                "INSERT INTO keywords (document_id, keyword) VALUES (?, ?)",
                [(document_id, keyword) for keyword in normalized],
            )
            application_module.cube_index.add_document_index(
                document_id, normalized, "2026-10-26", commit=False
            )
            application_module._refresh_index_integrity(db)
            db.commit()
            return document_id

    def search_with_proof(self, query, **options):
        response = self.client.post(
            "/api/search", json={"query": query, "verify": True, **options}
        )
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        return response.get_json()

    def verify(self, bundle, proof, expected_user=None, expected_version=1):
        return verifiable_search.verify_result_proof(
            bundle,
            proof,
            bundle["public_key"],
            expected_user,
            expected_version,
        )

    def test_valid_result_and_valid_proof_verify(self):
        document_id = self.add_document(self.owner_id, "record.txt", "diabetes")
        body = self.search_with_proof("diabetes")
        proof = body["verification"]["proofs"][0]

        self.assertEqual(body["matched_document_ids"], [document_id])
        self.assertTrue(self.verify(body["verification"], proof, self.owner_id))

    def test_modified_document_id_fails_verification(self):
        self.add_document(self.owner_id, "record.txt", "diabetes")
        body = self.search_with_proof("diabetes")
        proof = body["verification"]["proofs"][0]
        proof["leaf"][2] += 100

        self.assertFalse(self.verify(body["verification"], proof, self.owner_id))

    def test_modified_keyword_fails_verification(self):
        self.add_document(self.owner_id, "record.txt", "diabetes")
        body = self.search_with_proof("diabetes")
        proof = body["verification"]["proofs"][0]
        proof["leaf"][1] = "hypertension"

        self.assertFalse(self.verify(body["verification"], proof, self.owner_id))

    def test_modified_proof_node_fails_verification(self):
        self.add_document(self.owner_id, "record.txt", "diabetes")
        self.add_document(self.owner_id, "other.txt", "glucose")
        body = self.search_with_proof("diabetes")
        proof = body["verification"]["proofs"][0]
        proof["siblings"][0]["hash"] = "00" * 32

        self.assertFalse(self.verify(body["verification"], proof, self.owner_id))

    def test_wrong_root_fails_verification(self):
        self.add_document(self.owner_id, "record.txt", "diabetes")
        body = self.search_with_proof("diabetes")
        manifest = dict(body["verification"])
        manifest["root"] = "00" * 32

        self.assertFalse(
            self.verify(manifest, manifest["proofs"][0], self.owner_id)
        )

    def test_wrong_key_version_fails_verification(self):
        self.add_document(self.owner_id, "record.txt", "diabetes")
        body = self.search_with_proof("diabetes")

        self.assertFalse(
            self.verify(body["verification"], body["verification"]["proofs"][0],
                        self.owner_id, expected_version=2)
        )

    def test_cross_user_result_fails_verification(self):
        other_document = self.add_document(
            self.other_id, "private.txt", "diabetes"
        )
        self.login(self.owner_id, "admin")
        body = self.search_with_proof("diabetes")
        other_proof = next(
            proof for proof in body["verification"]["proofs"]
            if proof["result_id"] == other_document
        )

        self.assertFalse(
            self.verify(
                body["verification"], other_proof, expected_user=self.owner_id
            )
        )

    def test_deleted_document_stale_proof_fails_against_current_tree(self):
        deleted_id = self.add_document(self.owner_id, "deleted.txt", "diabetes")
        self.add_document(self.owner_id, "kept.txt", "diabetes")
        old_body = self.search_with_proof("diabetes")
        old_proof = next(
            proof for proof in old_body["verification"]["proofs"]
            if proof["result_id"] == deleted_id
        )
        with app.app_context():
            db = get_db()
            application_module.cube_index.remove_document_index(
                deleted_id, "2026-10-27", commit=False
            )
            db.execute("DELETE FROM keywords WHERE document_id = ?", (deleted_id,))
            db.execute("DELETE FROM documents WHERE id = ?", (deleted_id,))
            application_module._refresh_index_integrity(db)
            db.commit()
        current = self.search_with_proof("diabetes")

        self.assertNotIn(deleted_id, current["matched_document_ids"])
        self.assertFalse(
            self.verify(current["verification"], old_proof, self.owner_id)
        )

    def test_key_rotation_invalidates_old_proof_and_new_proof_verifies(self):
        self.add_document(self.owner_id, "record.txt", "diabetes")
        old_body = self.search_with_proof("diabetes")
        old_proof = old_body["verification"]["proofs"][0]
        with app.app_context():
            application_module.rotate_search_key()
        new_body = self.search_with_proof("diabetes")

        self.assertFalse(
            self.verify(
                old_body["verification"], old_proof,
                self.owner_id, expected_version=2,
            )
        )
        self.assertTrue(
            self.verify(
                new_body["verification"], new_body["verification"]["proofs"][0],
                self.owner_id, expected_version=2,
            )
        )
        self.assertNotEqual(
            old_body["verification"]["root"], new_body["verification"]["root"]
        )

    def test_reconstructed_cube_generates_valid_proof(self):
        self.add_document(self.owner_id, "record.txt", "diabetes")
        with app.app_context():
            application_module.rotate_search_key()
        body = self.search_with_proof("diabetes")
        proof = body["verification"]["proofs"][0]

        self.assertTrue(self.verify(body["verification"], proof, self.owner_id, 2))

    def test_exact_search_and_verification_preserve_results(self):
        exact_id = self.add_document(self.owner_id, "diabetes.txt", "diabetes")
        self.add_document(self.owner_id, "glucose.txt", "glucose")
        body = self.search_with_proof("diabetes")

        self.assertEqual(body["matched_document_ids"], [exact_id])
        self.assertEqual(body["search_mode"], "exact")

    def test_and_search_remains_conjunctive_and_provable(self):
        matching_id = self.add_document(
            self.owner_id, "both.txt", "diabetes", "insulin"
        )
        self.add_document(self.owner_id, "one.txt", "diabetes")
        body = self.search_with_proof("diabetes AND insulin")

        self.assertEqual(body["matched_document_ids"], [matching_id])
        self.assertEqual(
            {proof["leaf"][1] for proof in body["verification"]["proofs"]},
            {"diabetes", "insulin"},
        )

    def test_semantic_search_remains_functional_with_verification(self):
        related_id = self.add_document(
            self.owner_id, "glucose.txt", "diabetes"
        )
        body = self.search_with_proof(
            "high blood sugar", semantic=True
        )

        self.assertIn(related_id, body["matched_document_ids"])
        self.assertTrue(body["semantic_used"])
        self.assertTrue(
            self.verify(
                body["verification"], body["verification"]["proofs"][0],
                self.owner_id,
            )
        )

    def test_verification_response_contains_no_secret_material(self):
        self.add_document(self.owner_id, "record.txt", "diabetes")
        body = self.search_with_proof("diabetes")
        response_text = str(body)
        page = self.client.get("/search/results?query=diabetes&verify=true")

        self.assertNotIn(application_module.SEARCH_KEY.hex(), response_text)
        self.assertNotIn("document-key", response_text)
        self.assertNotIn("aes_key", response_text)
        self.assertNotIn("search_token", response_text)
        self.assertIn(body["verification"]["public_key"], response_text)
        self.assertNotIn(application_module.SEARCH_KEY.hex().encode(), page.data)
        self.assertNotIn(b"document-key", page.data)

    def test_duplicate_keywords_do_not_duplicate_results_or_merkle_leaves(self):
        document_id = self.add_document(self.owner_id, "record.txt", "diabetes")
        with app.app_context():
            db = get_db()
            db.execute(
                "INSERT INTO keywords (document_id, keyword) VALUES (?, ?)",
                (document_id, "diabetes"),
            )
            application_module._refresh_index_integrity(db)
            db.commit()
        body = self.search_with_proof("diabetes")

        self.assertEqual(body["matched_document_ids"], [document_id])
        self.assertEqual(body["verification"]["leaf_count"], 1)
        self.assertEqual(len(body["verification"]["proofs"]), 1)

    def test_malformed_proof_data_fails_closed(self):
        self.add_document(self.owner_id, "record.txt", "diabetes")
        body = self.search_with_proof("diabetes")
        proof = body["verification"]["proofs"][0]
        proof["siblings"] = "not-a-proof"

        self.assertFalse(self.verify(body["verification"], proof, self.owner_id))

    def test_api_verify_flag_validation_and_default_behavior(self):
        self.add_document(self.owner_id, "record.txt", "diabetes")
        default_response = self.client.post(
            "/api/search", json={"query": "diabetes"}
        )
        disabled_response = self.client.post(
            "/api/search", json={"query": "diabetes", "verify": False}
        )
        invalid_response = self.client.post(
            "/api/search", json={"query": "diabetes", "verify": "true"}
        )

        self.assertEqual(default_response.status_code, 200)
        self.assertNotIn("verification", default_response.get_json())
        self.assertEqual(disabled_response.status_code, 200)
        self.assertNotIn("verification", disabled_response.get_json())
        self.assertEqual(invalid_response.status_code, 400)

    def test_search_ui_includes_verification_option_and_client_verifier(self):
        self.add_document(self.owner_id, "record.txt", "diabetes")
        response = self.client.get(
            "/search/results?query=diabetes&verify=true"
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"VERIFIED", response.data)
        self.assertIn(b"Enable Result Verification", self.client.get("/search").data)
        self.assertIn(b"crypto.subtle.verify", response.data)


if __name__ == "__main__":
    unittest.main()
