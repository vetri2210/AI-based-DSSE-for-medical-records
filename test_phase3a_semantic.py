import inspect
import os
import tempfile
import unittest
from unittest.mock import patch

import app as application_module
import semantic_search
from app import app, create_tables, get_db
from cube import CUBEIndex


class PhaseThreeASemanticSearchTests(unittest.TestCase):
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
        app.secret_key = b"phase-three-a-test-session-secret"
        os.makedirs(app.config["UPLOAD_FOLDER"])
        os.makedirs(app.config["ENCRYPTED_FOLDER"])
        with app.app_context():
            create_tables()
            self.owner_id = self.add_user("semantic-owner")
            self.other_id = self.add_user("semantic-other")
        self.client = app.test_client()
        with self.client.session_transaction() as browser_session:
            browser_session.update(
                user_id=self.owner_id,
                username="semantic-owner",
                role="student",
            )

    def tearDown(self):
        app.config.update(self.original_config)
        app.secret_key = self.original_secret
        application_module.INSTANCE_FOLDER = self.original_instance_folder
        application_module.SEARCH_KEY = self.original_search_key
        application_module.cube_index = self.original_cube_index
        application_module.performance_tracker = self.original_tracker
        self.temp_dir.cleanup()

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

    def test_expansion_returns_normalized_unique_terms(self):
        self.assertEqual(
            semantic_search.expand_query("High BLOOD sugar treatment"),
            [
                "high",
                "blood",
                "sugar",
                "treatment",
                "diabetes",
                "glucose",
                "hyperglycemia",
                "insulin",
                "glycemia",
            ],
        )

    def test_original_terms_are_preserved(self):
        query = "high blood sugar treatment"
        expanded = semantic_search.expand_query(query)
        for original in semantic_search.normalize_query_terms(query):
            self.assertIn(original, expanded)

    def test_related_medical_terms_are_added(self):
        expanded = semantic_search.expand_query("high blood sugar treatment")
        self.assertTrue(
            {"diabetes", "glucose", "hyperglycemia", "insulin"}.issubset(expanded)
        )

    def test_exact_search_without_flag_keeps_current_behavior(self):
        exact_doc = self.add_document(self.owner_id, "diabetes.txt", "diabetes")
        expanded_only_doc = self.add_document(
            self.owner_id, "glucose.txt", "glucose"
        )

        response = self.client.post("/api/search", json={"query": "diabetes"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json()["matched_document_ids"], [exact_doc]
        )
        self.assertNotIn(
            expanded_only_doc, response.get_json()["matched_document_ids"]
        )
        self.assertFalse(response.get_json()["semantic_used"])

    def test_semantic_search_returns_related_term_match(self):
        diabetes_doc = self.add_document(
            self.owner_id, "diabetes.txt", "diabetes"
        )
        response = self.client.post(
            "/api/search",
            json={"query": "high blood sugar treatment", "semantic": True},
        )

        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertIn(diabetes_doc, body["matched_document_ids"])
        self.assertTrue(body["semantic_used"])
        self.assertEqual(body["search_mode"], "semantic")
        self.assertIn("diabetes", body["expanded_terms"])

    def test_explicit_and_query_remains_conjunctive_with_semantics_enabled(self):
        matching_doc = self.add_document(
            self.owner_id, "both.txt", "diabetes", "insulin"
        )
        self.add_document(self.owner_id, "only-diabetes.txt", "diabetes")

        response = self.client.post(
            "/api/search",
            json={"query": "diabetes AND insulin", "semantic": True},
        )
        body = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(body["matched_document_ids"], [matching_doc])
        self.assertEqual(body["search_mode"], "conjunctive")
        self.assertFalse(body["semantic_used"])

    def test_semantic_search_preserves_user_isolation(self):
        own_doc = self.add_document(self.owner_id, "own.txt", "diabetes")
        other_doc = self.add_document(self.other_id, "other.txt", "glucose")

        response = self.client.post(
            "/api/search",
            json={"query": "high blood sugar", "semantic": True},
        )

        self.assertEqual(response.status_code, 200)
        matched_ids = response.get_json()["matched_document_ids"]
        self.assertIn(own_doc, matched_ids)
        self.assertNotIn(other_doc, matched_ids)

    def test_search_tokens_are_generated_only_after_expansion(self):
        self.add_document(self.owner_id, "diabetes.txt", "diabetes")
        events = []
        original_expand = application_module.expand_query
        original_token = CUBEIndex.generate_search_token

        def expand_and_record(query):
            events.append(("expand", query))
            return original_expand(query)

        def generate_and_record(term, counter=None):
            events.append(("token", term))
            return original_token(application_module.cube_index, term, counter)

        with (
            patch.object(
                application_module, "expand_query", side_effect=expand_and_record
            ),
            patch.object(
                CUBEIndex,
                "generate_search_token",
                side_effect=generate_and_record,
            ),
        ):
            response = self.client.post(
                "/api/search",
                json={"query": "high blood sugar", "semantic": True},
            )

        self.assertEqual(response.status_code, 200)
        expand_position = next(i for i, event in enumerate(events) if event[0] == "expand")
        first_token_position = next(i for i, event in enumerate(events) if event[0] == "token")
        self.assertLess(expand_position, first_token_position)
        self.assertIn(
            ("token", "diabetes"),
            events,
        )

    def test_semantic_module_has_no_secret_inputs_or_application_dependencies(self):
        signature = inspect.signature(semantic_search.expand_query)
        self.assertEqual(list(signature.parameters), ["query"])
        self.assertFalse(hasattr(semantic_search, "SEARCH_KEY"))
        self.assertFalse(hasattr(semantic_search, "cube_index"))
        self.assertFalse(hasattr(semantic_search, "get_db"))

    def test_expansion_failure_falls_back_to_exact_search(self):
        exact_doc = self.add_document(
            self.owner_id, "exact.txt", "high blood sugar treatment"
        )
        with self.assertLogs(application_module.app.logger, level="WARNING") as logs:
            with patch.object(
                application_module,
                "expand_query",
                side_effect=RuntimeError("private model details"),
            ):
                response = self.client.post(
                    "/api/search",
                    json={"query": "high blood sugar treatment", "semantic": True},
                )

        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(body["matched_document_ids"], [exact_doc])
        self.assertFalse(body["semantic_used"])
        self.assertEqual(body["search_mode"], "exact")
        self.assertNotIn(b"private model details", response.data)
        self.assertNotIn("private model details", "\n".join(logs.output))

    def test_semantic_flag_must_be_boolean(self):
        response = self.client.post(
            "/api/search",
            json={"query": "diabetes", "semantic": "true"},
        )
        self.assertEqual(response.status_code, 400)

    def test_search_form_exposes_semantic_toggle(self):
        response = self.client.get("/search")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Enable Semantic Search", response.data)

    def test_web_form_opt_in_shows_semantic_expansion(self):
        self.add_document(self.owner_id, "diabetes.txt", "diabetes")
        response = self.client.post(
            "/search",
            data={
                "query": "high blood sugar treatment",
                "semantic_search": "true",
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertIn("semantic=true", response.location)
        results = self.client.get(response.location)
        self.assertEqual(results.status_code, 200)
        self.assertIn(b"Semantic expansion", results.data)
        self.assertIn(b"diabetes", results.data)


if __name__ == "__main__":
    unittest.main()
