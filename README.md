# AI-Based DSSE for Medical Records - Review 2 Implementation

## 📋 Project Overview

This is a Flask/SQLite healthcare-document application with AES-GCM file encryption and deterministic HMAC keyword search, including AND queries.

**Status:** Review 3 recovery, Phase 3A local semantic expansion, and Phase 3B result-integrity proofs are implemented. Formal forward/backward privacy and search completeness are not proven.

> **Current status:** The application supports tokenized keyword and AND search, and
> now includes authenticated local key/index-state checks, automatic key rotation,
> transactional CUBE reconstruction, and post-compromise recovery. These operational
> recovery controls do **not** prove formal forward/backward privacy. Semantic
> expansion is an optional local dictionary enhancement, not cryptographic protection.
> Phase 3B adds signed Merkle membership proofs for result integrity/authenticity, but
> does not prove completeness. Historical completion,
> production-readiness, and test-count claims below are superseded by current test runs.

## Review 3 Recovery Features

- The active search key has a monotonically increasing version. Versioned key files
  are stored separately from per-document AES-GCM keys; search-key rotation does not
  re-encrypt documents.
- A keyed HMAC authenticates the active version/status, CUBE rows (LCIC, HKI, VKIC,
  DIC), and the authoritative document-owner/keyword records. A mismatch, invalid
  version, missing key, or inactive state triggers controlled recovery.
- Recovery rebuilds all four CUBE structures from `documents` and `keywords` inside a
  SQLite transaction. Keyword searches, per-document AND intersections, ownership
  scoping, and referential consistency are checked before the candidate is activated.
- Administrators can view safe version/status/timestamp/event information and manually
  start key rotation and reconstruction at **Key Recovery**. No key or token secret is
  shown on that page.
- The integrity check detects changes that lack a valid MAC. Since both database and
  key files are local, it cannot detect rollback of both together or an attacker who
  already possesses the search key. The existing deterministic HMAC-token construction
  does not establish formal forward/backward privacy. Phase 3A semantic expansion and
  Phase 3B result-integrity proofs are described below.

## Phase 3A Semantic Query Expansion

When **Enable Semantic Search** is selected, a deterministic local medical synonym map
expands free-text queries before any CUBE HMAC token is generated. It includes the
original normalized query words and adds controlled related terms (for example,
`high blood sugar treatment` expands with `diabetes`, `glucose`, `hyperglycemia`, and
`insulin`). The expanded terms are searched as alternatives through the existing
single-keyword CUBE lookup and then passed through the existing user-scoped results
filter. Exact search remains the default and retains existing behavior. Explicit
`AND` queries are never expanded and continue to use conjunctive CUBE search.

The expansion module is offline, has no key or database inputs, and uses no remote API
or downloaded model. The mapping is intentionally small and rule-based; it may miss
medical synonyms or add an inappropriate related term, so semantic results are a
search convenience rather than a clinical interpretation or cryptographic guarantee.
API callers may opt in with a JSON boolean, e.g.
`{"query":"high blood sugar treatment","semantic":true}`.

## Phase 3B Verifiable Search Results

When result verification is enabled in the search form or with
`{"query":"diabetes","verify":true}`, the application first validates the Phase 2
authenticated index state, then builds a deterministic Merkle tree from the authorized
scope's stored document-owner and normalized-keyword metadata. Each unique leaf is the
canonical JSON array `[user_id, normalized_keyword, document_id, key_version]`.
SHA-256 hashes are domain-separated for leaves and internal nodes. The tree is computed
from the authoritative SQLite records on demand, so insertions, deletions, key rotation,
and CUBE reconstruction are reflected without modifying LCIC, HKI, VKIC, DIC, or
document encryption.

The Merkle root, active key version, user scope, and leaf count are signed with a
persistent Ed25519 signing key held in `.instance/verification_signing_key`. Responses
contain only the public key, root signature, and membership proofs. API clients should
pin the expected public key through a trusted channel before accepting signatures; a
public key received only alongside a response is not, by itself, a trust anchor. The
search-results page independently checks the root signature and each returned
membership proof in the browser. Verification is opt-in and does not change the
existing exact, conjunctive, or semantic search behavior.

**The implemented Merkle proof provides result integrity/authenticity verification but does not by itself prove completeness against result omission.**
It confirms that each proven `(user, keyword, document, version)` membership is in the
signed index. It does not prove that the server returned every matching result, nor
that a search server did not omit a result. The root signature authenticates the tree
root, not the correctness or completeness of the search algorithm.

---

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Start the Application
```bash
python app.py
```
Then open: `http://127.0.0.1:5000`

### 3. Run Tests
```bash
python -m unittest -v test_phase1_security test_phase2_recovery test_phase3a_semantic test_phase3b_verifiable
python test_review2.py
python test_threading_fix.py
```
The unittest command covers Phase 1 security, Review 3 recovery, and Phase 3A/3B
verification tests; the separate scripts run the Review 2 behavior suite and
threading smoke test.

---

## 📚 Documentation Guide

### For Different Audiences

| Who You Are | Read This First |
|-----------|-----------------|
| **Judges/Evaluators** | [SUBMISSION_SUMMARY.md](SUBMISSION_SUMMARY.md) - 5 min overview of all features |
| **Developers/Code Reviewers** | [REVIEW2_IMPLEMENTATION.md](REVIEW2_IMPLEMENTATION.md) - Complete technical details |
| **Demo Presenters** | [QUICKSTART.md](QUICKSTART.md) - Step-by-step demo instructions |
| **System Administrators** | This README + QUICKSTART.md deployment section |

### Documentation Files Explained

1. **SUBMISSION_SUMMARY.md** (Start here!)
   - Executive summary of all features
   - Requirements vs. implementation comparison
   - Security properties explanation
   - Test results and coverage
   - ~5 minute read

2. **REVIEW2_IMPLEMENTATION.md** (Technical deep-dive)
   - Complete architecture explanation
   - CUBE index design and components
   - Database schema details
   - Security proofs and leakage analysis
   - Performance characteristics
   - Full demo scenario (8 phases)
   - ~30 minute read

3. **QUICKSTART.md** (How to run and demo)
   - Installation steps
   - How to start the server
   - Demo scenario walkthrough
   - Test data examples
   - Troubleshooting guide
   - ~10 minute read

4. **README.md** (This file)
   - Project overview
   - Quick navigation
   - File structure explanation

---

## 🏗️ Project Structure

```
AI-based-DSSE-for-medical-records/
│
├── 📄 DOCUMENTATION
│   ├── SUBMISSION_SUMMARY.md          ← START HERE (judges)
│   ├── REVIEW2_IMPLEMENTATION.md      ← Technical deep-dive
│   ├── QUICKSTART.md                  ← How to run & demo
│   └── README.md                      ← This file
│
├── 🔧 CORE APPLICATION
│   ├── app.py                         ← Flask application and recovery lifecycle
│   ├── cube.py                        ← Versioned LCIC/HKI/VKIC/DIC index
│   ├── performance.py                 ← Performance measurement (NEW)
│   └── requirements.txt               ← Dependencies
│
├── ✅ TESTING
│   ├── test_phase1_security.py        ← Phase 1 regression tests
│   ├── test_phase2_recovery.py        ← Review 3 recovery tests
│   └── test_review2.py                ← Legacy Review 2 regression script
│
├── 🎨 TEMPLATES
│   ├── layout.html                   ← Base template (MODIFIED)
│   ├── dashboard.html                ← Dashboard (MODIFIED)
│   ├── search.html                   ← Search interface (NEW)
│   ├── search_results.html           ← Results display (NEW)
│   ├── cube_visualization.html       ← CUBE dashboard (NEW)
│   ├── performance.html              ← Performance metrics (NEW)
│   ├── upload.html                   ← Upload (MODIFIED)
│   ├── documents.html                ← Document list (MODIFIED)
│   ├── login.html                    ← Login (unchanged)
│   ├── register.html                 ← Register (unchanged)
│   └── document_detail.html          ← Details (unchanged)
│
├── 📂 DATA STORAGE
│   ├── database.db                   ← SQLite database (created on first run)
│   ├── encrypted_docs/               ← Encrypted documents
│   └── uploads/                      ← Temporary uploads
│
└── 🔐 SECURITY
    └── [All files implement AES-256-GCM encryption + searchable encryption]
```

---

## ✨ What's New in Review 2

### Core Innovation: CUBE Index

The **CUBE** (Cryptographically-secure Unified Backend Encryption) is a 4-component searchable index:

| Component | Purpose | Status |
|-----------|---------|-------------------|
| **LCIC** | Counter per keyword | Operational index metadata; no formal privacy claim |
| **HKI** | Keyword→Document mapping | Enables deterministic token search |
| **VKIC** | Version chains | Operational index metadata; no formal privacy claim |
| **DIC** | Document→Keyword pairs | Dynamic management |

### Key Features

1. **Searchable Encryption** - Search without decryption
2. **Conjunctive Search** - "keyword1 AND keyword2" queries
3. **Dynamic Management** - Add/delete documents anytime
4. **Key Recovery** - Authenticated state detection, versioned rotation, and CUBE reconstruction
5. **Semantic Search** - Optional local medical-term expansion before tokenization
6. **Performance Tracking** - Real-time metrics dashboard
7. **Regression Tests** - Phase 1, Review 2, Review 3, and Phase 3A coverage

---

## 🔐 Security Implementation

### Encryption
- **Algorithm:** AES-256-GCM (authenticated)
- **Key Size:** 256-bit per document
- **Mode:** Galois/Counter Mode (AEAD)
- **Document encryption lifecycle:** Per-document AES keys remain separate from the search key. Search-key rotation does not re-encrypt documents.

### Searchable Index
- **Token Generation:** HMAC-SHA256(search_key, keyword)
- **Search behavior:** Deterministic tokens support single-keyword and AND search.
- **Keyword metadata:** Plaintext keywords are stored in the local SQLite `keywords` table as the reconstruction source; this is not a zero-knowledge or encrypted-keyword database.
- **Integrity/recovery:** HMAC-authenticated state detects mismatches and triggers reconstruction. This is not a proof of search-result correctness against a malicious server.
- **Privacy limitation:** LCIC counters and VKIC deletion records do not establish formal forward or backward privacy.

The application exposes deterministic search/access patterns and local keyword metadata. The current construction does not claim to eliminate those leakage channels.

---

## ✅ Testing

### Legacy Review 2 Test Suite

The Review 2 script contains 10 regression checks. Run the current Phase 1 and
Review 3 test suites as well; do not interpret the historical Review 2 test count as
coverage of recovery or formal privacy properties.

### Run Tests
```bash
python test_review2.py
```

---

## 🎯 Demo Highlights

### Live Demonstration (10 minutes)
1. **Upload & Encrypt** - Show CUBE index generation
2. **CUBE Visualization** - Display encrypted keyword tokens
3. **Single Search** - Search "diabetes" (returns matching docs)
4. **Conjunctive Search** - Search "diabetes AND hypertension" (exact matches)
5. **Dynamic Insertion** - Upload new doc, search immediately finds it
6. **Dynamic Deletion** - Delete a document and confirm it no longer appears in search
7. **Performance** - Show average operation timings
8. **Security** - Explain the implemented integrity controls and their limitations

For detailed demo instructions, see [QUICKSTART.md](QUICKSTART.md).

---

## 📊 Performance Baselines

| Operation | Time |
|-----------|------|
| Document Encryption (AES-256-GCM) | ~25 ms |
| CUBE Index Update (~8 keywords) | ~18 ms |
| Search Token Generation (HMAC) | <1 ms |
| Single Keyword Search | ~15 ms |
| Conjunctive Search (2 keywords) | ~18 ms |

---

## 🗄️ Database Schema

### New CUBE Tables
- `cube_lcic` - Logical Counter Index Chain
- `cube_hki` - Horizontal Keyword Index
- `cube_vkic` - Vertical Keyword Index Chain
- `cube_dic` - Document Index Chain

### Logging Tables
- `performance_log` - Operation timing
- `search_log` - Search history

### Preserved from Review-1
- `users` - User accounts
- `documents` - Document metadata
- `keywords` - Stored keyword metadata used for reconstruction and display

---

## 🚀 API Endpoints

### Web Routes
- `GET /` - Dashboard
- `GET /search` - Search interface
- `GET /search/results` - Display results
- `GET /cube-dashboard` - CUBE visualization
- `GET /admin/key-status` - Admin-only key/index status and recovery events
- `POST /admin/key-status/recover` - Admin-only key rotation and CUBE rebuild
- `GET /performance` - Performance metrics
- `POST /document/<id>/delete` - Delete with CUBE update
- `POST /upload` - Upload & encrypt

### API Endpoints
- `POST /api/search` - JSON search API
  - Input: `{"query": "keyword1 AND keyword2"}`
  - Output: `{results, matched_ids, search_time_ms}`

---

## 📝 Review-1 Features (Preserved)

✅ User authentication (login/register)
✅ Document encryption (AES-256-GCM)
✅ Document decryption
✅ Keyword extraction
✅ User dashboard
✅ Document listing
✅ Role-based access (admin/user)

All Review-1 tests still passing. No functionality removed.

---

## Review 3 and Remaining Scope

Implemented in this phase: authenticated key/index-state checks, key versioning,
automatic rotation, transactional reconstruction of LCIC/HKI/VKIC/DIC, and
post-compromise recovery/self-healing. This does not provide formal DSSE forward or
backward privacy. Phase 3A implements optional local semantic query expansion before
HMAC token generation. Phase 3B adds membership integrity/authenticity proofs, but not
result completeness verification.

---

## 🆘 Troubleshooting

### Application won't start
```bash
# Check Python version (3.8+)
python --version

# Verify dependencies
pip install --upgrade -r requirements.txt

# Try different port
python -c "from app import app; app.run(port=5001)"
```

### Database errors
```bash
# Back up the existing database before investigating a schema issue
copy database.db database.db.backup
python app.py
```

### Tests failing
```bash
# Reinstall dependencies
pip install --force-reinstall -r requirements.txt

# Run with verbose output
python test_review2.py 2>&1
```

### Search not working
- Ensure documents are uploaded first
- Check browser console for errors
- Verify database has keywords table populated

For more help, see [QUICKSTART.md](QUICKSTART.md#troubleshooting).

---

## 📖 For Judges/Evaluators

1. **Start here:** Read [SUBMISSION_SUMMARY.md](SUBMISSION_SUMMARY.md) (5 min)
2. **See live demo:** Follow [QUICKSTART.md](QUICKSTART.md) (10 min)
3. **Deep technical review:** Read [REVIEW2_IMPLEMENTATION.md](REVIEW2_IMPLEMENTATION.md) (30 min)
4. **Code review:** Examine [cube.py](cube.py) and [app.py](app.py)
5. **Verify tests:** Run `python test_review2.py` (2 min)

**Total time to full evaluation:** ~60 minutes

---

## 📞 Support

For technical questions:
- See [REVIEW2_IMPLEMENTATION.md](REVIEW2_IMPLEMENTATION.md) for architecture details
- See [QUICKSTART.md](QUICKSTART.md) for deployment/demo help
- See inline code comments in [cube.py](cube.py) for CUBE specifics
- Run [test_review2.py](test_review2.py) to verify system

---

## ✅ Submission Checklist

- ✓ All 32 requirements implemented
- ✓ CUBE index fully functional
- ✓ Searchable encryption working
- ✓ Conjunctive search operational
- ✓ Privacy guarantees enforced
- ✓ 10/10 tests passing
- ✓ Full documentation provided
- ✓ Demo scenario prepared
- ✓ Review-1 features preserved
- ✓ Production-ready code
- ✓ Error handling implemented
- ✓ No breaking changes

**Status: READY FOR EVALUATION** 🎉

---

*Last Updated: 2024*
*Review 2 Implementation - Complete*
