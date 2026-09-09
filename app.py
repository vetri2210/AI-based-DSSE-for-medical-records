import os
import re
import sqlite3
import hashlib
import base64
import datetime
import json
import time
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
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from cube import CUBEIndex
from performance import PerformanceTracker

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
ALLOWED_EXTENSIONS = {"pdf", "docx", "txt"}
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "change_this_secret")

# Review 2: Searchable encryption key (derived from master key for DSSE)
# In production, this should be derived from a master key using a KDF
SEARCH_KEY = os.environ.get("SEARCH_KEY", "search_key_32_bytes_for_dsse").encode('utf-8')
if len(SEARCH_KEY) < 32:
    SEARCH_KEY = hashlib.sha256(SEARCH_KEY).digest()
else:
    SEARCH_KEY = SEARCH_KEY[:32]

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["ENCRYPTED_FOLDER"] = ENCRYPTED_FOLDER
app.config["DATABASE"] = DATABASE
app.secret_key = SECRET_KEY

# Global CUBE and performance tracker instances
cube_index = None
performance_tracker = None


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
    global cube_index, performance_tracker
    
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
    
    # Review 2: Initialize CUBE index and performance tracker with get_db callable
    # This ensures thread-safe database access in Flask's multi-threaded environment
    cube_index = CUBEIndex(get_db, SEARCH_KEY)
    cube_index.create_tables()
    
    performance_tracker = PerformanceTracker(get_db)
    performance_tracker.create_tables()


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


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


def login_required(view):
    def wrapped_view(**kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
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
        role = request.form.get("role", "student")

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
        if user and user["password"] == hash_password(password):
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
        cube_stats = cube_index.get_cube_stats()
    
    return render_template(
        "dashboard.html",
        documents=documents,
        cube_stats=cube_stats,
    )


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    global cube_index, performance_tracker
    
    if request.method == "POST":
        file = request.files.get("document")
        if not file or file.filename == "":
            flash("Please select a file to upload.", "warning")
            return redirect(request.url)

        if not allowed_file(file.filename):
            flash("Only PDF, DOCX, and TXT files are allowed.", "danger")
            return redirect(request.url)

        filename = secure_filename(file.filename)
        unique_name = f"{uuid4().hex}_{filename}"
        upload_path = os.path.join(app.config["UPLOAD_FOLDER"], unique_name)
        file.save(upload_path)

        extracted_text = extract_text(upload_path)
        keywords = extract_keywords(extracted_text)
        
        # Review 2: Measure encryption time
        enc_start = time.time()
        encrypted_name = f"{uuid4().hex}_{filename}.enc"
        encrypted_path = os.path.join(app.config["ENCRYPTED_FOLDER"], encrypted_name)
        aes_key = encrypt_file(upload_path, encrypted_path)
        enc_duration_ms = (time.time() - enc_start) * 1000
        
        if performance_tracker:
            performance_tracker.log_operation('encryption', enc_duration_ms, filename)

        db = get_db()
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
        db.commit()
        
        # Review 2: Build CUBE index for searchable encryption
        if cube_index:
            cube_start = time.time()
            lcic, hki, vkic, dic = cube_index.add_document_index(
                document_id, 
                keywords, 
                datetime.datetime.utcnow().isoformat()
            )
            cube_duration_ms = (time.time() - cube_start) * 1000
            
            if performance_tracker:
                performance_tracker.log_operation(
                    'cube_index_update', 
                    cube_duration_ms, 
                    f"doc={document_id},keywords={len(keywords)}"
                )
            
            flash(
                f"Document uploaded and encrypted successfully. "
                f"CUBE index updated: {len(keywords)} keywords indexed.",
                "success"
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

    encrypted_path = os.path.join(app.config["ENCRYPTED_FOLDER"], document["encrypted_path"])
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
        document=document,
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
        
        # Redirect to results page
        return redirect(url_for("search_results", query=query))
    
    return render_template("search.html", query="")


@app.route("/search/results")
@login_required
def search_results():
    """Display search results."""
    global cube_index, performance_tracker
    
    query = request.args.get("query", "").strip()
    if not query:
        return redirect(url_for("search"))
    
    # Parse keywords from query
    keywords = [kw.strip().lower() for kw in re.split(r'\s+AND\s+|\s+and\s+', query)]
    keywords = [kw for kw in keywords if kw]
    
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
    try:
        matched_doc_ids = cube_index.search_conjunctive(keywords)
    except Exception as e:
        flash(f"Search error: {str(e)}", "danger")
        matched_doc_ids = []
    
    search_duration_ms = (time.time() - search_start) * 1000
    
    # Log search if performance tracker available
    if performance_tracker:
        performance_tracker.log_search(
            session["user_id"],
            query,
            len(keywords),
            len(matched_doc_ids),
            search_duration_ms,
            'conjunctive' if len(keywords) > 1 else 'single'
        )
    
    # Fetch matched documents (respect access control)
    db = get_db()
    user_id = session["user_id"]
    role = session.get("role")
    
    results = []
    for doc_id in matched_doc_ids:
        doc = db.execute(
            "SELECT * FROM documents WHERE id = ?",
            (doc_id,)
        ).fetchone()
        
        if doc and (doc["owner"] == user_id or role == "admin"):
            # Get matched keywords from CUBE
            matched_keywords = []
            for kw in keywords:
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
    
    return render_template(
        "search_results.html",
        query=query,
        keywords=keywords,
        results=results,
        result_count=len(results),
        search_time_ms=round(search_duration_ms, 2),
        search_type='conjunctive' if len(keywords) > 1 else 'single'
    )


@app.route("/api/search", methods=["POST"])
@login_required
def api_search():
    """API endpoint for search requests."""
    global cube_index, performance_tracker
    
    data = request.get_json()
    query = data.get("query", "").strip()
    
    if not query or not cube_index:
        return jsonify({'error': 'Invalid query or search unavailable'}), 400
    
    # Parse keywords
    keywords = [kw.strip().lower() for kw in re.split(r'\s+AND\s+|\s+and\s+', query)]
    keywords = [kw for kw in keywords if kw]
    
    # Perform search
    search_start = time.time()
    try:
        matched_doc_ids = cube_index.search_conjunctive(keywords)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
    search_duration_ms = (time.time() - search_start) * 1000
    
    # Log search
    if performance_tracker:
        performance_tracker.log_search(
            session["user_id"],
            query,
            len(keywords),
            len(matched_doc_ids),
            search_duration_ms,
            'conjunctive' if len(keywords) > 1 else 'single'
        )
    
    return jsonify({
        'query': query,
        'keywords': keywords,
        'matched_document_ids': matched_doc_ids,
        'result_count': len(matched_doc_ids),
        'search_time_ms': round(search_duration_ms, 2)
    })


@app.route("/cube-dashboard")
@login_required
def cube_dashboard():
    """Visualize CUBE index structure and statistics."""
    global cube_index
    
    if not cube_index:
        cube_stats = {}
        keyword_mappings = []
    else:
        cube_stats = cube_index.get_cube_stats()
        keyword_mappings = cube_index.get_keyword_mappings(limit=50)
    
    return render_template(
        "cube_visualization.html",
        cube_stats=cube_stats,
        keyword_mappings=keyword_mappings
    )


@app.route("/performance")
@login_required
def performance():
    """Performance metrics dashboard."""
    global performance_tracker
    
    perf_summary = {}
    recent_searches = []
    
    if performance_tracker:
        perf_summary = performance_tracker.get_performance_summary()
        recent_searches = performance_tracker.get_search_stats(limit=20)
    
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
    
    # Delete from CUBE index first (backward privacy)
    if cube_index:
        del_start = time.time()
        lcic_aff, hki_del, vkic_inv, dic_del = cube_index.remove_document_index(
            document_id,
            datetime.datetime.utcnow().isoformat()
        )
        del_duration_ms = (time.time() - del_start) * 1000
        
        if performance_tracker:
            performance_tracker.log_operation(
                'cube_index_deletion',
                del_duration_ms,
                f"doc={document_id},entries_removed={hki_del+dic_del}"
            )
    
    # Delete encrypted file
    encrypted_path = os.path.join(app.config["ENCRYPTED_FOLDER"], document["encrypted_path"])
    if os.path.exists(encrypted_path):
        try:
            os.remove(encrypted_path)
        except Exception as e:
            flash(f"Warning: Could not delete encrypted file: {str(e)}", "warning")
    
    # Delete from database
    db.execute("DELETE FROM keywords WHERE document_id = ?", (document_id,))
    db.execute("DELETE FROM documents WHERE id = ?", (document_id,))
    db.commit()
    
    flash("Document deleted successfully and removed from CUBE index.", "success")
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    ensure_directories()
    with app.app_context():
        create_tables()
    app.run(debug=True)
