import os
import re
import sqlite3
import hashlib
import base64
import datetime
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
)
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

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

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["ENCRYPTED_FOLDER"] = ENCRYPTED_FOLDER
app.config["DATABASE"] = DATABASE
app.secret_key = SECRET_KEY


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
    return render_template(
        "dashboard.html",
        documents=documents,
    )


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
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

        encrypted_name = f"{uuid4().hex}_{filename}.enc"
        encrypted_path = os.path.join(app.config["ENCRYPTED_FOLDER"], encrypted_name)
        aes_key = encrypt_file(upload_path, encrypted_path)

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


if __name__ == "__main__":
    ensure_directories()
    with app.app_context():
        create_tables()
    app.run(debug=True)
