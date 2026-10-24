import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from dotenv import load_dotenv
from flask import Flask, abort, flash, redirect, render_template, request, send_file, url_for
from flask_login import (
    LoginManager, UserMixin, current_user, login_required,
    login_user, logout_user
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import and_, or_
from werkzeug.utils import secure_filename

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
STORAGE_DIR = Path(os.getenv("STORAGE_DIR", str(BASE_DIR / "private_storage"))).resolve()
STORAGE_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY", ""),
    SQLALCHEMY_DATABASE_URI=os.getenv(
        "DATABASE_URL", "sqlite:///" + str(BASE_DIR / "trustvault_dev.db")
    ),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    MAX_CONTENT_LENGTH=10 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "0") == "1",
    WTF_CSRF_TIME_LIMIT=None,
)

if not app.config["SECRET_KEY"] or app.config["SECRET_KEY"] == "dev-only-change-me":
    if os.getenv("ALLOW_INSECURE_DEV_SECRET") != "1":
        raise RuntimeError("Set a strong SECRET_KEY in .env before starting TrustVault.")

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
password_hasher = PasswordHasher()
ALLOWED_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg"}
MAX_FILE_BYTES = 10 * 1024 * 1024
AUDIT_KEY = os.getenv("AUDIT_HMAC_KEY", "")


def utcnow():
    return datetime.now(timezone.utc)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="viewer")
    is_active = db.Column(db.Boolean, nullable=False, default=True)

    def set_password(self, password):
        self.password_hash = password_hasher.hash(password)

    def check_password(self, password):
        try:
            return password_hasher.verify(self.password_hash, password)
        except VerifyMismatchError:
            return False


class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    name = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(100), nullable=False, default="General")
    storage_key = db.Column(db.String(100), unique=True, nullable=False)
    mime_type = db.Column(db.String(100), nullable=False)
    size_bytes = db.Column(db.Integer, nullable=False)
    sha256 = db.Column(db.String(64), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    deleted_at = db.Column(db.DateTime(timezone=True), nullable=True)
    owner = db.relationship("User", foreign_keys=[owner_id])


class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey("document.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    permission = db.Column(db.String(10), nullable=False)  # read or edit
    granted_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    granted_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    revoked_at = db.Column(db.DateTime(timezone=True), nullable=True)
    document = db.relationship("Document")
    user = db.relationship("User", foreign_keys=[user_id])


class AuditEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.Integer, nullable=True, index=True)
    document_id = db.Column(db.Integer, nullable=True, index=True)
    action = db.Column(db.String(60), nullable=False)
    outcome = db.Column(db.String(20), nullable=False)
    details_json = db.Column(db.Text, nullable=False, default="{}")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    previous_hash = db.Column(db.String(64), nullable=True)
    event_hash = db.Column(db.String(64), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    try:
        user = db.session.get(User, int(user_id))
        return user if user and user.is_active else None
    except (ValueError, TypeError):
        return None


def audit(action, outcome, document_id=None, details=None, actor_id=None):
    """Hash-chain audit entries. Production deployments should export signed checkpoints externally."""
    previous = db.session.query(AuditEvent).order_by(AuditEvent.id.desc()).first()
    previous_hash = previous.event_hash if previous else "GENESIS"
    payload = {
        "actor_id": actor_id if actor_id is not None else (
            current_user.id if current_user.is_authenticated else None
        ),
        "document_id": document_id,
        "action": action,
        "outcome": outcome,
        "details": details or {},
        "created_at": utcnow().isoformat(),
        "previous_hash": previous_hash,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    key = AUDIT_KEY.encode("utf-8") if AUDIT_KEY else app.config["SECRET_KEY"].encode("utf-8")
    digest = hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    event = AuditEvent(
        actor_id=payload["actor_id"], document_id=document_id, action=action,
        outcome=outcome, details_json=json.dumps(details or {}, sort_keys=True),
        created_at=datetime.fromisoformat(payload["created_at"]),
        previous_hash=previous_hash, event_hash=digest,
    )
    db.session.add(event)
    db.session.flush()
    return event


def verify_audit_chain():
    """Checks links and signatures. This detects edits but not a full rewrite without external checkpoints."""
    previous_hash = "GENESIS"
    key = AUDIT_KEY.encode("utf-8") if AUDIT_KEY else app.config["SECRET_KEY"].encode("utf-8")
    for event in AuditEvent.query.order_by(AuditEvent.id.asc()).all():
        event_time = event.created_at
        # SQLite may return timezone-naive datetimes even when UTC was stored.
        if event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=timezone.utc)
        payload = {
            "actor_id": event.actor_id,
            "document_id": event.document_id,
            "action": event.action,
            "outcome": event.outcome,
            "details": json.loads(event.details_json or "{}"),
            "created_at": event_time.isoformat(),
            "previous_hash": previous_hash,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        expected = hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
        if event.previous_hash != previous_hash or not hmac.compare_digest(event.event_hash, expected):
            return False
        previous_hash = event.event_hash
    return True


def get_document(document_id):
    doc = db.session.get(Document, document_id)
    if doc is None or doc.deleted_at is not None:
        abort(404)
    return doc


def active_grant(user_id, document_id):
    return Permission.query.filter(
        Permission.user_id == user_id,
        Permission.document_id == document_id,
        Permission.revoked_at.is_(None),
    ).order_by(Permission.id.desc()).first()


def can_access_document(user, document, action="read"):
    if not user or not user.is_authenticated or not user.is_active:
        return False
    if document.owner_id == user.id:
        return action in {"read", "edit", "delete", "share"}
    grant = active_grant(user.id, document.id)
    if not grant:
        return False
    if action == "read":
        return grant.permission in {"read", "edit"}
    if action in {"edit", "delete", "share"}:
        return grant.permission == "edit" and action == "edit"
    return False


def require_document_access(document, action="read"):
    if not can_access_document(current_user, document, action):
        audit("ACCESS_DENIED", "denied", document_id=document.id, details={"action": action})
        db.session.commit()
        abort(404)


def sniff_file(path, extension):
    with open(path, "rb") as f:
        head = f.read(16)
    if extension == ".pdf":
        return head.startswith(b"%PDF-"), "application/pdf"
    if extension == ".png":
        return head.startswith(b"\x89PNG\r\n\x1a\n"), "image/png"
    if extension in {".jpg", ".jpeg"}:
        return head.startswith(b"\xff\xd8\xff"), "image/jpeg"
    return False, "application/octet-stream"


@app.after_request
def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.errorhandler(413)
def too_large(_error):
    return "File exceeds the 10 MB upload limit.", 413


@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()
        if user and user.is_active and user.check_password(password):
            login_user(user, fresh=True)
            audit("LOGIN_SUCCESS", "allowed", actor_id=user.id)
            db.session.commit()
            return redirect(url_for("dashboard"))
        audit("LOGIN_FAILURE", "denied", details={"email": email[:255]})
        db.session.commit()
        flash("Invalid email or password.")
    return render_template("login.html")


@app.post("/logout")
@login_required
def logout():
    audit("LOGOUT", "allowed")
    db.session.commit()
    logout_user()
    return redirect(url_for("login"))


@app.get("/dashboard")
@login_required
def dashboard():
    query = Document.query.filter(Document.deleted_at.is_(None))
    if current_user.role != "admin":
        granted_ids = db.session.query(Permission.document_id).filter(
            Permission.user_id == current_user.id,
            Permission.revoked_at.is_(None),
        )
        query = query.filter(or_(Document.owner_id == current_user.id, Document.id.in_(granted_ids)))

    name = request.args.get("name", "").strip()
    category = request.args.get("category", "").strip()
    owner = request.args.get("owner", "").strip()
    start = request.args.get("start", "").strip()
    end = request.args.get("end", "").strip()

    if name:
        query = query.filter(Document.name.ilike(f"%{name}%"))
    if category:
        query = query.filter(Document.category.ilike(f"%{category}%"))
    if owner:
        query = query.join(Document.owner).filter(User.name.ilike(f"%{owner}%"))
    if start:
        try:
            query = query.filter(Document.created_at >= datetime.fromisoformat(start).replace(tzinfo=timezone.utc))
        except ValueError:
            flash("Invalid start date.")
    if end:
        try:
            query = query.filter(Document.created_at < datetime.fromisoformat(end).replace(tzinfo=timezone.utc))
        except ValueError:
            flash("Invalid end date.")

    docs = query.order_by(Document.id.desc()).limit(200).all()
    return render_template("dashboard.html", documents=docs)


@app.post("/documents/upload")
@login_required
def upload_document():
    if current_user.role not in {"owner", "admin"}:
        abort(403)
    file = request.files.get("file")
    if not file or not file.filename:
        abort(400, "Choose a file.")
    display_name = secure_filename(file.filename)
    if not display_name or len(display_name) > 255:
        abort(400, "Invalid filename.")
    extension = Path(display_name).suffix.lower()
    if extension not in ALLOWED_EXTENSIONS:
        abort(400, "Only PDF, PNG, and JPEG files are allowed.")
    category = request.form.get("category", "General").strip()[:100] or "General"
    storage_key = secrets.token_hex(32)
    destination = STORAGE_DIR / storage_key
    file.save(destination)
    size = destination.stat().st_size
    valid, mime = sniff_file(destination, extension)
    if size <= 0 or size > MAX_FILE_BYTES or not valid:
        destination.unlink(missing_ok=True)
        audit("DOCUMENT_UPLOAD", "denied", details={"reason": "invalid file"})
        db.session.commit()
        abort(400, "Invalid file content or file size.")
    sha = hashlib.sha256(destination.read_bytes()).hexdigest()
    try:
        doc = Document(
            owner_id=current_user.id, name=display_name, category=category,
            storage_key=storage_key, mime_type=mime, size_bytes=size, sha256=sha,
        )
        db.session.add(doc)
        db.session.flush()
        audit("DOCUMENT_UPLOAD", "allowed", doc.id, {"name": display_name, "size": size})
        db.session.commit()
    except Exception:
        db.session.rollback()
        destination.unlink(missing_ok=True)
        raise
    flash("Document uploaded.")
    return redirect(url_for("dashboard"))


@app.get("/documents/<int:document_id>/download")
@login_required
def download_document(document_id):
    doc = get_document(document_id)
    require_document_access(doc, "read")
    path = (STORAGE_DIR / doc.storage_key).resolve()
    if path.parent != STORAGE_DIR or not path.is_file():
        abort(404)
    audit("DOCUMENT_DOWNLOAD", "allowed", doc.id, {"sha256": doc.sha256})
    db.session.commit()
    response = send_file(
        path, mimetype=doc.mime_type, as_attachment=True,
        download_name=doc.name, conditional=False,
    )
    response.headers["Cache-Control"] = "no-store, private"
    return response


@app.post("/documents/<int:document_id>/delete")
@login_required
def delete_document(document_id):
    doc = get_document(document_id)
    if doc.owner_id != current_user.id and current_user.role != "admin":
        require_document_access(doc, "delete")
    # Soft-delete metadata, then remove the file. Production needs a durable deletion job
    # and a recovery policy for failures between database and filesystem operations.
    doc.deleted_at = utcnow()
    audit("DOCUMENT_DELETE", "allowed", doc.id)
    db.session.commit()
    (STORAGE_DIR / doc.storage_key).unlink(missing_ok=True)
    flash("Document deleted.")
    return redirect(url_for("dashboard"))


@app.post("/documents/<int:document_id>/permissions")
@login_required
def grant_permission(document_id):
    doc = get_document(document_id)
    if doc.owner_id != current_user.id and current_user.role != "admin":
        abort(404)
    email = request.form.get("email", "").strip().lower()
    level = request.form.get("permission", "")
    target = User.query.filter_by(email=email, is_active=True).first()
    if not target:
        abort(400, "Recipient email not found or account inactive.")

    if level not in {"read", "edit"}:
        abort(400, "Invalid permission. Choose read or edit.")

    if target.id == doc.owner_id:
        abort(400, "The recipient already owns this document.")
    existing = active_grant(target.id, doc.id)
    if existing:
        existing.permission = level
        existing.granted_by = current_user.id
        existing.granted_at = utcnow()
    else:
        db.session.add(Permission(
            document_id=doc.id, user_id=target.id, permission=level,
            granted_by=current_user.id,
        ))
    audit("PERMISSION_GRANTED", "allowed", doc.id, {"recipient_id": target.id, "permission": level})
    db.session.commit()
    flash("Permission saved.")
    return redirect(url_for("dashboard"))


@app.post("/documents/<int:document_id>/permissions/<int:grant_id>/revoke")
@login_required
def revoke_permission(document_id, grant_id):
    doc = get_document(document_id)
    if doc.owner_id != current_user.id and current_user.role != "admin":
        abort(404)
    grant = Permission.query.filter_by(id=grant_id, document_id=doc.id).first_or_404()
    if grant.revoked_at is None:
        grant.revoked_at = utcnow()
        audit("PERMISSION_REVOKED", "allowed", doc.id, {"recipient_id": grant.user_id})
        db.session.commit()
    return redirect(url_for("dashboard"))


@app.get("/documents/<int:document_id>/permissions")
@login_required
def list_permissions(document_id):
    doc = get_document(document_id)
    if doc.owner_id != current_user.id and current_user.role != "admin":
        abort(404)
    grants = Permission.query.filter_by(document_id=doc.id).order_by(Permission.id.desc()).all()
    return {
        "document_id": doc.id,
        "permissions": [
            {"grant_id": g.id, "user_id": g.user_id, "email": g.user.email,
             "permission": g.permission, "revoked": g.revoked_at is not None}
            for g in grants
        ],
    }


@app.get("/admin/audit")
@login_required
def admin_audit():
    if current_user.role != "admin":
        abort(403)
    events = AuditEvent.query.order_by(AuditEvent.id.desc()).limit(500).all()
    return render_template("admin_audit.html", events=events, chain_valid=verify_audit_chain())


@app.get("/health")
def health():
    return {"status": "ok"}


@app.cli.command("init-db")
def init_db():
    db.create_all()
    print("Database tables created.")


@app.cli.command("create-user")
def create_user():
    """Create a user interactively: flask --app app create-user"""
    name = input("Name: ").strip()
    email = input("Email: ").strip().lower()
    role = input("Role (admin/owner/viewer): ").strip().lower()
    password = input("Password (input may be visible): ")
    if role not in {"admin", "owner", "viewer"}:
        raise SystemExit("Invalid role.")
    if User.query.filter_by(email=email).first():
        raise SystemExit("Email already exists.")
    user = User(name=name, email=email, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    print("User created.")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=False)
