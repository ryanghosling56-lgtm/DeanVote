"""
DeanVote v2.0
Anonymous Dean Candidate Election System
Single-file Flask application.

Run:
    python app.py
Then open:
    http://localhost:5000

Default admin credentials (change immediately after first login):
    username: admin
    password: admin12345
"""

import os
import io
import csv
import re
import sqlite3
import secrets
import hashlib
import string
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, request, session, redirect, url_for, jsonify,
    render_template_string, g, flash, send_file, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "deanvote.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
ALLOWED_IMAGE_EXT = {"png", "jpg", "jpeg", "webp"}

TOKEN_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # excludes O,0,I,1,L
TOKEN_LENGTH_DEFAULT = 6
EDIT_MINUTES_DEFAULT = 4
MAX_CANDIDATE_DEFAULT = 3

# All timestamps are stored internally in UTC (datetime.utcnow()) — this only
# controls how they're *displayed* to admins/voters. Default: WIB (Western
# Indonesia Time, UTC+7 / Asia-Jakarta). Change DISPLAY_TZ_OFFSET_HOURS to 8
# for WITA or 9 for WIT if your institution is outside Java/Sumatra/etc.
DISPLAY_TZ_OFFSET_HOURS = 7
DISPLAY_TZ_LABEL = "WIB"

app = Flask(__name__)
app.secret_key = os.environ.get("DEANVOTE_SECRET_KEY", secrets.token_hex(32))
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5MB uploads

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA journal_mode = WAL")
        g.db.execute("PRAGMA busy_timeout = 5000")
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS candidate (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            photo TEXT,
            vision TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS token (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            locked INTEGER NOT NULL DEFAULT 0,
            used_at TEXT,
            expire_at TEXT,
            email TEXT,
            email_sent INTEGER NOT NULL DEFAULT 0,
            email_sent_at TEXT,
            email_error TEXT,
            email_delivery TEXT DEFAULT NULL
        );

        CREATE TABLE IF NOT EXISTS vote (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (token_id) REFERENCES token(id)
        );

        CREATE TABLE IF NOT EXISTS vote_detail (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vote_id INTEGER NOT NULL,
            candidate_id INTEGER NOT NULL,
            FOREIGN KEY (vote_id) REFERENCES vote(id),
            FOREIGN KEY (candidate_id) REFERENCES candidate(id)
        );

        CREATE TABLE IF NOT EXISTS config (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            voting_open INTEGER NOT NULL DEFAULT 0,
            max_candidate INTEGER NOT NULL DEFAULT 3,
            edit_minutes INTEGER NOT NULL DEFAULT 5,
            token_length INTEGER NOT NULL DEFAULT 6,
            election_title TEXT NOT NULL DEFAULT 'Dean Candidate Election',
            smtp_host TEXT DEFAULT '',
            smtp_port INTEGER DEFAULT 587,
            smtp_username TEXT DEFAULT '',
            smtp_password TEXT DEFAULT '',
            smtp_from_email TEXT DEFAULT '',
            smtp_from_name TEXT DEFAULT 'DeanVote Election Committee',
            smtp_use_tls INTEGER DEFAULT 1,
            voting_url TEXT DEFAULT '',
            welcome_notes TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS voter_roster (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            added_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT,
            ip_hash TEXT,
            browser TEXT,
            action TEXT,
            time TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS admin_user (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );
        """
    )
    # --- Lightweight migration for databases created by earlier versions ---
    existing_token_cols = {row["name"] for row in db.execute("PRAGMA table_info(token)")}
    for col, ddl in [
        ("email", "ALTER TABLE token ADD COLUMN email TEXT"),
        ("email_sent", "ALTER TABLE token ADD COLUMN email_sent INTEGER NOT NULL DEFAULT 0"),
        ("email_sent_at", "ALTER TABLE token ADD COLUMN email_sent_at TEXT"),
        ("email_error", "ALTER TABLE token ADD COLUMN email_error TEXT"),
        ("email_delivery", "ALTER TABLE token ADD COLUMN email_delivery TEXT DEFAULT NULL"),
    ]:
        if col not in existing_token_cols:
            db.execute(ddl)

    existing_config_cols = {row["name"] for row in db.execute("PRAGMA table_info(config)")}
    for col, ddl in [
        ("smtp_host", "ALTER TABLE config ADD COLUMN smtp_host TEXT DEFAULT ''"),
        ("smtp_port", "ALTER TABLE config ADD COLUMN smtp_port INTEGER DEFAULT 587"),
        ("smtp_username", "ALTER TABLE config ADD COLUMN smtp_username TEXT DEFAULT ''"),
        ("smtp_password", "ALTER TABLE config ADD COLUMN smtp_password TEXT DEFAULT ''"),
        ("smtp_from_email", "ALTER TABLE config ADD COLUMN smtp_from_email TEXT DEFAULT ''"),
        ("smtp_from_name", "ALTER TABLE config ADD COLUMN smtp_from_name TEXT DEFAULT 'DeanVote Election Committee'"),
        ("smtp_use_tls", "ALTER TABLE config ADD COLUMN smtp_use_tls INTEGER DEFAULT 1"),
        ("voting_url", "ALTER TABLE config ADD COLUMN voting_url TEXT DEFAULT ''"),
        ("welcome_notes", "ALTER TABLE config ADD COLUMN welcome_notes TEXT DEFAULT ''"),
    ]:
        if col not in existing_config_cols:
            db.execute(ddl)

    db.execute(
        "INSERT OR IGNORE INTO config (id, voting_open, max_candidate, edit_minutes, token_length, welcome_notes) "
        "VALUES (1, 0, ?, ?, ?, ?)",
        (
            MAX_CANDIDATE_DEFAULT, EDIT_MINUTES_DEFAULT, TOKEN_LENGTH_DEFAULT,
            "Hak memilih hanya diberikan kepada Dosen tetap yang terdaftar sebagai pemilih sah dalam Pemilihan Dekan ini.\n"
            "Satu token hanya dapat digunakan satu kali untuk satu suara.\n"
            "Setelah mengirim suara, Anda masih dapat mengubah pilihan selama masa edit berlangsung — setelah itu, suara akan terkunci secara permanen dan tidak dapat diubah kembali.\n"
            "Jaga kerahasiaan token Anda — jangan membagikannya kepada siapa pun.",
        ),
    )
    cur = db.execute("SELECT COUNT(*) c FROM admin_user")
    if cur.fetchone()["c"] == 0:
        db.execute(
            "INSERT INTO admin_user (username, password_hash) VALUES (?, ?)",
            ("admin", generate_password_hash("admin12345")),
        )
    db.commit()
    db.close()


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def get_config():
    db = get_db()
    return db.execute("SELECT * FROM config WHERE id = 1").fetchone()


def now_str():
    return datetime.utcnow().isoformat(timespec="seconds")


def parse_dt(s):
    if not s:
        return None
    return datetime.fromisoformat(s)


def to_local_display(iso_str, fmt="%d %b %Y, %H:%M"):
    """Convert a stored UTC ISO timestamp to a human-readable local-time string
    (WIB by default) for display purposes only. Storage/locking logic always
    stays in UTC — only this presentation layer shifts the clock."""
    dt = parse_dt(iso_str)
    if not dt:
        return "-"
    local_dt = dt + timedelta(hours=DISPLAY_TZ_OFFSET_HOURS)
    return local_dt.strftime(fmt) + f" {DISPLAY_TZ_LABEL}"


def hash_ip(ip):
    return hashlib.sha256((ip or "unknown").encode()).hexdigest()[:16]


def generate_unique_token(db, length):
    while True:
        candidate = "".join(secrets.choice(TOKEN_ALPHABET) for _ in range(length))
        exists = db.execute("SELECT 1 FROM token WHERE token = ?", (candidate,)).fetchone()
        if not exists:
            return candidate


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def parse_email_list(raw_text):
    """Split free-form textarea input into a deduplicated, validated list of emails."""
    candidates = re.split(r"[,\n\r;\t ]+", raw_text.strip())
    seen = set()
    valid, invalid = [], []
    for item in candidates:
        item = item.strip()
        if not item:
            continue
        if EMAIL_RE.match(item) and item.lower() not in seen:
            seen.add(item.lower())
            valid.append(item)
        elif not EMAIL_RE.match(item):
            invalid.append(item)
    return valid, invalid


def build_token_email(cfg, token, voting_url):
    subject = f"Your Voting Token — {cfg['election_title']}"
    text_body = (
        f"You have been invited to vote in: {cfg['election_title']}\n\n"
        f"Your one-time voting token: {token}\n\n"
        f"Cast your ballot here: {voting_url}\n\n"
        f"This token is confidential and can only be used once (you may revise "
        f"your ballot for {cfg['edit_minutes']} minutes after first submitting). "
        f"Do not share it with anyone.\n\n"
        f"If you did not expect this email, you can ignore it."
    )
    html_body = f"""
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;padding:24px;border:1px solid #E7E0CE;border-radius:8px;">
      <p style="text-transform:uppercase;letter-spacing:2px;font-size:11px;color:#B98A2E;font-weight:bold;">Official Voting Token</p>
      <h2 style="color:#1B2440;margin:8px 0 20px;">{cfg['election_title']}</h2>
      <p style="color:#3C4568;font-size:14px;">You are eligible to vote. Use the token below to cast your ballot:</p>
      <div style="font-family:monospace;font-size:28px;letter-spacing:6px;text-align:center;background:#FAF7F0;border:1px dashed #E7E0CE;border-radius:8px;padding:16px;margin:20px 0;color:#1B2440;font-weight:bold;">{token}</div>
      <p style="text-align:center;margin:24px 0;">
        <a href="{voting_url}" style="background:#B98A2E;color:#fff;text-decoration:none;padding:12px 28px;border-radius:6px;font-size:14px;">Cast Your Vote</a>
      </p>
      <p style="color:#3C4568;font-size:12px;">This token is confidential and single-use (you may revise your ballot for
      {cfg['edit_minutes']} minutes after your first submission). Please do not forward this email.</p>
    </div>
    """
    return subject, text_body, html_body


def send_email(cfg, to_email, subject, text_body, html_body):
    """Send a single email using the SMTP settings stored in config. Raises on failure."""
    if not cfg["smtp_host"] or not cfg["smtp_from_email"]:
        raise RuntimeError("SMTP is not configured yet. Set it up in Admin → Settings.")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"{cfg['smtp_from_name']} <{cfg['smtp_from_email']}>"
    msg["To"] = to_email
    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    port = cfg["smtp_port"] or 587
    if port == 465:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(cfg["smtp_host"], port, context=context, timeout=15) as server:
            if cfg["smtp_username"]:
                server.login(cfg["smtp_username"], cfg["smtp_password"])
            server.sendmail(cfg["smtp_from_email"], [to_email], msg.as_string())
    else:
        with smtplib.SMTP(cfg["smtp_host"], port, timeout=15) as server:
            if cfg["smtp_use_tls"]:
                server.starttls(context=ssl.create_default_context())
            if cfg["smtp_username"]:
                server.login(cfg["smtp_username"], cfg["smtp_password"])
            server.sendmail(cfg["smtp_from_email"], [to_email], msg.as_string())


def log_action(token, action):
    db = get_db()
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    ua = request.headers.get("User-Agent", "unknown")[:255]
    db.execute(
        "INSERT INTO audit_log (token, ip_hash, browser, action, time) VALUES (?, ?, ?, ?, ?)",
        (token, hash_ip(ip), ua, action, now_str()),
    )
    db.commit()


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("admin_id"):
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return wrapper


def sync_token_lock_state(db, token_row):
    """Lock the token if the edit window has expired."""
    if token_row["used"] and not token_row["locked"]:
        expire_at = parse_dt(token_row["expire_at"])
        if expire_at and datetime.utcnow() > expire_at:
            db.execute("UPDATE token SET locked = 1 WHERE id = ?", (token_row["id"],))
            db.commit()
            return True
    return bool(token_row["locked"])


def allowed_image(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_IMAGE_EXT


# ---------------------------------------------------------------------------
# Shared layout (Tailwind + Chart.js CDN, civic/ceremonial design system)
# ---------------------------------------------------------------------------

BASE_LAYOUT = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{ page_title }} · DeanVote</title>
<script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,400;9..144,600;9..144,700&family=Inter:wght@400;500;600;700&family=IBM+Plex+Mono:wght@500&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"></script>
<style>
  :root{
    --ink:#1B2440;      /* deep indigo */
    --ink-soft:#3C4568;
    --gold:#B98A2E;     /* seal gold */
    --gold-soft:#E4C77E;
    --paper:#FAF7F0;    /* ballot paper */
    --paper-line:#E7E0CE;
    --green:#2F6B4F;
    --red:#9B3B3B;
  }
  body{ background:var(--paper); font-family:'Inter',sans-serif; color:var(--ink); }
  .font-display{ font-family:'Fraunces',serif; }
  .font-mono{ font-family:'IBM Plex Mono',monospace; }
  .seal{
    background: conic-gradient(from 180deg, var(--gold), var(--gold-soft), var(--gold));
    box-shadow: 0 0 0 3px var(--paper), 0 0 0 4px var(--gold);
  }
  .paper-card{ background:#fff; border:1px solid var(--paper-line); }
  .ballot-line{ border-bottom:1px dashed var(--paper-line); }
  ::selection{ background:var(--gold-soft); }
  .btn-primary{ background:var(--ink); color:var(--paper); transition:.15s; }
  .btn-primary:hover{ background:var(--ink-soft); }
  .btn-gold{ background:var(--gold); color:#fff; transition:.15s; }
  .btn-gold:hover{ background:#a67926; }
  .badge-open{ background:#E7F3EC; color:var(--green); }
  .badge-closed{ background:#F5E7E7; color:var(--red); }
  input:focus, select:focus, textarea:focus{ outline:2px solid var(--gold); outline-offset:1px; }
</style>
</head>
<body class="min-h-screen">
{{ body|safe }}
</body>
</html>
"""


def render_page(page_title, body):
    return render_template_string(BASE_LAYOUT, page_title=page_title, body=body)


# ---------------------------------------------------------------------------
# Public: Token entry / Home
# ---------------------------------------------------------------------------

WELCOME_BODY = """
<div class="max-w-lg mx-auto px-6 py-16">
  <div class="text-center mb-8">
    <div class="w-14 h-14 seal rounded-full mx-auto mb-5"></div>
    <p class="font-mono text-xs tracking-[0.25em] text-[var(--gold)] uppercase mb-2">Sistem Pemilihan Elektronik</p>
    <h1 class="font-display text-3xl font-semibold">Selamat Datang di {{ title }}</h1>
    <span class="inline-block mt-3 text-xs px-3 py-1.5 rounded-full font-medium {{ 'badge-open' if voting_open else 'badge-closed' }}">
      {{ "VOTING SEDANG DIBUKA" if voting_open else "VOTING DITUTUP/TIDAK DIBUKA" }}
    </span>
  </div>

  <div class="paper-card rounded-lg p-6 mb-6">
    <p class="text-xs uppercase tracking-wider text-[var(--ink-soft)] mb-3">Persyaratan &amp; Catatan Pemilihan</p>
    <ul class="space-y-2.5 text-sm text-[var(--ink-soft)]">
      {% for note in welcome_notes %}
      <li class="flex gap-2"><span class="text-[var(--gold)]">•</span><span>{{ note }}</span></li>
      {% endfor %}
      <li class="flex gap-2"><span class="text-[var(--gold)]">•</span><span>Anda dapat memilih maksimal <strong>{{ max_candidate }}</strong> kandidat.</span></li>
      <li class="flex gap-2"><span class="text-[var(--gold)]">•</span><span>Setelah suara pertama dikirim, Anda memiliki waktu <strong>{{ edit_minutes }} menit</strong> untuk melakukan perubahan terakhir sebelum otomatis terkunci.</span></li>
    </ul>
  </div>

  <a href="{{ url_for('submit_tokens_page') }}" class="block w-full btn-primary rounded-md py-3 font-medium text-center">Masuk &amp; Isi Token Voting</a>

  <div class="text-center mt-8">
    <!-- <a href="{{ url_for('results') }}" class="text-xs text-[var(--ink-soft)] underline underline-offset-4">Lihat hasil live</a>
    <span class="mx-2 text-[var(--paper-line)]">|</span> -->
    <a href="{{ url_for('admin_login') }}" class="text-xs text-[var(--ink-soft)] underline underline-offset-4">Login Administrator</a>
  </div>
</div>
"""


SUBMIT_TOKENS_BODY = """
<div class="max-w-md mx-auto px-6 py-16">
  <div class="text-center mb-10">
    <div class="w-14 h-14 seal rounded-full mx-auto mb-5"></div>
    <p class="font-mono text-xs tracking-[0.25em] text-[var(--gold)] uppercase mb-2">Sistem Pemilihan Elektronik</p>
    <h1 class="font-display text-3xl font-semibold">{{ title }}</h1>
    <p class="text-sm text-[var(--ink-soft)] mt-2">Masukkan token sekali pakai yang dikirimkan kepada anda melalui email.</p>
  </div>

  {% if not voting_open %}
  <div class="paper-card rounded-lg p-5 text-center text-sm text-[var(--ink-soft)]">
    Voting saat ini <span class="font-semibold text-[var(--red)]">ditutup</span>. Silahkan periksa kembali setelah pemilihan dibuka oleh panitia.
  </div>
  {% endif %}

  <form method="POST" action="{{ url_for('enter_token') }}" class="paper-card rounded-lg p-6 {% if not voting_open %}opacity-50 pointer-events-none{% endif %}">
    <label class="block text-xs uppercase tracking-wider text-[var(--ink-soft)] mb-2">Voting Token</label>
    <input name="token" maxlength="8" autocomplete="off" placeholder="YourToken"
      class="w-full font-mono text-center text-1xl tracking-[0.4em] uppercase border border-[var(--paper-line)] rounded-md py-3 px-3 mb-4" required>
    {% if error %}<p class="text-[var(--red)] text-sm mb-4">{{ error }}</p>{% endif %}
    <button type="submit" class="w-full btn-primary rounded-md py-3 font-medium">Lanjut ke Pemilihan</button>
  </form>

  <div class="text-center mt-8">
    <a href="{{ url_for('index') }}" class="text-xs text-[var(--ink-soft)] underline underline-offset-4">← Halaman depan</a>
    <span class="mx-2 text-[var(--paper-line)]">|</span>
    <a href="{{ url_for('vote_link_page') }}" class="text-xs text-[var(--ink-soft)] underline underline-offset-4">Vote-Email terdaftar</a>
    <span class="mx-2 text-[var(--paper-line)]">|</span>
  </div>
</div>
"""


def render_welcome_page():
    cfg = get_config()
    notes = [n.strip() for n in (cfg["welcome_notes"] or "").split("\n") if n.strip()]
    body = render_template_string(
        WELCOME_BODY, title=cfg["election_title"], voting_open=cfg["voting_open"],
        welcome_notes=notes, max_candidate=cfg["max_candidate"], edit_minutes=cfg["edit_minutes"],
    )
    return render_page("Selamat Datang", body)


def render_submit_tokens_page(error=None):
    cfg = get_config()
    body = render_template_string(SUBMIT_TOKENS_BODY, title=cfg["election_title"],
                                   voting_open=cfg["voting_open"], error=error)
    return render_page("Isi Token Voting", body)


@app.route("/", methods=["GET"])
def index():
    return render_welcome_page()


@app.route("/submit-tokens", methods=["GET"])
def submit_tokens_page():
    return render_submit_tokens_page()


@app.route("/enter-token", methods=["POST"])
def enter_token():
    cfg = get_config()
    db = get_db()
    raw = request.form.get("token", "").strip().upper()

    if not cfg["voting_open"]:
        return render_submit_tokens_page(error="Voting is closed.")

    row = db.execute("SELECT * FROM token WHERE token = ?", (raw,)).fetchone()
    if not row:
        log_action(raw, "TOKEN_INVALID")
        return render_submit_tokens_page(error="Token tidak dikenali.")

    locked = sync_token_lock_state(db, row)
    if locked:
        log_action(raw, "TOKEN_LOCKED_ATTEMPT")
        return render_submit_tokens_page(error="Jendela edit untuk token ini telah kedaluwarsa dan pemilihan telah dikunci.")

    session["voter_token"] = raw
    log_action(raw, "TOKEN_ACCEPTED")
    return redirect(url_for("vote_page"))


# ---------------------------------------------------------------------------
# Public: Vote via link (email verification, no manual token entry)
# ---------------------------------------------------------------------------

VOTE_LINK_BODY = """
<div class="max-w-md mx-auto px-6 py-16">
  <div class="text-center mb-10">
    <div class="w-14 h-14 seal rounded-full mx-auto mb-5"></div>
    <p class="font-mono text-xs tracking-[0.25em] text-[var(--gold)] uppercase mb-2">Verifikasi Pemilih</p>
    <h1 class="font-display text-3xl font-semibold">{{ title }}</h1>
    <p class="text-sm text-[var(--ink-soft)] mt-1">Masukkan alamat email Anda yang terdaftar untuk langsung masuk ke halaman pemilihan — tanpa perlu isi token manual.</p>
  </div>

  {% if not voting_open %}
  <div class="paper-card rounded-lg p-5 text-center text-sm text-[var(--ink-soft)] mt-1">
    Voting saat ini <span class="font-semibold text-[var(--red)]">ditutup</span>. Silahkan periksa kembali setelah pemilihan dibuka.
  </div>
  {% endif %}

  <form method="POST" action="{{ url_for('vote_link_verify') }}" class="paper-card rounded-lg p-6 {% if not voting_open %}opacity-50 pointer-events-none{% endif %}">
    <label class="block text-xs uppercase tracking-wider text-[var(--ink-soft)] mb-2">Email Terdaftar</label>
    <input name="email" type="email" autocomplete="email" placeholder="dosen@university.ac.id"
      class="w-full border border-[var(--paper-line)] rounded-md py-3 px-3 mb-4" required>
    {% if error %}<p class="text-[var(--red)] text-sm mb-4">{{ error }}</p>{% endif %}
    <button type="submit" class="w-full btn-primary rounded-md py-3 font-medium">Verifikasi &amp; Masuk</button>
  </form>

  <div class="text-center mt-5">
    <a href="{{ url_for('submit_tokens_page') }}" class="text-xs text-[var(--ink-soft)] underline underline-offset-4">Punya token? Isi manual di sini</a>
    <span class="mx-2 text-[var(--paper-line)]">|</span>
    <a href="{{ url_for('index') }}" class="text-xs text-[var(--ink-soft)] underline underline-offset-4">Halaman depan</a>
  </div>
</div>
"""


def render_vote_link_page(error=None):
    cfg = get_config()
    body = render_template_string(VOTE_LINK_BODY, title=cfg["election_title"], voting_open=cfg["voting_open"], error=error)
    return render_page("Verifikasi Pemilih", body)


@app.route("/vote-link", methods=["GET"])
def vote_link_page():
    return render_vote_link_page()


@app.route("/vote-link/verify", methods=["POST"])
def vote_link_verify():
    cfg = get_config()
    db = get_db()
    email = request.form.get("email", "").strip()

    if not EMAIL_RE.match(email):
        return render_vote_link_page(error="Format email tidak valid.")

    if not cfg["voting_open"]:
        return render_vote_link_page(error="Voting sedang ditutup.")

    # Does this email already have a token (from a previous visit, or from bulk email delivery)?
    existing_token = db.execute(
        "SELECT * FROM token WHERE LOWER(email) = LOWER(?) ORDER BY id DESC LIMIT 1", (email,)
    ).fetchone()

    if existing_token:
        locked = sync_token_lock_state(db, existing_token)
        if locked:
            log_action(existing_token["token"], "VOTE_LINK_LOCKED_ATTEMPT")
            return render_vote_link_page(error="Anda sudah memilih dan pemilihan telah dikunci permanen. Tidak dapat memilih lagi.")
        session["voter_token"] = existing_token["token"]
        log_action(existing_token["token"], "VOTE_LINK_REENTRY")
        return redirect(url_for("vote_page"))

    # No token yet — is this email on the eligible-voter roster?
    on_roster = db.execute("SELECT 1 FROM voter_roster WHERE LOWER(email) = LOWER(?)", (email,)).fetchone()
    if not on_roster:
        log_action(None, "VOTE_LINK_EMAIL_NOT_REGISTERED")
        return render_vote_link_page(error="Email tidak terdaftar sebagai pemilih yang sah. Hubungi panitia pemilihan jika Anda merasa ini keliru.")

    new_token = generate_unique_token(db, cfg["token_length"])
    db.execute("INSERT INTO token (token, email, email_delivery) VALUES (?, ?, 'via_link')", (new_token, email))
    db.commit()
    session["voter_token"] = new_token
    log_action(new_token, "TOKEN_CREATED_VIA_LINK")
    return redirect(url_for("vote_page"))


# ---------------------------------------------------------------------------
# Public: Voting page
# ---------------------------------------------------------------------------

VOTE_BODY = """
<div class="max-w-2xl mx-auto px-6 py-12">
  <div class="flex items-center justify-between mb-8">
    <div>
      <p class="font-mono text-xs tracking-[0.25em] text-[var(--gold)] uppercase mb-1">Token {{ token }}</p>
      <h1 class="font-display text-3xl font-semibold">{{ title }}</h1>
    </div>
    {% if editing %}
    <div class="text-right">
      <p class="text-xs text-[var(--ink-soft)]">Time left for editing</p>
      <p id="countdown" class="font-mono text-lg font-semibold text-[var(--red)]">--:--</p>
    </div>
    {% endif %}
  </div>

  <p class="text-sm text-[var(--ink-soft)] mb-6">Pilih maximal <strong>{{ max_candidate }}</strong> kandidat, kemudian kirim suara Anda.</p>

  <form method="POST" action="{{ url_for('submit_vote') }}" id="voteForm">
    <div class="space-y-3 mb-8">
      {% for c in candidates %}
      <label class="paper-card rounded-lg p-4 flex items-center gap-4 cursor-pointer has-[:checked]:ring-2 has-[:checked]:ring-[var(--gold)] block">
        <input type="checkbox" name="candidate_id" value="{{ c.id }}" class="w-5 h-5 accent-[var(--gold)]"
          {% if c.id in selected %}checked{% endif %}>
        {% if c.photo %}
        <img src="/static/uploads/{{ c.photo }}" class="w-14 h-14 rounded-full object-cover border border-[var(--paper-line)]">
        {% else %}
        <div class="w-14 h-14 rounded-full bg-[var(--paper-line)] flex items-center justify-center font-display text-lg">{{ c.name[0] }}</div>
        {% endif %}
        <div>
          <p class="font-semibold">{{ c.name }}</p>
          {% if c.vision %}<p class="text-xs text-[var(--ink-soft)] mt-1">{{ c.vision[:120] }}{% if c.vision|length > 120 %}...{% endif %}</p>{% endif %}
        </div>
      </label>
      {% endfor %}
    </div>
    <button type="submit" class="w-full btn-gold rounded-md py-3 font-medium">
      {{ "Confirm & Lock My Final Choice" if editing else "Submit" }}
    </button>
    <input type="hidden" name="finalize" id="finalizeInput" value="0">
  </form>
  {% if editing %}
  <p class="text-center text-xs text-[var(--ink-soft)] mt-4">Memperbarui pilihan anda akan langsung menguncinya secara permanen dan tidak akan dapat diubah kembali setelah ini.</p>
  {% endif %}
</div>

<script>
  const form = document.getElementById('voteForm');
  const max = {{ max_candidate }};
  form.addEventListener('change', (event) => {
    if (max === 1 && event.target.checked) {
      form.querySelectorAll('input[name=candidate_id]').forEach(cb => {
        if (cb !== event.target) cb.checked = false;
      });
      return;
    }
    const checked = form.querySelectorAll('input[name=candidate_id]:checked');
    if (checked.length > max) {
      event.target.checked = false;
      alert('Anda dapat memilih paling banyak ' + max + ' candidate(s).');
    }
  });
  form.addEventListener('submit', (e) => {
    const checked = form.querySelectorAll('input[name=candidate_id]:checked');
    if (checked.length === 0) {
      e.preventDefault();
      alert('Silahkan pilih setidaknya 1 kandidat sebelum mengirim.');
      return;
    }
    {% if editing %}
    const names = Array.from(checked).map(c => c.closest('label').querySelector('.font-semibold').textContent.trim());
    const confirmed = confirm(
      "Konfirmasi pilihan akhir anda:\\n\\n" + names.map(n => "• " + n).join("\\n") +
      "\\n\\nSetelah dikonfirmasi, pemilihan anda akan langsung dikunci dan anda TIDAK akan dapat memilih atau mengedit kembali. Lanjutkan?"
    );
    if (!confirmed) { e.preventDefault(); return; }
    document.getElementById('finalizeInput').value = '1';
    {% endif %}
  });
  {% if editing and expire_at %}
  const expireAt = new Date("{{ expire_at }}Z").getTime();
  const el = document.getElementById('countdown');
  function tick(){
    const diff = expireAt - Date.now();
    if (diff <= 0){ el.textContent = "Locked"; window.location.reload(); return; }
    const m = Math.floor(diff/60000), s = Math.floor((diff%60000)/1000);
    el.textContent = String(m).padStart(2,'0') + ':' + String(s).padStart(2,'0');
    setTimeout(tick, 1000);
  }
  tick();
  {% endif %}
</script>
"""


@app.route("/vote", methods=["GET"])
def vote_page():
    token = session.get("voter_token")
    if not token:
        return redirect(url_for("submit_tokens_page"))
    db = get_db()
    cfg = get_config()
    row = db.execute("SELECT * FROM token WHERE token = ?", (token,)).fetchone()
    if not row:
        session.pop("voter_token", None)
        return redirect(url_for("submit_tokens_page"))

    locked = sync_token_lock_state(db, row)
    if locked:
        session.pop("voter_token", None)
        return render_submit_tokens_page(error="Jendela pengeditan token ini telah kadaluwarsa dan pemungutan suara terkunci .")

    candidates = db.execute("SELECT * FROM candidate ORDER BY id").fetchall()
    selected = []
    editing = bool(row["used"])
    if editing:
        v = db.execute("SELECT * FROM vote WHERE token_id = ? ORDER BY id DESC LIMIT 1", (row["id"],)).fetchone()
        if v:
            details = db.execute("SELECT candidate_id FROM vote_detail WHERE vote_id = ?", (v["id"],)).fetchall()
            selected = [d["candidate_id"] for d in details]

    body = render_template_string(
        VOTE_BODY, token=token, title=cfg["election_title"], candidates=candidates,
        selected=selected, max_candidate=cfg["max_candidate"], editing=editing,
        expire_at=row["expire_at"],
    )
    return render_page("Berikan Suara Anda", body)


DONE_BODY = """
<div class="max-w-md mx-auto px-6 py-20 text-center">
  <div class="w-16 h-16 seal rounded-full mx-auto mb-6 flex items-center justify-center text-white font-display text-2xl">✓</div>
  {% if locked %}
  <h1 class="font-display text-2xl font-semibold mb-5">Pemungutan Suara Di Finalisasi &amp; Dikunci</h1>
  <p class="text-sm text-[var(--ink-soft)] mb-2">Suara anda telah direkam secara anonim dan sekarang telah dikunci secara permanen.</p>
  <p class="text-sm text-[var(--ink-soft)] mb-8">Token ini tidak dapat digunakan lagi untuk memilih atau membuat perubahan. Terima kasih telah berpartisipasi.</p>
  {% else %}
  <h1 class="font-display text-2xl font-semibold mb-3">Suara Tercatat</h1>
  <p class="text-sm text-[var(--ink-soft)] mb-2">Suara anda telah dicatat secara anonim.</p>
  <p class="text-sm text-[var(--ink-soft)] mb-10">Anda masih dapat mengedit pilihan anda dengan token yang sama hingga <strong>{{ expire_at }}</strong>.</p>
  <a href="{{ url_for('vote_page') }}" class="inline-block btn-primary rounded-md px-6 py-3 text-sm font-medium">Tinjau / Edit Pilihan</a>
  {% endif %}
  <div class="mt-6"><a href="{{ url_for('results') }}" class="text-xs underline text-[var(--ink-soft)]">View live results</a></div>
</div>
"""


@app.route("/vote/submit", methods=["POST"])
def submit_vote():
    token = session.get("voter_token")
    if not token:
        return redirect(url_for("submit_tokens_page"))
    db = get_db()
    cfg = get_config()
    row = db.execute("SELECT * FROM token WHERE token = ?", (token,)).fetchone()
    if not row:
        session.pop("voter_token", None)
        return redirect(url_for("submit_tokens_page"))

    if sync_token_lock_state(db, row):
        session.pop("voter_token", None)
        return redirect(url_for("submit_tokens_page"))

    if not cfg["voting_open"]:
        return redirect(url_for("submit_tokens_page"))

    candidate_ids = request.form.getlist("candidate_id")
    candidate_ids = [int(c) for c in candidate_ids][: cfg["max_candidate"]]
    if not candidate_ids:
        return redirect(url_for("vote_page"))

    finalize = request.form.get("finalize") == "1"
    ts = now_str()

    if row["used"]:
        # editing existing vote
        v = db.execute("SELECT * FROM vote WHERE token_id = ? ORDER BY id DESC LIMIT 1", (row["id"],)).fetchone()
        db.execute("DELETE FROM vote_detail WHERE vote_id = ?", (v["id"],))
        db.execute("UPDATE vote SET updated_at = ? WHERE id = ?", (ts, v["id"]))
        vote_id = v["id"]
        action = "VOTE_UPDATED"
        expire_at = row["expire_at"]
    else:
        cur = db.execute(
            "INSERT INTO vote (token_id, created_at, updated_at) VALUES (?, ?, ?)",
            (row["id"], ts, ts),
        )
        vote_id = cur.lastrowid
        edit_minutes = cfg["edit_minutes"]
        expire_at = (datetime.utcnow() + timedelta(minutes=edit_minutes)).isoformat(timespec="seconds")
        db.execute(
            "UPDATE token SET used = 1, used_at = ?, expire_at = ? WHERE id = ?",
            (ts, expire_at, row["id"]),
        )
        action = "VOTE_SUBMITTED"

    for cid in candidate_ids:
        db.execute("INSERT INTO vote_detail (vote_id, candidate_id) VALUES (?, ?)", (vote_id, cid))

    locked_now = False
    if finalize:
        db.execute("UPDATE token SET locked = 1 WHERE id = ?", (row["id"],))
        locked_now = True
        action = "VOTE_FINALIZED_LOCKED"

    db.commit()
    log_action(token, action)

    if locked_now:
        session.pop("voter_token", None)

    body = render_template_string(DONE_BODY, expire_at=to_local_display(expire_at), locked=locked_now)
    return render_page("Suara Tercatat", body)


@app.route("/logout-token")
def logout_token():
    session.pop("voter_token", None)
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# Public: Live results dashboard
# ---------------------------------------------------------------------------

RESULTS_BODY = """
<div class="max-w-5xl mx-auto px-6 py-12">
  <div class="flex items-center justify-between mb-8 flex-wrap gap-4">
    <div>
      <p class="font-mono text-xs tracking-[0.25em] text-[var(--gold)] uppercase mb-1">Live Dashboard</p>
      <h1 class="font-display text-3xl font-semibold">{{ title }}</h1>
    </div>
    <span class="text-xs px-3 py-1.5 rounded-full font-medium {{ 'badge-open' if voting_open else 'badge-closed' }}">
      {{ "VOTING OPEN" if voting_open else "VOTING CLOSED" }}
    </span>
  </div>

  <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
    <div class="paper-card rounded-lg p-4"><p class="text-xs text-[var(--ink-soft)]">Partisipasi</p><p id="s-pct" class="font-display text-2xl font-semibold">-</p></div>
    <div class="paper-card rounded-lg p-4"><p class="text-xs text-[var(--ink-soft)]">Total Suara Diberikan</p><p id="s-votes" class="font-display text-2xl font-semibold">-</p></div>
  </div>
  <p class="text-xs text-[var(--ink-soft)] mb-6">Jumlah pemilih sebenarnya dirahasiakan untuk melindungi kerahasiaan data partisipasi — hanya tingkat partisipasi yang ditampilkan.</p>

  <div class="paper-card rounded-lg p-4 mb-8">
    <div class="w-full bg-[var(--paper-line)] rounded-full h-3">
      <div id="progress-bar" class="h-3 rounded-full" style="width:0%; background:var(--gold);"></div>
    </div>
  </div>

  <div class="grid md:grid-cols-2 gap-6 mb-8">
    <div class="paper-card rounded-lg p-5">
      <p class="text-xs uppercase tracking-wider text-[var(--ink-soft)] mb-3">Vote Ranking</p>
      <canvas id="barChart" height="220"></canvas>
    </div>
    <div class="paper-card rounded-lg p-5">
      <p class="text-xs uppercase tracking-wider text-[var(--ink-soft)] mb-3">Vote Share</p>
      <canvas id="pieChart" height="220"></canvas>
    </div>
  </div>

  <div class="paper-card rounded-lg p-5">
    <p class="text-xs uppercase tracking-wider text-[var(--ink-soft)] mb-4">Live Ranking</p>
    <div id="ranking" class="space-y-3"></div>
  </div>
</div>

<script>
let bar, pie;
async function refresh(){
  const res = await fetch("{{ url_for('api_public_dashboard') }}");
  const d = await res.json();
  document.getElementById('s-pct').textContent = d.participation_pct + '%';
  document.getElementById('s-votes').textContent = d.total_votes_cast;
  document.getElementById('progress-bar').style.width = d.participation_pct + '%';

  const labels = d.ranking.map(r => r.name);
  const votes = d.ranking.map(r => r.votes);
  const colors = ['#B98A2E','#1B2440','#2F6B4F','#9B3B3B','#3C4568','#E4C77E'];

  if (!bar){
    bar = new Chart(document.getElementById('barChart'), {
      type: 'bar',
      data: { labels, datasets: [{ label: 'Votes', data: votes, backgroundColor: colors }] },
      options: { plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } }
    });
    pie = new Chart(document.getElementById('pieChart'), {
      type: 'pie',
      data: { labels, datasets: [{ data: votes, backgroundColor: colors }] },
    });
  } else {
    bar.data.labels = labels; bar.data.datasets[0].data = votes; bar.update();
    pie.data.labels = labels; pie.data.datasets[0].data = votes; pie.update();
  }

  const rankingEl = document.getElementById('ranking');
  rankingEl.innerHTML = '';
  d.ranking.forEach((r, i) => {
    const pct = d.total_votes_cast ? Math.round((r.votes / d.total_votes_cast) * 100) : 0;
    rankingEl.innerHTML += `
      <div>
        <div class="flex justify-between text-sm mb-1">
          <span class="font-medium">${i+1}. ${r.name}</span>
          <span class="font-mono text-[var(--ink-soft)]">${r.votes} votes</span>
        </div>
        <div class="w-full bg-[var(--paper-line)] rounded-full h-2">
          <div class="h-2 rounded-full" style="width:${pct}%; background:${['#B98A2E','#1B2440','#2F6B4F','#9B3B3B','#3C4568','#E4C77E'][i % 6]};"></div>
        </div>
      </div>`;
  });
}
refresh();
setInterval(refresh, 2000);
</script>
"""


@app.route("/results")
def results():
    cfg = get_config()
    body = render_template_string(RESULTS_BODY, title=cfg["election_title"], voting_open=cfg["voting_open"])
    return render_page("Live Results", body)


# ---------------------------------------------------------------------------
# REST API
# ---------------------------------------------------------------------------

@app.route("/api/public-dashboard")
def api_public_dashboard():
    """Privacy-safe version of the dashboard for the public /results page —
    exposes participation rate and vote ranking, but never raw token counts
    (which could reveal exact turnout numbers)."""
    db = get_db()
    cfg = get_config()
    total_tokens = db.execute("SELECT COUNT(*) c FROM token").fetchone()["c"]
    used_tokens = db.execute("SELECT COUNT(*) c FROM token WHERE used = 1").fetchone()["c"]
    pct = round((used_tokens / total_tokens) * 100, 1) if total_tokens else 0.0
    ranking = db.execute(
        """
        SELECT c.name as name, COUNT(vd.id) as votes
        FROM candidate c
        LEFT JOIN vote_detail vd ON vd.candidate_id = c.id
        GROUP BY c.id
        ORDER BY votes DESC, c.name ASC
        """
    ).fetchall()
    total_votes_cast = db.execute("SELECT COUNT(*) c FROM vote_detail").fetchone()["c"]
    return jsonify({
        "voting_open": bool(cfg["voting_open"]),
        "participation_pct": pct,
        "total_votes_cast": total_votes_cast,
        "ranking": [dict(r) for r in ranking],
    })


@app.route("/api/statistics")
@admin_required
def api_statistics():
    db = get_db()
    total_tokens = db.execute("SELECT COUNT(*) c FROM token").fetchone()["c"]
    used_tokens = db.execute("SELECT COUNT(*) c FROM token WHERE used = 1").fetchone()["c"]
    remaining = total_tokens - used_tokens
    pct = round((used_tokens / total_tokens) * 100, 1) if total_tokens else 0.0
    cfg = get_config()
    return jsonify({
        "total_candidates": db.execute("SELECT COUNT(*) c FROM candidate").fetchone()["c"],
        "total_tokens": total_tokens,
        "used_tokens": used_tokens,
        "remaining_tokens": remaining,
        "participation_pct": pct,
        "voting_open": bool(cfg["voting_open"]),
    })


@app.route("/api/result")
def api_result():
    db = get_db()
    rows = db.execute(
        """
        SELECT c.id, c.name, COUNT(vd.id) as votes
        FROM candidate c
        LEFT JOIN vote_detail vd ON vd.candidate_id = c.id
        GROUP BY c.id
        ORDER BY votes DESC, c.name ASC
        """
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/dashboard")
@admin_required
def api_dashboard():
    db = get_db()
    total_tokens = db.execute("SELECT COUNT(*) c FROM token").fetchone()["c"]
    used_tokens = db.execute("SELECT COUNT(*) c FROM token WHERE used = 1").fetchone()["c"]
    remaining = total_tokens - used_tokens
    pct = round((used_tokens / total_tokens) * 100, 1) if total_tokens else 0.0
    ranking = db.execute(
        """
        SELECT c.name as name, COUNT(vd.id) as votes
        FROM candidate c
        LEFT JOIN vote_detail vd ON vd.candidate_id = c.id
        GROUP BY c.id
        ORDER BY votes DESC, c.name ASC
        """
    ).fetchall()
    total_votes_cast = db.execute("SELECT COUNT(*) c FROM vote_detail").fetchone()["c"]
    return jsonify({
        "total_tokens": total_tokens,
        "used_tokens": used_tokens,
        "remaining_tokens": remaining,
        "participation_pct": pct,
        "total_votes_cast": total_votes_cast,
        "ranking": [dict(r) for r in ranking],
    })


@app.route("/api/candidate")
def api_candidate():
    db = get_db()
    rows = db.execute("SELECT id, name, photo, vision FROM candidate ORDER BY id").fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/token")
@admin_required
def api_token():
    db = get_db()
    rows = db.execute(
        "SELECT id, token, used, locked, used_at, expire_at, email, email_sent, email_error, email_delivery FROM token ORDER BY id"
    ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["used_at_display"] = to_local_display(r["used_at"])
        d["expire_at_display"] = to_local_display(r["expire_at"])
        result.append(d)
    return jsonify(result)


# ---------------------------------------------------------------------------
# Admin: Login / Logout
# ---------------------------------------------------------------------------

ADMIN_LOGIN_BODY = """
<div class="max-w-sm mx-auto px-6 py-24">
  <div class="text-center mb-8">
    <div class="w-12 h-12 seal rounded-full mx-auto mb-4"></div>
    <h1 class="font-display text-2xl font-semibold">Administrator</h1>
    <p class="text-xs text-[var(--ink-soft)] mt-1">DeanVote Control Panel</p>
  </div>
  <form method="POST" class="paper-card rounded-lg p-6">
    <label class="block text-xs uppercase tracking-wider text-[var(--ink-soft)] mb-2">Username</label>
    <input name="username" class="w-full border border-[var(--paper-line)] rounded-md py-2.5 px-3 mb-4" required>
    <label class="block text-xs uppercase tracking-wider text-[var(--ink-soft)] mb-2">Password</label>
    <input name="password" type="password" class="w-full border border-[var(--paper-line)] rounded-md py-2.5 px-3 mb-4" required>
    {% if error %}<p class="text-[var(--red)] text-sm mb-4">{{ error }}</p>{% endif %}
    <button class="w-full btn-primary rounded-md py-2.5 font-medium">Sign In</button>
  </form>
  <p class="text-center text-xs text-[var(--ink-soft)] mt-6"><a href="{{ url_for('index') }}" class="underline">← Kembali ke halaman depan</a></p>
</div>
"""


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    error = None
    if request.method == "POST":
        db = get_db()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = db.execute("SELECT * FROM admin_user WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session["admin_id"] = user["id"]
            session["admin_username"] = user["username"]
            return redirect(url_for("admin_dashboard"))
        error = "Invalid username or password."
    body = render_template_string(ADMIN_LOGIN_BODY, error=error)
    return render_page("Admin Login", body)


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_id", None)
    session.pop("admin_username", None)
    return redirect(url_for("admin_login"))


# ---------------------------------------------------------------------------
# Admin: Shared nav
# ---------------------------------------------------------------------------

ADMIN_NAV = """
<div class="border-b border-[var(--paper-line)] bg-white">
  <div class="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between flex-wrap gap-3">
    <a href="{{ url_for('admin_dashboard') }}" class="font-display text-lg font-semibold flex items-center gap-2">
      <span class="w-6 h-6 seal rounded-full inline-block"></span> DeanVote Admin
    </a>
    <nav class="flex gap-5 text-sm items-center flex-wrap">
      <a href="{{ url_for('admin_dashboard') }}" class="hover:text-[var(--gold)] {{ 'text-[var(--gold)] font-medium' if active=='dashboard' else '' }}">Dashboard</a>
      <a href="{{ url_for('admin_candidates') }}" class="hover:text-[var(--gold)] {{ 'text-[var(--gold)] font-medium' if active=='candidates' else '' }}">Kandidat</a>
      <a href="{{ url_for('admin_tokens') }}" class="hover:text-[var(--gold)] {{ 'text-[var(--gold)] font-medium' if active=='tokens' else '' }}">Token</a>
      <a href="{{ url_for('admin_audit') }}" class="hover:text-[var(--gold)] {{ 'text-[var(--gold)] font-medium' if active=='audit' else '' }}">Audit Log</a>
      <a href="{{ url_for('admin_settings') }}" class="hover:text-[var(--gold)] {{ 'text-[var(--gold)] font-medium' if active=='settings' else '' }}">Setting</a>
      <a href="{{ url_for('results') }}" target="_blank" class="hover:text-[var(--gold)]">Live Site ↗</a>
      <a href="{{ url_for('admin_logout') }}" class="text-[var(--red)] hover:underline">Logout</a>
    </nav>
  </div>
</div>
"""


def render_admin_page(title, active, inner_html):
    nav = render_template_string(ADMIN_NAV, active=active)
    body = nav + f'<div class="max-w-6xl mx-auto px-6 py-8">{inner_html}</div>'
    return render_page(title, body)


def flash_block():
    msgs = session.pop("_flash", None)
    if not msgs:
        return ""
    color = "badge-open" if msgs[0] == "ok" else "badge-closed"
    return f'<div class="mb-6 px-4 py-3 rounded-md text-sm {color}">{msgs[1]}</div>'


def set_flash(kind, message):
    session["_flash"] = (kind, message)


# ---------------------------------------------------------------------------
# Admin: Dashboard (control voting + monitor)
# ---------------------------------------------------------------------------

ADMIN_DASHBOARD_INNER = """
{{ flash|safe }}
<div class="flex items-center justify-between mb-6 flex-wrap gap-4">
  <h1 class="font-display text-2xl font-semibold">Election Control</h1>
  <span class="text-xs px-3 py-1.5 rounded-full font-medium {{ 'badge-open' if voting_open else 'badge-closed' }}">
    {{ "VOTING DIBUKA" if voting_open else "VOTING DITUTUP" }}
  </span>
</div>

<div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
  <div class="paper-card rounded-lg p-4"><p class="text-xs text-[var(--ink-soft)]">Kandidat</p><p class="font-display text-2xl font-semibold">{{ stats.total_candidates }}</p></div>
  <div class="paper-card rounded-lg p-4"><p class="text-xs text-[var(--ink-soft)]">Total Token</p><p class="font-display text-2xl font-semibold">{{ stats.total_tokens }}</p></div>
  <div class="paper-card rounded-lg p-4"><p class="text-xs text-[var(--ink-soft)]">Token Digunakan</p><p class="font-display text-2xl font-semibold">{{ stats.used_tokens }}</p></div>
  <div class="paper-card rounded-lg p-4"><p class="text-xs text-[var(--ink-soft)]">Partisipasi</p><p class="font-display text-2xl font-semibold">{{ stats.participation_pct }}%</p></div>
</div>

<div class="paper-card rounded-lg p-5 mb-8">
  <p class="text-xs uppercase tracking-wider text-[var(--ink-soft)] mb-4">Voting Controls</p>
  <div class="flex gap-3 flex-wrap">
    <form method="POST" action="{{ url_for('admin_voting_start') }}">
      <button class="btn-gold rounded-md px-5 py-2.5 text-sm font-medium" {{ 'disabled' if voting_open else '' }}>Start Voting</button>
    </form>
    <form method="POST" action="{{ url_for('admin_voting_stop') }}">
      <button class="border border-[var(--ink)] rounded-md px-5 py-2.5 text-sm font-medium" {{ 'disabled' if not voting_open else '' }}>Stop Voting</button>
    </form>
    <form method="POST" action="{{ url_for('admin_voting_reset') }}" onsubmit="return confirm('This will permanently erase all votes, tokens usage, and audit logs. Continue?');">
      <button class="text-[var(--red)] border border-[var(--red)] rounded-md px-5 py-2.5 text-sm font-medium">Reset Election</button>
    </form>
  </div>
</div>

<div class="paper-card rounded-lg p-5">
  <p class="text-xs uppercase tracking-wider text-[var(--ink-soft)] mb-4">Live Ranking</p>
  <div class="space-y-2">
    {% for r in ranking %}
    <div class="flex justify-between text-sm ballot-line py-2">
      <span>{{ loop.index }}. {{ r.name }}</span>
      <span class="font-mono text-[var(--ink-soft)]">{{ r.votes }} votes</span>
    </div>
    {% endfor %}
  </div>
</div>
"""


@app.route("/admin")
@admin_required
def admin_dashboard():
    db = get_db()
    cfg = get_config()
    total_tokens = db.execute("SELECT COUNT(*) c FROM token").fetchone()["c"]
    used_tokens = db.execute("SELECT COUNT(*) c FROM token WHERE used = 1").fetchone()["c"]
    stats = {
        "total_candidates": db.execute("SELECT COUNT(*) c FROM candidate").fetchone()["c"],
        "total_tokens": total_tokens,
        "used_tokens": used_tokens,
        "participation_pct": round((used_tokens / total_tokens) * 100, 1) if total_tokens else 0.0,
    }
    ranking = db.execute(
        """
        SELECT c.name as name, COUNT(vd.id) as votes
        FROM candidate c LEFT JOIN vote_detail vd ON vd.candidate_id = c.id
        GROUP BY c.id ORDER BY votes DESC, c.name ASC
        """
    ).fetchall()
    inner = render_template_string(ADMIN_DASHBOARD_INNER, flash=flash_block(), stats=stats,
                                    voting_open=cfg["voting_open"], ranking=ranking)
    return render_admin_page("Admin Dashboard", "dashboard", inner)


@app.route("/admin/voting/start", methods=["POST"])
@admin_required
def admin_voting_start():
    db = get_db()
    db.execute("UPDATE config SET voting_open = 1 WHERE id = 1")
    db.commit()
    log_action(None, "ADMIN_VOTING_STARTED")
    set_flash("ok", "Voting telah dibuka.")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/voting/stop", methods=["POST"])
@admin_required
def admin_voting_stop():
    db = get_db()
    db.execute("UPDATE config SET voting_open = 0 WHERE id = 1")
    db.commit()
    log_action(None, "ADMIN_VOTING_STOPPED")
    set_flash("ok", "Voting telah ditutup.")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/voting/reset", methods=["POST"])
@admin_required
def admin_voting_reset():
    db = get_db()
    db.execute("DELETE FROM vote_detail")
    db.execute("DELETE FROM vote")
    db.execute("UPDATE token SET used = 0, locked = 0, used_at = NULL, expire_at = NULL")
    db.execute("DELETE FROM audit_log")
    db.execute("UPDATE config SET voting_open = 0 WHERE id = 1")
    db.commit()
    set_flash("ok", "Pemilihan telah sepenuhnya di reset.")
    return redirect(url_for("admin_dashboard"))


# ---------------------------------------------------------------------------
# Admin: Candidates
# ---------------------------------------------------------------------------

ADMIN_CANDIDATES_INNER = """
{{ flash|safe }}
<div class="flex items-center justify-between mb-6">
  <h1 class="font-display text-2xl font-semibold">Kandidat</h1>
</div>

<div class="paper-card rounded-lg p-5 mb-8">
  <p class="text-xs uppercase tracking-wider text-[var(--ink-soft)] mb-4">Tambah Kandidat</p>
  <form method="POST" action="{{ url_for('admin_candidate_add') }}" enctype="multipart/form-data" class="grid md:grid-cols-3 gap-4">
    <div class="md:col-span-1">
      <label class="block text-xs text-[var(--ink-soft)] mb-1">Nama</label>
      <input name="name" required class="w-full border border-[var(--paper-line)] rounded-md py-2 px-3">
    </div>
    <div class="md:col-span-1">
      <label class="block text-xs text-[var(--ink-soft)] mb-1">Foto</label>
      <input type="file" name="photo" accept="image/*" class="w-full text-sm">
    </div>
    <div class="md:col-span-1">
      <label class="block text-xs text-[var(--ink-soft)] mb-1">Visi Misi / Statement</label>
      <input name="vision" class="w-full border border-[var(--paper-line)] rounded-md py-2 px-3">
    </div>
    <div class="md:col-span-3">
      <button class="btn-gold rounded-md px-5 py-2.5 text-sm font-medium">Tambah Kandidat</button>
    </div>
  </form>
</div>

<div class="space-y-4">
  {% for c in candidates %}
  <div class="paper-card rounded-lg p-4 flex items-center gap-4 flex-wrap">
    {% if c.photo %}
    <div class="relative group w-16 h-16 shrink-0">
      <img src="/static/uploads/{{ c.photo }}" class="w-16 h-16 rounded-full object-cover border border-[var(--paper-line)]">
      <form method="POST" action="{{ url_for('admin_candidate_photo_delete', candidate_id=c.id) }}"
        onsubmit="return confirm('Hapus foto kandidat ini? Foto akan dihapus permanen dari server, kandidat tetap ada.');">
        <button type="submit" title="Hapus foto"
          class="absolute inset-0 w-16 h-16 rounded-full bg-black/55 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center text-white">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-6 h-6">
            <polyline points="3 6 5 6 21 6"></polyline>
            <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"></path>
            <path d="M10 11v6"></path>
            <path d="M14 11v6"></path>
            <path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"></path>
          </svg>
        </button>
      </form>
    </div>
    {% else %}
    <div class="w-16 h-16 rounded-full bg-[var(--paper-line)] flex items-center justify-center font-display text-xl shrink-0">{{ c.name[0] }}</div>
    {% endif %}
    <form method="POST" action="{{ url_for('admin_candidate_edit', candidate_id=c.id) }}" enctype="multipart/form-data" class="flex-1 grid md:grid-cols-4 gap-3 items-center">
      <input name="name" value="{{ c.name }}" class="border border-[var(--paper-line)] rounded-md py-2 px-3 text-sm">
      <input name="vision" value="{{ c.vision or '' }}" class="border border-[var(--paper-line)] rounded-md py-2 px-3 text-sm md:col-span-1">
      <input type="file" name="photo" accept="image/*" class="text-xs">
      <div class="flex gap-2">
        <button class="btn-primary rounded-md px-4 py-2 text-xs font-medium">Simpan</button>
      </div>
    </form>
    <form method="POST" action="{{ url_for('admin_candidate_delete', candidate_id=c.id) }}" onsubmit="return confirm('Hapus kandidat ini? Foto dan seluruh data kandidat akan dihapus permanen.');">
      <button class="text-[var(--red)] border border-[var(--red)] rounded-md px-4 py-2 text-xs font-medium">Hapus</button>
    </form>
  </div>
  {% else %}
  <p class="text-sm text-[var(--ink-soft)]">Belum ada kandidat. Tambahkan kandidat pertama di atas.</p>
  {% endfor %}
</div>
<p class="text-xs text-[var(--ink-soft)] mt-3">Arahkan kursor ke foto kandidat untuk menampilkan tombol hapus foto.</p>
"""


@app.route("/admin/candidates")
@admin_required
def admin_candidates():
    db = get_db()
    candidates = db.execute("SELECT * FROM candidate ORDER BY id").fetchall()
    inner = render_template_string(ADMIN_CANDIDATES_INNER, flash=flash_block(), candidates=candidates)
    return render_admin_page("Candidates", "candidates", inner)


def save_photo(file_storage):
    if not file_storage or file_storage.filename == "":
        return None
    if not allowed_image(file_storage.filename):
        return None
    ext = file_storage.filename.rsplit(".", 1)[1].lower()
    filename = secure_filename(f"{secrets.token_hex(8)}.{ext}")
    file_storage.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
    return filename


def delete_photo_file(filename):
    """Remove an uploaded candidate photo from disk, if it exists. Never raises."""
    if not filename:
        return
    path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    try:
        if os.path.isfile(path):
            os.remove(path)
    except OSError:
        pass


@app.route("/admin/candidates/add", methods=["POST"])
@admin_required
def admin_candidate_add():
    db = get_db()
    name = request.form.get("name", "").strip()
    vision = request.form.get("vision", "").strip()
    if not name:
        set_flash("err", "Candidate name is required.")
        return redirect(url_for("admin_candidates"))
    photo = save_photo(request.files.get("photo"))
    db.execute(
        "INSERT INTO candidate (name, photo, vision, created_at) VALUES (?, ?, ?, ?)",
        (name, photo, vision, now_str()),
    )
    db.commit()
    set_flash("ok", f"Candidate '{name}' added.")
    return redirect(url_for("admin_candidates"))


@app.route("/admin/candidates/<int:candidate_id>/edit", methods=["POST"])
@admin_required
def admin_candidate_edit(candidate_id):
    db = get_db()
    row = db.execute("SELECT * FROM candidate WHERE id = ?", (candidate_id,)).fetchone()
    if not row:
        set_flash("err", "Candidate not found.")
        return redirect(url_for("admin_candidates"))

    name = request.form.get("name", "").strip()
    vision = request.form.get("vision", "").strip()
    new_photo = save_photo(request.files.get("photo"))

    if new_photo:
        # A fresh photo was uploaded — it replaces whatever was there before.
        delete_photo_file(row["photo"])
        db.execute("UPDATE candidate SET name=?, vision=?, photo=? WHERE id=?", (name, vision, new_photo, candidate_id))
        set_flash("ok", "Kandidat diperbarui, foto baru diunggah.")
    else:
        db.execute("UPDATE candidate SET name=?, vision=? WHERE id=?", (name, vision, candidate_id))
        set_flash("ok", "Candidate updated.")

    db.commit()
    return redirect(url_for("admin_candidates"))


@app.route("/admin/candidates/<int:candidate_id>/photo/delete", methods=["POST"])
@admin_required
def admin_candidate_photo_delete(candidate_id):
    db = get_db()
    row = db.execute("SELECT * FROM candidate WHERE id = ?", (candidate_id,)).fetchone()
    if not row:
        set_flash("err", "Candidate not found.")
        return redirect(url_for("admin_candidates"))
    if not row["photo"]:
        set_flash("err", "Kandidat ini tidak memiliki foto.")
        return redirect(url_for("admin_candidates"))

    delete_photo_file(row["photo"])
    db.execute("UPDATE candidate SET photo = NULL WHERE id = ?", (candidate_id,))
    db.commit()
    set_flash("ok", f"Foto {row['name']} telah dihapus.")
    return redirect(url_for("admin_candidates"))


@app.route("/admin/candidates/<int:candidate_id>/delete", methods=["POST"])
@admin_required
def admin_candidate_delete(candidate_id):
    db = get_db()
    row = db.execute("SELECT * FROM candidate WHERE id = ?", (candidate_id,)).fetchone()
    if row:
        delete_photo_file(row["photo"])
    db.execute("DELETE FROM vote_detail WHERE candidate_id = ?", (candidate_id,))
    db.execute("DELETE FROM candidate WHERE id = ?", (candidate_id,))
    db.commit()
    set_flash("ok", "Candidate deleted.")
    return redirect(url_for("admin_candidates"))


# ---------------------------------------------------------------------------
# Admin: Tokens
# ---------------------------------------------------------------------------

ADMIN_TOKENS_INNER = """
{{ flash|safe }}
<div class="flex items-center justify-between mb-6 flex-wrap gap-3">
  <h1 class="font-display text-2xl font-semibold">Voting Tokens</h1>
  <div class="flex gap-3">
    <a href="{{ url_for('admin_tokens_export') }}" class="text-sm border border-[var(--ink)] rounded-md px-4 py-2">Export Tokens CSV</a>
    <a href="{{ url_for('admin_votes_export') }}" class="text-sm border border-[var(--ink)] rounded-md px-4 py-2">Export Votes CSV</a>
  </div>
</div>

<div class="grid md:grid-cols-2 gap-6 mb-8">
  <div class="paper-card rounded-lg p-5">
    <p class="text-xs uppercase tracking-wider text-[var(--ink-soft)] mb-4">Generate Tokens (no email)</p>
    <form method="POST" action="{{ url_for('admin_tokens_generate') }}" class="flex items-end gap-4 flex-wrap">
      <div>
        <label class="block text-xs text-[var(--ink-soft)] mb-1">Berapa token?</label>
        <input type="number" name="count" min="1" max="5000" value="50" class="border border-[var(--paper-line)] rounded-md py-2 px-3 w-32">
      </div>
      <button class="btn-gold rounded-md px-5 py-2.5 text-sm font-medium">Generate</button>
    </form>
    <p class="text-xs text-[var(--ink-soft)] mt-3">Gunakan ini untuk distribusi offline — lalu ekspor via CSV.</p>
  </div>

  <div class="paper-card rounded-lg p-5">
    <p class="text-xs uppercase tracking-wider text-[var(--ink-soft)] mb-1">Generate &amp; Email Tokens</p>
    <p class="text-xs text-[var(--ink-soft)] mb-3">Satu token per email, dikirim secara otomatis. Tempel satu alamat per baris (atau pisahkan dengan koma).</p>
    {% if not smtp_configured %}
    <p class="text-xs text-[var(--red)] mb-3">SMTP is not configured yet — <a href="{{ url_for('admin_settings') }}" class="underline">Atur di Settings terlebih dahulu</a> first.</p>
    {% endif %}
    <form method="POST" action="{{ url_for('admin_tokens_generate_email') }}">
      <textarea name="emails" rows="4" placeholder="dean.voter1@university.ac.id&#10;voter2@gmail.com" class="w-full border border-[var(--paper-line)] rounded-md py-2 px-3 text-sm font-mono mb-3"></textarea>
      <button class="btn-primary rounded-md px-5 py-2.5 text-sm font-medium" {{ 'disabled' if not smtp_configured else '' }}>Generate &amp; Send Email</button>
    </form>
  </div>
</div>

<div class="paper-card rounded-lg p-5 mb-8">
  <p class="text-xs uppercase tracking-wider text-[var(--ink-soft)] mb-1">Vote via Link (tanpa isi token manual)</p>
  <p class="text-xs text-[var(--ink-soft)] mb-3">
    Daftarkan email pemilih di bawah ini, lalu bagikan link berikut lewat WhatsApp/grup.
    Saat pemilih membuka link dan memasukkan emailnya, sistem otomatis memverifikasi lalu membuatkan token
    dan membawanya ke halaman pemilihan.
  </p>
  <div class="paper-card rounded-lg p-3 mb-4 font-mono text-sm break-all bg-[var(--paper)]">{{ vote_link_url }}</div>
  <form method="POST" action="{{ url_for('admin_roster_add') }}" class="mb-4">
    <label class="block text-xs text-[var(--ink-soft)] mb-1">Daftarkan email pemilih (satu per baris, atau pisahkan koma)</label>
    <textarea name="emails" rows="4" placeholder="dosen1@university.ac.id&#10;dosen2@university.ac.id" class="w-full border border-[var(--paper-line)] rounded-md py-2 px-3 text-sm font-mono mb-3"></textarea>
    <button class="btn-gold rounded-md px-5 py-2.5 text-sm font-medium">Daftarkan Email</button>
  </form>

  <p class="text-xs uppercase tracking-wider text-[var(--ink-soft)] mb-2">Pemilih Terdaftar ({{ roster|length }})</p>
  <div class="overflow-x-auto">
    <table class="w-full text-sm">
      <thead><tr class="text-left text-[var(--ink-soft)] border-b border-[var(--paper-line)]">
        <th class="py-2 pr-4">Email</th><th class="py-2 pr-4">Didaftarkan</th><th class="py-2 pr-4">Status Token</th><th class="py-2 pr-4"></th>
      </tr></thead>
      <tbody>
      {% for r in roster %}
        <tr class="ballot-line">
          <td class="py-2 pr-4">{{ r.email }}</td>
          <td class="py-2 pr-4 text-xs text-[var(--ink-soft)]">{{ r.added_at }}</td>
          <td class="py-2 pr-4 text-xs">
            {% if r.token_status == 'locked' %}<span class="badge-closed px-2 py-0.5 rounded-full text-xs">Terkunci</span>
            {% elif r.token_status == 'used' %}<span class="badge-open px-2 py-0.5 rounded-full text-xs">Telah memilih</span>
            {% elif r.token_status == 'unused' %}<span class="text-[var(--ink-soft)]">Token dibuat, belum memilih</span>
            {% else %}<span class="text-[var(--ink-soft)]">Belum membuka link</span>{% endif %}
          </td>
          <td class="py-2 pr-4">
            <form method="POST" action="{{ url_for('admin_roster_delete', roster_id=r.id) }}" onsubmit="return confirm('Hapus pendaftaran email ini dari daftar pemilih via link?');">
              <button class="text-xs text-[var(--red)] underline">Hapus</button>
            </form>
          </td>
        </tr>
      {% else %}
        <tr><td colspan="4" class="py-3 text-center text-[var(--ink-soft)] text-sm">Belum ada email terdaftar.</td></tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
</div>

<div class="paper-card rounded-lg p-5">
  <div class="flex items-center justify-between mb-4 flex-wrap gap-3">
    <div class="flex items-center gap-3 flex-wrap">
      <p class="text-xs uppercase tracking-wider text-[var(--ink-soft)]">Semua Token (<span id="tokensCount">{{ tokens|length }}</span>)</p>
      <span id="lastUpdated" class="text-xs text-[var(--ink-soft)]"></span>
    </div>
    <div class="flex items-center gap-3 flex-wrap">
      <label class="flex items-center gap-1.5 text-xs text-[var(--ink-soft)]">
        <input type="checkbox" id="autoRefreshToggle" checked class="w-3.5 h-3.5">
        Refresh otomatis tiap 5 detik
      </label>
      <button type="button" id="refreshNowBtn" class="text-xs border border-[var(--ink)] rounded-md px-3 py-1.5">↻ Refresh Sekarang</button>
      <form method="POST" action="{{ url_for('admin_tokens_delete_unused') }}" onsubmit="return confirm('Hapus semua token yang tidak digunakan? Token yang sudah memberikan suara akan tetap disimpan. Ini tidak dapat dibatalkan.');">
        <button class="text-xs text-[var(--red)] border border-[var(--red)] rounded-md px-3 py-1.5">Hapus semua token yang tidak digunakan</button>
      </form>
    </div>
  </div>
  <div class="overflow-x-auto">
    <table class="w-full text-sm">
      <thead><tr class="text-left text-[var(--ink-soft)] border-b border-[var(--paper-line)]">
        <th class="py-2 pr-4">Token</th><th class="py-2 pr-4">Email</th><th class="py-2 pr-4">Status</th><th class="py-2 pr-4">Digunakan pada</th><th class="py-2 pr-4">Kadaluwarsa</th><th class="py-2 pr-4"></th>
      </tr></thead>
      <tbody id="tokensTableBody">
      {% for t in tokens %}
        <tr class="ballot-line">
          <td class="py-2 pr-4 font-mono">{{ t.token }}</td>
          <td class="py-2 pr-4 text-xs">
            {% if t.email %}
              {{ t.email }}
              {% if t.email_delivery == 'sent' %}<span class="badge-open px-2 py-0.5 rounded-full text-xs ml-1">Terkirim</span>
              {% elif t.email_delivery == 'failed' %}<span class="badge-closed px-2 py-0.5 rounded-full text-xs ml-1" title="{{ t.email_error or '' }}">Gagal</span>
              {% elif t.email_delivery == 'via_link' %}<span class="bg-[var(--paper-line)] text-[var(--ink-soft)] px-2 py-0.5 rounded-full text-xs ml-1" title="Token dibuat otomatis saat pemilih verifikasi email lewat /vote-link, bukan hasil kirim email">Via Link</span>
              {% endif %}
            {% else %}<span class="text-[var(--ink-soft)]">-</span>{% endif %}
          </td>
          <td class="py-2 pr-4">
            {% if t.locked %}<span class="badge-closed px-2 py-0.5 rounded-full text-xs">Terkunci</span>
            {% elif t.used %}<span class="badge-open px-2 py-0.5 rounded-full text-xs">Telah memilih (dapat diedit)</span>
            {% else %}<span class="text-[var(--ink-soft)]">Belum digunakan</span>{% endif %}
          </td>
          <td class="py-2 pr-4 text-[var(--ink-soft)]">{{ t.used_at_display }}</td>
          <td class="py-2 pr-4 text-[var(--ink-soft)]">{{ t.expire_at_display }}</td>
          <td class="py-2 pr-4 whitespace-nowrap">
            {% if t.email %}
            <form method="POST" action="{{ url_for('admin_token_resend', token_id=t.id) }}" class="inline">
              <button class="text-xs underline text-[var(--ink-soft)]">Kirim Ulang</button>
            </form>
            {% endif %}
            <form method="POST" action="{{ url_for('admin_token_delete', token_id=t.id) }}" class="inline"
              onsubmit="return confirm({{ ('Token ini sudah digunakan untuk memberikan suara — Menghapusnya juga akan menghapus suara itu secara permanen. Apakah Anda benar-benar yakin?' if t.used else 'Hapus token yang tidak terpakai ini?')|tojson }});">
              <button class="text-xs text-[var(--red)] underline ml-3">Hapus</button>
            </form>
          </td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
</div>

<script>
(function(){
  const tbody = document.getElementById('tokensTableBody');
  const countEl = document.getElementById('tokensCount');
  const lastUpdatedEl = document.getElementById('lastUpdated');
  const toggle = document.getElementById('autoRefreshToggle');
  const refreshBtn = document.getElementById('refreshNowBtn');
  let timer = null;
  let inFlight = false;

  function esc(s){
    if (s === null || s === undefined) return '';
    return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  function statusBadge(t){
    if (t.locked) return '<span class="badge-closed px-2 py-0.5 rounded-full text-xs">Terkunci</span>';
    if (t.used) return '<span class="badge-open px-2 py-0.5 rounded-full text-xs">Telah memilih (dapat diedit)</span>';
    return '<span class="text-[var(--ink-soft)]">Belum digunakan</span>';
  }

  function emailCell(t){
    if (!t.email) return '<span class="text-[var(--ink-soft)]">-</span>';
    let badge = '';
    if (t.email_delivery === 'sent') {
      badge = '<span class="badge-open px-2 py-0.5 rounded-full text-xs ml-1">Terkirim</span>';
    } else if (t.email_delivery === 'failed') {
      badge = '<span class="badge-closed px-2 py-0.5 rounded-full text-xs ml-1" title="' + esc(t.email_error || '') + '">Gagal</span>';
    } else if (t.email_delivery === 'via_link') {
      badge = '<span class="bg-[var(--paper-line)] text-[var(--ink-soft)] px-2 py-0.5 rounded-full text-xs ml-1" title="Token dibuat otomatis saat pemilih verifikasi email lewat /vote-link, bukan hasil kirim email">Via Link</span>';
    }
    return esc(t.email) + badge;
  }

  function rowHtml(t){
    const deleteMsg = t.used
      ? 'Token ini sudah digunakan untuk memberikan suara — Menghapusnya juga akan menghapus suara itu secara permanen. Apakah Anda benar-benar yakin?'
      : 'Hapus token yang tidak terpakai ini?';
    const resendForm = t.email
      ? '<form method="POST" action="/admin/tokens/' + t.id + '/resend" class="inline"><button class="text-xs underline text-[var(--ink-soft)]">Kirim Ulang</button></form>'
      : '';
    return '<tr class="ballot-line">' +
      '<td class="py-2 pr-4 font-mono">' + esc(t.token) + '</td>' +
      '<td class="py-2 pr-4 text-xs">' + emailCell(t) + '</td>' +
      '<td class="py-2 pr-4">' + statusBadge(t) + '</td>' +
      '<td class="py-2 pr-4 text-[var(--ink-soft)]">' + esc(t.used_at_display) + '</td>' +
      '<td class="py-2 pr-4 text-[var(--ink-soft)]">' + esc(t.expire_at_display) + '</td>' +
      '<td class="py-2 pr-4 whitespace-nowrap">' + resendForm +
        '<form method="POST" action="/admin/tokens/' + t.id + '/delete" class="inline" onsubmit="return confirm(' + JSON.stringify(deleteMsg) + ');">' +
          '<button class="text-xs text-[var(--red)] underline ml-3">Hapus</button>' +
        '</form>' +
      '</td>' +
    '</tr>';
  }

  async function refreshTokens(){
    if (inFlight) return;
    inFlight = true;
    refreshBtn.textContent = '↻ Menyegarkan…';
    try {
      const res = await fetch('/api/token', { credentials: 'same-origin' });
      if (!res.ok) throw new Error('request failed');
      const tokens = await res.json();
      tbody.innerHTML = tokens.map(rowHtml).join('') || '<tr><td colspan="6" class="py-4 text-center text-[var(--ink-soft)] text-sm">Belum ada token.</td></tr>';
      countEl.textContent = tokens.length;
      lastUpdatedEl.textContent = 'Diperbarui ' + new Date().toLocaleTimeString();
    } catch (e) {
      lastUpdatedEl.textContent = 'Gagal refresh — akan dicoba lagi';
    } finally {
      inFlight = false;
      refreshBtn.textContent = '↻ Refresh Sekarang';
    }
  }

  function startAutoRefresh(){
    stopAutoRefresh();
    timer = setInterval(refreshTokens, 5000);
  }
  function stopAutoRefresh(){
    if (timer) { clearInterval(timer); timer = null; }
  }

  refreshBtn.addEventListener('click', refreshTokens);
  toggle.addEventListener('change', () => {
    if (toggle.checked) { refreshTokens(); startAutoRefresh(); }
    else { stopAutoRefresh(); }
  });

  if (toggle.checked) startAutoRefresh();
})();
</script>
"""


@app.route("/admin/tokens")
@admin_required
def admin_tokens():
    db = get_db()
    cfg = get_config()
    token_rows = db.execute("SELECT * FROM token ORDER BY id DESC LIMIT 500").fetchall()
    tokens = []
    for t in token_rows:
        d = dict(t)
        d["used_at_display"] = to_local_display(t["used_at"])
        d["expire_at_display"] = to_local_display(t["expire_at"])
        tokens.append(d)
    smtp_configured = bool(cfg["smtp_host"] and cfg["smtp_from_email"])

    roster_rows = db.execute("SELECT * FROM voter_roster ORDER BY id DESC LIMIT 500").fetchall()
    roster = []
    for r in roster_rows:
        t = db.execute(
            "SELECT used, locked FROM token WHERE LOWER(email) = LOWER(?) ORDER BY id DESC LIMIT 1", (r["email"],)
        ).fetchone()
        if not t:
            status = "none"
        elif t["locked"]:
            status = "locked"
        elif t["used"]:
            status = "used"
        else:
            status = "unused"
        roster.append({
            "id": r["id"], "email": r["email"],
            "added_at": to_local_display(r["added_at"]),
            "token_status": status,
        })

    base_url = cfg["voting_url"].rstrip("/") if cfg["voting_url"] else request.host_url.rstrip("/")
    vote_link_url = base_url + url_for("vote_link_page")

    inner = render_template_string(ADMIN_TOKENS_INNER, flash=flash_block(), tokens=tokens,
                                    smtp_configured=smtp_configured, roster=roster, vote_link_url=vote_link_url)
    return render_admin_page("Tokens", "tokens", inner)


@app.route("/admin/tokens/generate", methods=["POST"])
@admin_required
def admin_tokens_generate():
    db = get_db()
    cfg = get_config()
    try:
        count = int(request.form.get("count", 0))
    except ValueError:
        count = 0
    count = max(1, min(count, 5000))
    for _ in range(count):
        tok = generate_unique_token(db, cfg["token_length"])
        db.execute("INSERT INTO token (token) VALUES (?)", (tok,))
    db.commit()
    set_flash("ok", f"{count} tokens generated.")
    return redirect(url_for("admin_tokens"))


@app.route("/admin/tokens/generate-email", methods=["POST"])
@admin_required
def admin_tokens_generate_email():
    db = get_db()
    cfg = get_config()

    if not cfg["smtp_host"] or not cfg["smtp_from_email"]:
        set_flash("err", "SMTP is not configured yet. Set it up in Settings first.")
        return redirect(url_for("admin_tokens"))

    raw = request.form.get("emails", "")
    valid_emails, invalid_entries = parse_email_list(raw)

    if not valid_emails:
        set_flash("err", "No valid email addresses were found in the list.")
        return redirect(url_for("admin_tokens"))

    voting_url = cfg["voting_url"] or request.host_url.rstrip("/") + url_for("submit_tokens_page")

    sent, failed = 0, 0
    for addr in valid_emails:
        tok = generate_unique_token(db, cfg["token_length"])
        db.execute("INSERT INTO token (token, email) VALUES (?, ?)", (tok, addr))
        db.commit()
        row = db.execute("SELECT id FROM token WHERE token = ?", (tok,)).fetchone()
        try:
            subject, text_body, html_body = build_token_email(cfg, tok, voting_url)
            send_email(cfg, addr, subject, text_body, html_body)
            db.execute(
                "UPDATE token SET email_sent = 1, email_sent_at = ?, email_error = NULL, email_delivery = 'sent' WHERE id = ?",
                (now_str(), row["id"]),
            )
            sent += 1
            log_action(tok, "TOKEN_EMAILED")
        except Exception as e:  # noqa: BLE001 - surfaced to the admin, not swallowed silently
            db.execute(
                "UPDATE token SET email_sent = 0, email_error = ?, email_delivery = 'failed' WHERE id = ?",
                (str(e)[:250], row["id"]),
            )
            failed += 1
        db.commit()

    msg = f"{sent} email(s) sent."
    if failed:
        msg += f" {failed} failed — check the Email column for details."
    if invalid_entries:
        msg += f" Ignored {len(invalid_entries)} invalid entr{'y' if len(invalid_entries)==1 else 'ies'}."
    set_flash("ok" if not failed else "err", msg)
    return redirect(url_for("admin_tokens"))


@app.route("/admin/tokens/<int:token_id>/resend", methods=["POST"])
@admin_required
def admin_token_resend(token_id):
    db = get_db()
    cfg = get_config()
    row = db.execute("SELECT * FROM token WHERE id = ?", (token_id,)).fetchone()
    if not row or not row["email"]:
        set_flash("err", "This token has no email address on file.")
        return redirect(url_for("admin_tokens"))
    if not cfg["smtp_host"] or not cfg["smtp_from_email"]:
        set_flash("err", "SMTP is not configured yet. Set it up in Settings first.")
        return redirect(url_for("admin_tokens"))

    voting_url = cfg["voting_url"] or request.host_url.rstrip("/") + url_for("submit_tokens_page")
    try:
        subject, text_body, html_body = build_token_email(cfg, row["token"], voting_url)
        send_email(cfg, row["email"], subject, text_body, html_body)
        db.execute(
            "UPDATE token SET email_sent = 1, email_sent_at = ?, email_error = NULL, email_delivery = 'sent' WHERE id = ?",
            (now_str(), token_id),
        )
        db.commit()
        log_action(row["token"], "TOKEN_EMAIL_RESENT")
        set_flash("ok", f"Email resent to {row['email']}.")
    except Exception as e:  # noqa: BLE001
        db.execute(
            "UPDATE token SET email_sent = 0, email_error = ?, email_delivery = 'failed' WHERE id = ?",
            (str(e)[:250], token_id),
        )
        db.commit()
        set_flash("err", f"Failed to resend: {e}")
    return redirect(url_for("admin_tokens"))


def delete_token_cascade(db, token_row):
    """Delete a token and, if it was used, its associated vote/vote_detail rows too."""
    vote = db.execute("SELECT id FROM vote WHERE token_id = ?", (token_row["id"],)).fetchone()
    if vote:
        db.execute("DELETE FROM vote_detail WHERE vote_id = ?", (vote["id"],))
        db.execute("DELETE FROM vote WHERE id = ?", (vote["id"],))
    db.execute("DELETE FROM token WHERE id = ?", (token_row["id"],))


@app.route("/admin/tokens/<int:token_id>/delete", methods=["POST"])
@admin_required
def admin_token_delete(token_id):
    db = get_db()
    row = db.execute("SELECT * FROM token WHERE id = ?", (token_id,)).fetchone()
    if not row:
        set_flash("err", "Token not found.")
        return redirect(url_for("admin_tokens"))
    was_used = bool(row["used"])
    delete_token_cascade(db, row)
    db.commit()
    log_action(row["token"], "TOKEN_DELETED_WITH_VOTE" if was_used else "TOKEN_DELETED")
    set_flash("ok", f"Token {row['token']} deleted" + (" along with its cast vote." if was_used else "."))
    return redirect(url_for("admin_tokens"))


@app.route("/admin/tokens/delete-unused", methods=["POST"])
@admin_required
def admin_tokens_delete_unused():
    db = get_db()
    rows = db.execute("SELECT id FROM token WHERE used = 0").fetchall()
    for r in rows:
        db.execute("DELETE FROM token WHERE id = ?", (r["id"],))
    db.commit()
    set_flash("ok", f"{len(rows)} unused token(s) deleted.")
    return redirect(url_for("admin_tokens"))


@app.route("/admin/roster/add", methods=["POST"])
@admin_required
def admin_roster_add():
    db = get_db()
    raw = request.form.get("emails", "")
    valid_emails, invalid_entries = parse_email_list(raw)

    if not valid_emails:
        set_flash("err", "Tidak ada alamat email yang valid ditemukan.")
        return redirect(url_for("admin_tokens"))

    added, skipped = 0, 0
    for addr in valid_emails:
        existing = db.execute("SELECT 1 FROM voter_roster WHERE LOWER(email) = LOWER(?)", (addr,)).fetchone()
        if existing:
            skipped += 1
            continue
        db.execute("INSERT INTO voter_roster (email, added_at) VALUES (?, ?)", (addr, now_str()))
        added += 1
    db.commit()

    msg = f"{added} email pemilih berhasil didaftarkan."
    if skipped:
        msg += f" {skipped} email sudah terdaftar sebelumnya (dilewati)."
    if invalid_entries:
        msg += f" {len(invalid_entries)} entri tidak valid diabaikan."
    set_flash("ok", msg)
    return redirect(url_for("admin_tokens"))


@app.route("/admin/roster/<int:roster_id>/delete", methods=["POST"])
@admin_required
def admin_roster_delete(roster_id):
    db = get_db()
    db.execute("DELETE FROM voter_roster WHERE id = ?", (roster_id,))
    db.commit()
    set_flash("ok", "Pendaftaran email dihapus dari daftar pemilih via link.")
    return redirect(url_for("admin_tokens"))


@app.route("/admin/tokens/export")
@admin_required
def admin_tokens_export():
    db = get_db()
    rows = db.execute(
        "SELECT token, email, email_sent, email_delivery, used, locked, used_at, expire_at FROM token ORDER BY id"
    ).fetchall()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["token", "email", "email_sent", "email_delivery", "used", "locked", "used_at", "expire_at"])
    for r in rows:
        writer.writerow([r["token"], r["email"] or "", r["email_sent"], r["email_delivery"] or "", r["used"], r["locked"], r["used_at"], r["expire_at"]])
    mem = io.BytesIO(buf.getvalue().encode())
    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name="deanvote_tokens.csv")


@app.route("/admin/votes/export")
@admin_required
def admin_votes_export():
    db = get_db()
    rows = db.execute(
        """
        SELECT v.id as vote_id, t.token as token, v.created_at, v.updated_at,
               GROUP_CONCAT(c.name, ' | ') as candidates
        FROM vote v
        JOIN token t ON t.id = v.token_id
        JOIN vote_detail vd ON vd.vote_id = v.id
        JOIN candidate c ON c.id = vd.candidate_id
        GROUP BY v.id
        ORDER BY v.id
        """
    ).fetchall()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["vote_id", "token", "created_at", "updated_at", "candidates_selected"])
    for r in rows:
        writer.writerow([r["vote_id"], r["token"], r["created_at"], r["updated_at"], r["candidates"]])
    mem = io.BytesIO(buf.getvalue().encode())
    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name="deanvote_votes.csv")


# ---------------------------------------------------------------------------
# Admin: Audit log
# ---------------------------------------------------------------------------

ADMIN_AUDIT_INNER = """
{{ flash|safe }}
<div class="flex items-center justify-between mb-6 flex-wrap gap-3">
  <h1 class="font-display text-2xl font-semibold">Audit Log</h1>
  <div class="flex gap-3">
    <a href="{{ url_for('admin_audit_export') }}" class="text-sm border border-[var(--ink)] rounded-md px-4 py-2">Export CSV</a>
    <form method="POST" action="{{ url_for('admin_audit_clear') }}" onsubmit="return confirm('Hapus SEMUA entri Audit Log secara permanen? Ini tidak bisa dibatalkan — ekspor backup CSV terlebih dahulu jika anda membutuhkannya.');">
      <button class="text-sm text-[var(--red)] border border-[var(--red)] rounded-md px-4 py-2">Hapus semua Log</button>
    </form>
  </div>
</div>
<div class="paper-card rounded-lg p-5 overflow-x-auto">
  <table class="w-full text-sm">
    <thead><tr class="text-left text-[var(--ink-soft)] border-b border-[var(--paper-line)]">
      <th class="py-2 pr-4">Waktu</th><th class="py-2 pr-4">Token</th><th class="py-2 pr-4">Action</th><th class="py-2 pr-4">IP Hash</th><th class="py-2 pr-4">Browser</th><th class="py-2 pr-4"></th>
    </tr></thead>
    <tbody>
    {% for a in logs %}
      <tr class="ballot-line">
        <td class="py-2 pr-4 font-mono text-xs">{{ a.time_display }}</td>
        <td class="py-2 pr-4 font-mono">{{ a.token or '-' }}</td>
        <td class="py-2 pr-4">{{ a.action }}</td>
        <td class="py-2 pr-4 font-mono text-xs">{{ a.ip_hash }}</td>
        <td class="py-2 pr-4 text-xs text-[var(--ink-soft)]">{{ a.browser[:40] }}</td>
        <td class="py-2 pr-4">
          <form method="POST" action="{{ url_for('admin_audit_log_delete', log_id=a.id) }}" onsubmit="return confirm('Hapus entri log ini?');">
            <button class="text-xs text-[var(--red)] underline">Hapus</button>
          </form>
        </td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
</div>
"""


@app.route("/admin/audit")
@admin_required
def admin_audit():
    db = get_db()
    log_rows = db.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 500").fetchall()
    logs = []
    for a in log_rows:
        d = dict(a)
        d["time_display"] = to_local_display(a["time"], fmt="%d %b %Y, %H:%M:%S")
        logs.append(d)
    inner = render_template_string(ADMIN_AUDIT_INNER, flash=flash_block(), logs=logs)
    return render_admin_page("Audit Log", "audit", inner)


@app.route("/admin/audit/<int:log_id>/delete", methods=["POST"])
@admin_required
def admin_audit_log_delete(log_id):
    db = get_db()
    db.execute("DELETE FROM audit_log WHERE id = ?", (log_id,))
    db.commit()
    set_flash("ok", "Log entry deleted.")
    return redirect(url_for("admin_audit"))


@app.route("/admin/audit/clear", methods=["POST"])
@admin_required
def admin_audit_clear():
    db = get_db()
    db.execute("DELETE FROM audit_log")
    db.commit()
    set_flash("ok", "All audit log entries have been cleared.")
    return redirect(url_for("admin_audit"))


@app.route("/admin/audit/export")
@admin_required
def admin_audit_export():
    db = get_db()
    rows = db.execute("SELECT token, ip_hash, browser, action, time FROM audit_log ORDER BY id").fetchall()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["token", "ip_hash", "browser", "action", "time"])
    for r in rows:
        writer.writerow([r["token"], r["ip_hash"], r["browser"], r["action"], r["time"]])
    mem = io.BytesIO(buf.getvalue().encode())
    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name="deanvote_audit.csv")


# ---------------------------------------------------------------------------
# Admin: Settings
# ---------------------------------------------------------------------------

ADMIN_SETTINGS_INNER = """
{{ flash|safe }}
<h1 class="font-display text-2xl font-semibold mb-6">Settings</h1>

<div class="grid md:grid-cols-2 gap-6">
  <div class="paper-card rounded-lg p-5">
    <p class="text-xs uppercase tracking-wider text-[var(--ink-soft)] mb-4">Konfigurasi Pemilihan</p>
    <form method="POST" action="{{ url_for('admin_settings_update') }}" class="space-y-4">
      <div>
        <label class="block text-xs text-[var(--ink-soft)] mb-1">Judul Pemilihan</label>
        <input name="election_title" value="{{ cfg.election_title }}" class="w-full border border-[var(--paper-line)] rounded-md py-2 px-3">
      </div>
      <div>
        <label class="block text-xs text-[var(--ink-soft)] mb-1">Maximal Kandidat per Vote</label>
        <input type="number" name="max_candidate" min="1" max="10" value="{{ cfg.max_candidate }}" class="w-full border border-[var(--paper-line)] rounded-md py-2 px-3">
      </div>
      <div>
        <label class="block text-xs text-[var(--ink-soft)] mb-1">Jendela Edit Vote (menit)</label>
        <input type="number" name="edit_minutes" min="1" max="120" value="{{ cfg.edit_minutes }}" class="w-full border border-[var(--paper-line)] rounded-md py-2 px-3">
      </div>
      <div>
        <label class="block text-xs text-[var(--ink-soft)] mb-1">Panjang token baru</label>
        <select name="token_length" class="w-full border border-[var(--paper-line)] rounded-md py-2 px-3">
          <option value="5" {{ 'selected' if cfg.token_length==5 else '' }}>5 characters</option>
          <option value="6" {{ 'selected' if cfg.token_length==6 else '' }}>6 characters</option>
        </select>
      </div>
      <div>
        <label class="block text-xs text-[var(--ink-soft)] mb-1">Persyaratan &amp; Catatan Halaman Depan (satu baris = satu poin)</label>
        <textarea name="welcome_notes" rows="5" class="w-full border border-[var(--paper-line)] rounded-md py-2 px-3 text-sm">{{ cfg.welcome_notes }}</textarea>
        <p class="text-xs text-[var(--ink-soft)] mt-1">Ditampilkan sebagai daftar poin di halaman depan (sebelum voter masuk ke halaman isi token). Poin jumlah kandidat &amp; jendela edit ditambahkan otomatis, tidak perlu ditulis ulang di sini.</p>
      </div>
      <button class="btn-gold rounded-md px-5 py-2.5 text-sm font-medium">Save Settings</button>
    </form>
  </div>

  <div class="paper-card rounded-lg p-5">
    <p class="text-xs uppercase tracking-wider text-[var(--ink-soft)] mb-1">Email (SMTP) Settings</p>
    <p class="text-xs text-[var(--ink-soft)] mb-4">Digunakan untuk mengirim token langsung ke inbox pemilih dari halaman token.</p>
    <form method="POST" action="{{ url_for('admin_smtp_update') }}" class="space-y-3">
      <div>
        <label class="block text-xs text-[var(--ink-soft)] mb-1">SMTP Host</label>
        <input name="smtp_host" value="{{ cfg.smtp_host }}" placeholder="smtp.gmail.com" class="w-full border border-[var(--paper-line)] rounded-md py-2 px-3 text-sm">
      </div>
      <div class="grid grid-cols-2 gap-3">
        <div>
          <label class="block text-xs text-[var(--ink-soft)] mb-1">Port</label>
          <input type="number" name="smtp_port" value="{{ cfg.smtp_port }}" placeholder="587" class="w-full border border-[var(--paper-line)] rounded-md py-2 px-3 text-sm">
        </div>
        <div class="flex items-center gap-2 mt-5">
          <input type="checkbox" id="smtp_use_tls" name="smtp_use_tls" {{ 'checked' if cfg.smtp_use_tls else '' }} class="w-4 h-4">
          <label for="smtp_use_tls" class="text-xs text-[var(--ink-soft)]">Use STARTTLS (port 587)</label>
        </div>
      </div>
      <div>
        <label class="block text-xs text-[var(--ink-soft)] mb-1">SMTP Username</label>
        <input name="smtp_username" value="{{ cfg.smtp_username }}" class="w-full border border-[var(--paper-line)] rounded-md py-2 px-3 text-sm">
      </div>
      <div>
        <label class="block text-xs text-[var(--ink-soft)] mb-1">SMTP Password / App Password</label>
        <input type="password" name="smtp_password" value="{{ cfg.smtp_password }}" class="w-full border border-[var(--paper-line)] rounded-md py-2 px-3 text-sm">
      </div>
      <div class="grid grid-cols-2 gap-3">
        <div>
          <label class="block text-xs text-[var(--ink-soft)] mb-1">From Email</label>
          <input name="smtp_from_email" value="{{ cfg.smtp_from_email }}" placeholder="election@university.ac.id" class="w-full border border-[var(--paper-line)] rounded-md py-2 px-3 text-sm">
        </div>
        <div>
          <label class="block text-xs text-[var(--ink-soft)] mb-1">From Name</label>
          <input name="smtp_from_name" value="{{ cfg.smtp_from_name }}" class="w-full border border-[var(--paper-line)] rounded-md py-2 px-3 text-sm">
        </div>
      </div>
      <div>
        <label class="block text-xs text-[var(--ink-soft)] mb-1">Voting URL (Ditampilkan di tombol email)</label>
        <input name="voting_url" value="{{ cfg.voting_url }}" placeholder="https://vote.university.ac.id" class="w-full border border-[var(--paper-line)] rounded-md py-2 px-3 text-sm">
        <p class="text-xs text-[var(--ink-soft)] mt-1">Biarkan kosong untuk menggunakan alamat server ini secara otomatis.</p>
      </div>
      <button class="btn-gold rounded-md px-5 py-2.5 text-sm font-medium">Save SMTP Settings</button>
    </form>
    <form method="POST" action="{{ url_for('admin_smtp_test') }}" class="mt-4 pt-4 border-t border-[var(--paper-line)] flex items-end gap-3">
      <div class="flex-1">
        <label class="block text-xs text-[var(--ink-soft)] mb-1">Kirim test email kepada</label>
        <input name="test_email" type="email" placeholder="you@university.ac.id" class="w-full border border-[var(--paper-line)] rounded-md py-2 px-3 text-sm" required>
      </div>
      <button class="border border-[var(--ink)] rounded-md px-4 py-2.5 text-sm font-medium">Send Test</button>
    </form>
  </div>

  <div class="paper-card rounded-lg p-5">
    <p class="text-xs uppercase tracking-wider text-[var(--ink-soft)] mb-4">Ubah Password Admin</p>
    <form method="POST" action="{{ url_for('admin_password_update') }}" class="space-y-4">
      <div>
        <label class="block text-xs text-[var(--ink-soft)] mb-1">Password Saat Ini</label>
        <input type="password" name="current_password" class="w-full border border-[var(--paper-line)] rounded-md py-2 px-3" required>
      </div>
      <div>
        <label class="block text-xs text-[var(--ink-soft)] mb-1">Password Baru</label>
        <input type="password" name="new_password" minlength="8" class="w-full border border-[var(--paper-line)] rounded-md py-2 px-3" required>
      </div>
      <button class="btn-primary rounded-md px-5 py-2.5 text-sm font-medium">Update Password</button>
    </form>
  </div>
</div>
"""


@app.route("/admin/settings")
@admin_required
def admin_settings():
    cfg = get_config()
    inner = render_template_string(ADMIN_SETTINGS_INNER, flash=flash_block(), cfg=cfg)
    return render_admin_page("Settings", "settings", inner)


@app.route("/admin/settings/update", methods=["POST"])
@admin_required
def admin_settings_update():
    db = get_db()
    title = request.form.get("election_title", "Dean Candidate Election").strip()
    max_candidate = int(request.form.get("max_candidate", 3))
    edit_minutes = int(request.form.get("edit_minutes", 5))
    token_length = int(request.form.get("token_length", 6))
    welcome_notes = request.form.get("welcome_notes", "").strip()
    db.execute(
        "UPDATE config SET election_title=?, max_candidate=?, edit_minutes=?, token_length=?, welcome_notes=? WHERE id=1",
        (title, max_candidate, edit_minutes, token_length, welcome_notes),
    )
    db.commit()
    set_flash("ok", "Settings updated.")
    return redirect(url_for("admin_settings"))


@app.route("/admin/settings/smtp", methods=["POST"])
@admin_required
def admin_smtp_update():
    db = get_db()
    db.execute(
        """
        UPDATE config SET
            smtp_host = ?, smtp_port = ?, smtp_username = ?, smtp_password = ?,
            smtp_from_email = ?, smtp_from_name = ?, smtp_use_tls = ?, voting_url = ?
        WHERE id = 1
        """,
        (
            request.form.get("smtp_host", "").strip(),
            int(request.form.get("smtp_port") or 587),
            request.form.get("smtp_username", "").strip(),
            request.form.get("smtp_password", ""),
            request.form.get("smtp_from_email", "").strip(),
            request.form.get("smtp_from_name", "DeanVote Election Committee").strip(),
            1 if request.form.get("smtp_use_tls") else 0,
            request.form.get("voting_url", "").strip(),
        ),
    )
    db.commit()
    set_flash("ok", "SMTP settings saved.")
    return redirect(url_for("admin_settings"))


@app.route("/admin/settings/smtp/test", methods=["POST"])
@admin_required
def admin_smtp_test():
    cfg = get_config()
    to_email = request.form.get("test_email", "").strip()
    if not to_email or not EMAIL_RE.match(to_email):
        set_flash("err", "Enter a valid email address to send the test to.")
        return redirect(url_for("admin_settings"))
    try:
        voting_url = cfg["voting_url"] or request.host_url.rstrip("/") + url_for("submit_tokens_page")
        subject, text_body, html_body = build_token_email(cfg, "TEST12", voting_url)
        subject = "[TEST] " + subject
        send_email(cfg, to_email, subject, text_body, html_body)
        set_flash("ok", f"Test email sent to {to_email}.")
    except Exception as e:  # noqa: BLE001
        set_flash("err", f"Test email failed: {e}")
    return redirect(url_for("admin_settings"))


@app.route("/admin/password/update", methods=["POST"])
@admin_required
def admin_password_update():
    db = get_db()
    user = db.execute("SELECT * FROM admin_user WHERE id = ?", (session["admin_id"],)).fetchone()
    current = request.form.get("current_password", "")
    new = request.form.get("new_password", "")
    if not check_password_hash(user["password_hash"], current):
        set_flash("err", "Current password is incorrect.")
        return redirect(url_for("admin_settings"))
    if len(new) < 8:
        set_flash("err", "New password must be at least 8 characters.")
        return redirect(url_for("admin_settings"))
    db.execute("UPDATE admin_user SET password_hash = ? WHERE id = ?", (generate_password_hash(new), user["id"]))
    db.commit()
    set_flash("ok", "Password updated.")
    return redirect(url_for("admin_settings"))


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
else:
    init_db()