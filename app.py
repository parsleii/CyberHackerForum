import json
import logging
import os
import re
import smtplib
import ssl
import uuid
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from functools import wraps
from io import BytesIO
from logging.handlers import RotatingFileHandler

import click
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    abort,
    has_request_context,
    send_file,
)
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename


app = Flask(__name__)

# ---------- KONFIGURACJA (wszystko przez zmienne środowiskowe) ----------

# Klucz do podpisywania cookie sesji i tokenów w mailach. W chmurze: Secret Manager.
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-tylko-lokalnie")

# Baza danych. Lokalnie: plik SQLite. W chmurze: Cloud SQL (PostgreSQL) po prywatnym IP.
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "sqlite:///forum.db"
)
# pool_pre_ping: przed użyciem połączenia z puli sprawdza, czy baza nadal je trzyma
# (Cloud SQL zamyka bezczynne połączenia - bez tego zdarzają się losowe błędy 500)
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}

# Ciasteczko sesji: niedostępne dla JavaScriptu, nie wysyłane z obcych stron,
# a w chmurze (HTTPS) tylko po szyfrowanym połączeniu
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE") == "1"

# Publiczny adres aplikacji używany w linkach w mailach, np. https://forum.example.pl
# Celowo NIE bierzemy adresu z nagłówka Host żądania - atakujący mógłby podać własny
# i dostać link resetu hasła do swojej domeny (Host header injection).
APP_BASE_URL = os.environ.get("APP_BASE_URL", "").rstrip("/")

# Limity treści
POST_MAX_CHARS = 2000
COMMENT_MAX_CHARS = 500
MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5 MB na plik
# Flask odrzuci całe żądanie większe niż to (błąd 413) zanim w ogóle je przeczytamy
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES + 512 * 1024

# Hasła
PASSWORD_MIN_LEN = 10
PASSWORD_MAX_LEN = 128
MAX_FAILED_LOGINS = 5  # po tylu nieudanych próbach konto blokuje się czasowo
LOCKOUT_TIME = timedelta(minutes=15)

# Ważność linków z maili
VERIFY_TOKEN_MAX_AGE = 24 * 3600  # 24 h
RESET_TOKEN_MAX_AGE = 3600  # 1 h

db = SQLAlchemy(app)

# ---------- LOGI AUDYTOWE ----------
AUDIT_LOG_FILE = os.environ.get("AUDIT_LOG_FILE", "logs/audit.log")
os.makedirs(os.path.dirname(AUDIT_LOG_FILE) or ".", exist_ok=True)

audit_logger = logging.getLogger("audit")
audit_logger.setLevel(logging.INFO)
audit_logger.propagate = False
if not audit_logger.handlers:
    _fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
    _fmt.converter = __import__("time").gmtime  # czas w UTC
    # plik rotowany: max 1 MB, 5 starych kopii (audit.log.1 ... audit.log.5)
    _file = RotatingFileHandler(AUDIT_LOG_FILE, maxBytes=1_000_000, backupCount=5, encoding="utf-8")
    _file.setFormatter(_fmt)
    _console = logging.StreamHandler()
    _console.setFormatter(_fmt)
    audit_logger.addHandler(_file)
    audit_logger.addHandler(_console)


def _clean(value):
    """Zabezpieczenie przed wstrzykiwaniem do logów (log injection):
    bierze w cudzysłów wartości ze spacjami/znakami specjalnymi i escapuje nowe linie, żeby użytkownik nie mógł podrobić osobnego wpisu w logu,"""
    text = str(value)
    if any(ch in text for ch in ' =|"\r\n\t'):
        # json.dumps dodaje cudzysłowy i zamienia znaki nowej linii na \n
        text = json.dumps(text, ensure_ascii=False)
    return text


def audit(event, level=logging.INFO, user=None, **details):
    """Zapisuje jedno zdarzenie audytowe w formacie:
    czas | poziom | ZDARZENIE user=... ip=... szczegóły..."""
    if user is None and has_request_context() and "user_id" in session:
        user = session.get("username")
    fields = [
        event,
        f"user={_clean(user) if user else '-'}",
        f"ip={request.remote_addr if has_request_context() else '-'}",
    ]
    fwd = request.headers.get("X-Forwarded-For") if has_request_context() else None
    if fwd:
        fields.append(f"fwd={_clean(fwd)}")  # adres klienta przekazany przez proxy (Cloud Run)
    fields += [f"{k}={_clean(v)}" for k, v in details.items()]
    audit_logger.log(level, " ".join(fields))


def utcnow():
    """Aktualny czas UTC bez strefy."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


# Dostępne długości bana (wartość z formularza -> czas trwania, None = na stałe)
BAN_DURATIONS = {
    "1h": timedelta(hours=1),
    "1d": timedelta(days=1),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
    "perm": None,
}


# ---------- MODELE (tabele w bazie) ----------


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)  # rola moderatora
    banned_until = db.Column(db.DateTime, nullable=True)  # ban czasowy (do kiedy, UTC)
    banned_permanent = db.Column(
        db.Boolean, default=False, nullable=False
    )  # ban na stałe
    # e-mail zapisywany małymi literami; unikalność pilnuje indeks w bazie
    email = db.Column(db.String(254), nullable=True)
    email_verified = db.Column(db.Boolean, default=False, nullable=False)
    # ochrona przed zgadywaniem hasła
    failed_logins = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)

    def ban_active(self):
        """Czy trwa ban czasowy."""
        return self.banned_until is not None and self.banned_until > utcnow()

    def is_banned(self):
        return self.banned_permanent or self.ban_active()

    def ban_message(self):
        if self.banned_permanent:
            return "Twoje konto zostało zablokowane na stałe."
        return f"Twoje konto jest zablokowane do {self.banned_until.strftime('%Y-%m-%d %H:%M')} UTC."

    def is_locked(self):
        return self.locked_until is not None and self.locked_until > utcnow()

    def password_fingerprint(self):
        """Fragment hasha hasła. Trafia do sesji i do tokenu resetu - po zmianie hasła
        przestaje się zgadzać, więc stare sesje i użyty link resetu stają się nieważne."""
        return self.password_hash[-16:]


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    author = db.relationship("User")
    # komentarze pod postem; usunięcie posta usuwa też jego komentarze
    comments = db.relationship(
        "Comment",
        backref="post",
        order_by="Comment.created_at",
        cascade="all, delete-orphan",
    )
    attachments = db.relationship(
        "Attachment", backref="post", cascade="all, delete-orphan"
    )


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey("post.id"), nullable=False)
    author = db.relationship("User")


class Attachment(db.Model):
    """Plik dołączony do posta. Sam plik leży w magazynie (folder lokalny albo
    prywatny bucket Cloud Storage), w bazie są tylko jego metadane."""
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey("post.id"), nullable=False)
    stored_name = db.Column(db.String(64), unique=True, nullable=False)  # losowa nazwa
    original_name = db.Column(db.String(255), nullable=False)
    mime_type = db.Column(db.String(64), nullable=False)
    size = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)

    @property
    def is_image(self):
        return self.mime_type.startswith("image/")


# ---------- MAILE ----------
# Dowolny serwer SMTP ustawiany zmiennymi: SMTP_HOST, SMTP_PORT, SMTP_USER,
# SMTP_PASSWORD, MAIL_FROM. Bez SMTP_HOST (lokalnie) mail wypisuje się w terminalu.

mail_logger = logging.getLogger("mail")
mail_logger.setLevel(logging.INFO)
if not mail_logger.handlers:
    mail_logger.addHandler(logging.StreamHandler())


def send_mail(to, subject, body):
    host = os.environ.get("SMTP_HOST")
    if not host:
        # Tryb DEV: brak serwera pocztowego - treść maila (z linkiem) idzie tylko na konsolę,
        # NIE do pliku audytu, bo link zawiera token, który działa jak hasło jednorazowe.
        mail_logger.info(
            "\n===== MAIL (DEV, nie wysłano) =====\nDo: %s\nTemat: %s\n\n%s\n===================================",
            to, subject, body,
        )
        return True

    msg = EmailMessage()
    msg["From"] = os.environ.get("MAIL_FROM", os.environ.get("SMTP_USER", ""))
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)

    port = int(os.environ.get("SMTP_PORT", "587"))
    context = ssl.create_default_context()  # weryfikacja certyfikatu serwera pocztowego
    try:
        if port == 465:
            server = smtplib.SMTP_SSL(host, port, context=context, timeout=10)
        else:
            server = smtplib.SMTP(host, port, timeout=10)
            server.starttls(context=context)  # szyfrowanie przed wysłaniem hasła SMTP
        with server:
            if os.environ.get("SMTP_USER"):
                server.login(os.environ["SMTP_USER"], os.environ.get("SMTP_PASSWORD", ""))
            server.send_message(msg)
        return True
    except (smtplib.SMTPException, OSError) as exc:
        audit("MAIL_FAIL", logging.ERROR, to=to, error=type(exc).__name__)
        return False


def external_url(endpoint, **values):
    """Pełny adres do wstawienia w mailu."""
    path = url_for(endpoint, **values)
    if APP_BASE_URL:
        return APP_BASE_URL + path
    return request.host_url.rstrip("/") + path  # tylko DEV, gdy APP_BASE_URL nie ustawiono


# Tokeny w linkach: podpisane SECRET_KEY i z datą utworzenia (itsdangerous).
# Nie trzymamy ich w bazie - podpis gwarantuje, że nikt ich nie podrobi ani nie zmieni.
_serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])


def make_token(data, purpose):
    return _serializer.dumps(data, salt=purpose)  # salt rozdziela rodzaje tokenów


def read_token(token, purpose, max_age):
    try:
        return _serializer.loads(token, salt=purpose, max_age=max_age)
    except SignatureExpired:
        return "expired"
    except BadSignature:
        return None


def send_verification_mail(user):
    token = make_token({"uid": user.id, "email": user.email}, "verify-email")
    link = external_url("verify_email", token=token)
    ok = send_mail(
        user.email,
        "CyberHackerForum - potwierdź adres e-mail",
        f"Cześć {user.username},\n\nkliknij, aby potwierdzić adres e-mail:\n{link}\n\n"
        f"Link jest ważny 24 godziny. Jeśli to nie Ty zakładałeś konto, zignoruj tę wiadomość.",
    )
    if ok:
        audit("EMAIL_VERIFY_SENT", user=user.username, email=user.email)
    return ok


def send_password_changed_mail(user):
    send_mail(
        user.email,
        "CyberHackerForum - hasło zostało zmienione",
        f"Cześć {user.username},\n\nhasło do Twojego konta właśnie zostało zmienione.\n"
        f"Jeśli to nie Ty, natychmiast zresetuj hasło: {external_url('forgot_password')}",
    )


# ---------- WALIDACJA DANYCH ----------

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,30}$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[A-Za-z]{2,}$")

def password_problems(password, username=""):
    """Zwraca listę problemów z hasłem (pusta lista = hasło OK)."""
    problems = []
    if len(password) < PASSWORD_MIN_LEN:
        problems.append(f"co najmniej {PASSWORD_MIN_LEN} znaków")
    if len(password) > PASSWORD_MAX_LEN:
        problems.append(f"najwyżej {PASSWORD_MAX_LEN} znaków")
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        problems.append("przynajmniej jedna litera i jedna cyfra")
    if username and username.lower() in password.lower():
        problems.append("nie może zawierać loginu")
    return problems


def hash_password(password):
    # scrypt: celowo wolna i pamięciożerna funkcja z losową solą - utrudnia łamanie
    # wykradzionych hashy na kartach graficznych
    return generate_password_hash(password, method="scrypt")


# Hash "na niby" - używany, gdy login nie istnieje, żeby odpowiedź trwała tyle samo
# co przy złym haśle (inaczej po czasie odpowiedzi dałoby się sprawdzić, czy login istnieje)
_DUMMY_HASH = hash_password("dummy-password-for-timing")


# ---------- PLIKI (załączniki) ----------

# Typ rozpoznajemy po ZAWARTOŚCI pliku (magic bytes), a nie po rozszerzeniu
# podanym przez użytkownika - plik "obrazek.png" może być w środku skryptem.
# SVG celowo nie jest dozwolony: to XML, który może zawierać JavaScript (XSS).
ALLOWED_TYPES = {
    "png": "image/png",
    "jpg": "image/jpeg",
    "gif": "image/gif",
    "webp": "image/webp",
    "pdf": "application/pdf",
    "txt": "text/plain",
}


def detect_type(data):
    """Zwraca rozszerzenie na podstawie pierwszych bajtów pliku albo None."""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    if data.startswith(b"%PDF-"):
        return "pdf"
    try:
        data.decode("utf-8")
        if b"\x00" not in data:
            return "txt"
    except UnicodeDecodeError:
        pass
    return None


class LocalStorage:
    """DEV: pliki w lokalnym folderze (poza katalogiem static, więc nie ma do nich
    bezpośredniego adresu - dostęp tylko przez widok sprawdzający logowanie)."""

    def __init__(self, folder):
        self.folder = folder
        os.makedirs(folder, exist_ok=True)

    def save(self, name, data, mime):
        with open(os.path.join(self.folder, name), "wb") as f:
            f.write(data)

    def load(self, name):
        with open(os.path.join(self.folder, name), "rb") as f:
            return f.read()

    def delete(self, name):
        try:
            os.remove(os.path.join(self.folder, name))
        except FileNotFoundError:
            pass


class GCSStorage:
    """Chmura: prywatny bucket Cloud Storage. Bucket nie ma publicznego dostępu -
    aplikacja czyta pliki swoim kontem serwisowym i oddaje je zalogowanym użytkownikom."""

    def __init__(self, bucket_name):
        from google.cloud import storage  # import tylko gdy używamy GCS

        self.bucket = storage.Client().bucket(bucket_name)

    def save(self, name, data, mime):
        self.bucket.blob(name).upload_from_string(data, content_type=mime)

    def load(self, name):
        return self.bucket.blob(name).download_as_bytes()

    def delete(self, name):
        blob = self.bucket.blob(name)
        if blob.exists():
            blob.delete()


_storage = None


def get_storage():
    global _storage
    if _storage is None:
        bucket = os.environ.get("GCS_BUCKET")
        _storage = GCSStorage(bucket) if bucket else LocalStorage(
            os.environ.get("UPLOAD_DIR", "uploads")
        )
    return _storage


# ---------- POMOCNICZE ----------


def current_user():
    """Zwraca zalogowanego użytkownika z bazy (albo None).
    Zbanowany użytkownik jest od razu wylogowywany, ban działa także na otwarte sesje.
    Po zmianie hasła wszystkie inne sesje tego konta też przestają działać."""
    if "user_id" not in session:
        return None
    user = db.session.get(User, session["user_id"])
    if user is not None and session.get("pwd") != user.password_fingerprint():
        audit("SESSION_TERMINATED_PASSWORD_CHANGED", logging.WARNING, user=user.username)
        session.clear()
        return None
    if user is None or user.is_banned():
        if user is not None:
            audit("SESSION_TERMINATED_BANNED", logging.WARNING, user=user.username)
        session.clear()
        return None
    return user


def log_in(user):
    session.clear()  # nowa sesja po zalogowaniu (ochrona przed session fixation)
    session["user_id"] = user.id
    session["username"] = user.username
    session["pwd"] = user.password_fingerprint()


def login_required(view):
    """Dekorator: wpuszcza tylko zalogowanych (i niezbanowanych)."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    """Dekorator: wpuszcza tylko administratora. Inni dostają 403 Forbidden."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if user is None:
            return redirect(url_for("login"))
        if not user.is_admin:
            audit("ACCESS_DENIED", logging.WARNING, user=user.username, path=request.path)
            abort(403)
        return view(*args, **kwargs)

    return wrapped


# Widoki dostępne dla zalogowanego, który nie ma jeszcze potwierdzonego maila
EMAIL_EXEMPT_ENDPOINTS = {"account", "set_email", "resend_my_verification",
                          "verify_email", "logout", "static"}


@app.before_request
def require_verified_email():
    """Konta bez potwierdzonego maila (np. założone przed tą wersją aplikacji)
    muszą najpierw podać i potwierdzić e-mail - inaczej nie da się im zresetować hasła."""
    if request.endpoint in EMAIL_EXEMPT_ENDPOINTS or "user_id" not in session:
        return None
    user = current_user()
    if user is not None and not (user.email and user.email_verified):
        return redirect(url_for("account"))
    return None


@app.context_processor
def inject_user():
    """Udostępnia zalogowanego użytkownika i limity we wszystkich szablonach."""
    return {
        "me": current_user(),
        "POST_MAX_CHARS": POST_MAX_CHARS,
        "COMMENT_MAX_CHARS": COMMENT_MAX_CHARS,
        "PASSWORD_MIN_LEN": PASSWORD_MIN_LEN,
    }


@app.after_request
def security_headers(response):
    # przeglądarka nie zgaduje typu pliku - liczy się tylko Content-Type od serwera
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    return response


@app.errorhandler(413)
def too_large(_e):
    audit("UPLOAD_REJECTED", logging.WARNING, reason="request_too_large")
    flash(f"Plik jest za duży (limit {MAX_UPLOAD_BYTES // (1024 * 1024)} MB).")
    return redirect(url_for("forum"))


# ---------- WIDOKI (adresy URL) ----------


@app.route("/")
def index():
    return redirect(url_for("forum") if "user_id" in session else url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        password2 = request.form.get("password2", "")

        errors = []
        if not USERNAME_RE.match(username):
            errors.append("Login: 3-30 znaków, tylko litery, cyfry oraz _ . -")
        if not EMAIL_RE.match(email) or len(email) > 254:
            errors.append("Podaj poprawny adres e-mail.")
        if password != password2:
            errors.append("Hasła nie są takie same.")
        problems = password_problems(password, username)
        if problems:
            errors.append("Hasło: " + ", ".join(problems) + ".")

        if not errors:
            # Sprawdzenie bez rozróżniania wielkości liter
            if User.query.filter(db.func.lower(User.username) == username.lower()).first():
                errors.append("Taki użytkownik już istnieje.")
            elif User.query.filter_by(email=email).first():
                errors.append("Ten adres e-mail jest już używany.")

        if errors:
            for e in errors:
                flash(e)
            audit("REGISTER_FAIL", logging.WARNING, user=username, reason=errors[0][:60])
            return render_template("register.html", username=username, email=email)

        user = User(username=username, email=email, password_hash=hash_password(password))
        db.session.add(user)
        db.session.commit()
        audit("REGISTER_OK", user=user.username, user_id=user.id, email=email)
        send_verification_mail(user)
        flash("Konto utworzone. Wysłaliśmy link aktywacyjny na podany e-mail - kliknij go, żeby się zalogować.")
        return redirect(url_for("login"))

    return render_template("register.html", username="", email="")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()

        if user and user.is_locked():
            audit("LOGIN_LOCKED", logging.WARNING, user=user.username)
            minutes = int((user.locked_until - utcnow()).total_seconds() // 60) + 1
            flash(f"Zbyt wiele nieudanych prób. Spróbuj ponownie za {minutes} min albo zresetuj hasło.")
            return render_template("login.html")

        if user is None:
            check_password_hash(_DUMMY_HASH, password)  # wyrównanie czasu odpowiedzi
            audit("LOGIN_FAIL", logging.WARNING, user=username, reason="unknown_user")
            flash("Błędny login lub hasło.")
            return render_template("login.html")

        if not check_password_hash(user.password_hash, password):
            user.failed_logins += 1
            if user.failed_logins >= MAX_FAILED_LOGINS:
                user.locked_until = utcnow() + LOCKOUT_TIME
                user.failed_logins = 0
                audit("ACCOUNT_LOCKED", logging.WARNING, user=user.username,
                      minutes=int(LOCKOUT_TIME.total_seconds() // 60))
            db.session.commit()
            # hasła NIGDY nie logujemy - tylko login, którego próbowano użyć
            audit("LOGIN_FAIL", logging.WARNING, user=username, reason="bad_password")
            flash("Błędny login lub hasło.")
            return render_template("login.html")

        if user.is_banned():
            audit("LOGIN_BLOCKED_BANNED", logging.WARNING, user=user.username)
            flash(user.ban_message())
            return render_template("login.html")

        if user.email and not user.email_verified:
            audit("LOGIN_BLOCKED_UNVERIFIED", logging.WARNING, user=user.username)
            flash("Najpierw potwierdź adres e-mail linkiem z maila.")
            return render_template("login.html", show_resend=True)

        # udane logowanie: zerujemy licznik, a stary hash (np. pbkdf2) podmieniamy na scrypt
        user.failed_logins = 0
        user.locked_until = None
        if not user.password_hash.startswith("scrypt:"):
            user.password_hash = hash_password(password)
        db.session.commit()
        log_in(user)
        audit("LOGIN_OK", user=user.username, admin=user.is_admin)
        return redirect(url_for("forum"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    if "user_id" in session:
        audit("LOGOUT")
    session.clear()
    return redirect(url_for("login"))


# ---------- E-MAIL I HASŁO ----------


@app.route("/verify/<token>")
def verify_email(token):
    data = read_token(token, "verify-email", VERIFY_TOKEN_MAX_AGE)
    user = db.session.get(User, data["uid"]) if isinstance(data, dict) else None
    # token musi dotyczyć AKTUALNEGO maila konta (po zmianie maila stary link nie działa)
    if user is None or user.email != data["email"]:
        audit("EMAIL_VERIFY_FAIL", logging.WARNING,
              reason="expired" if data == "expired" else "bad_token")
        flash("Link jest nieprawidłowy albo wygasł. Wyślij nowy.")
        return redirect(url_for("login"))
    user.email_verified = True
    db.session.commit()
    audit("EMAIL_VERIFIED", user=user.username, email=user.email)
    flash("Adres e-mail potwierdzony.")
    return redirect(url_for("forum") if "user_id" in session else url_for("login"))


@app.route("/resend-verification", methods=["GET", "POST"])
def resend_verification():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = User.query.filter_by(email=email).first()
        if user and not user.email_verified:
            send_verification_mail(user)
        # ta sama odpowiedź niezależnie od tego, czy mail jest w bazie (brak enumeracji kont)
        flash("Jeśli konto z tym adresem czeka na potwierdzenie, wysłaliśmy nowy link.")
        return redirect(url_for("login"))
    return render_template("email_form.html", title="Wyślij ponownie link aktywacyjny",
                           button="Wyślij link")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = User.query.filter_by(email=email, email_verified=True).first()
        if user:
            token = make_token({"uid": user.id, "pwd": user.password_fingerprint()}, "reset-password")
            send_mail(
                user.email,
                "CyberHackerForum - reset hasła",
                f"Cześć {user.username},\n\nktoś poprosił o reset hasła do Twojego konta. "
                f"Aby ustawić nowe hasło, wejdź w link:\n{external_url('reset_password', token=token)}\n\n"
                f"Link jest ważny 1 godzinę i działa tylko raz. Jeśli to nie Ty, zignoruj tę wiadomość - "
                f"Twoje hasło się nie zmieni.",
            )
            audit("PASSWORD_RESET_REQUEST", user=user.username)
        else:
            audit("PASSWORD_RESET_REQUEST_UNKNOWN", logging.WARNING, email=email)
        flash("Jeśli konto z tym adresem istnieje, wysłaliśmy link do resetu hasła.")
        return redirect(url_for("login"))
    return render_template("email_form.html", title="Nie pamiętasz hasła?",
                           button="Wyślij link resetu")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    data = read_token(token, "reset-password", RESET_TOKEN_MAX_AGE)
    user = db.session.get(User, data["uid"]) if isinstance(data, dict) else None
    # pwd w tokenie musi pasować do obecnego hasła: po użyciu linku hasło się zmienia,
    # więc ten sam link drugi raz już nie zadziała (token jednorazowy bez zapisu w bazie)
    if user is None or data["pwd"] != user.password_fingerprint():
        audit("PASSWORD_RESET_BAD_TOKEN", logging.WARNING,
              reason="expired" if data == "expired" else "invalid_or_used")
        flash("Link resetu jest nieprawidłowy, wygasł albo został już użyty.")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form.get("password", "")
        if password != request.form.get("password2", ""):
            flash("Hasła nie są takie same.")
        elif problems := password_problems(password, user.username):
            flash("Hasło: " + ", ".join(problems) + ".")
        else:
            user.password_hash = hash_password(password)
            user.failed_logins = 0
            user.locked_until = None
            db.session.commit()
            audit("PASSWORD_RESET_OK", user=user.username)
            send_password_changed_mail(user)
            session.clear()
            flash("Hasło zmienione. Zaloguj się nowym hasłem.")
            return redirect(url_for("login"))

    return render_template("reset.html", token=token)


@app.route("/account")
@login_required
def account():
    return render_template("account.html")


@app.route("/account/email", methods=["POST"])
@login_required
def set_email():
    user = current_user()
    email = request.form.get("email", "").strip().lower()
    if not EMAIL_RE.match(email) or len(email) > 254:
        flash("Podaj poprawny adres e-mail.")
    elif User.query.filter(User.email == email, User.id != user.id).first():
        flash("Ten adres e-mail jest już używany.")
    else:
        old = user.email
        user.email = email
        user.email_verified = False
        db.session.commit()
        audit("EMAIL_SET", user=user.username, old=old or "-", new=email)
        send_verification_mail(user)
        flash("Wysłaliśmy link potwierdzający na nowy adres.")
    return redirect(url_for("account"))


@app.route("/account/resend", methods=["POST"])
@login_required
def resend_my_verification():
    user = current_user()
    if user.email and not user.email_verified:
        send_verification_mail(user)
        flash("Wysłaliśmy nowy link potwierdzający.")
    return redirect(url_for("account"))


@app.route("/account/password", methods=["POST"])
@login_required
def change_password():
    user = current_user()
    current = request.form.get("current_password", "")
    new = request.form.get("password", "")
    if not check_password_hash(user.password_hash, current):
        audit("PASSWORD_CHANGE_FAIL", logging.WARNING, reason="bad_current_password")
        flash("Obecne hasło jest nieprawidłowe.")
    elif new != request.form.get("password2", ""):
        flash("Nowe hasła nie są takie same.")
    elif problems := password_problems(new, user.username):
        flash("Hasło: " + ", ".join(problems) + ".")
    else:
        user.password_hash = hash_password(new)
        db.session.commit()
        session["pwd"] = user.password_fingerprint()  # ta sesja zostaje, pozostałe wygasają
        audit("PASSWORD_CHANGE_OK")
        send_password_changed_mail(user)
        flash("Hasło zmienione.")
    return redirect(url_for("account"))


# ---------- FORUM ----------


@app.route("/forum")
@login_required
def forum():
    posts = Post.query.order_by(Post.created_at.desc()).all()
    return render_template("forum.html", posts=posts)


@app.route("/post", methods=["POST"])
@login_required
def add_post():
    content = request.form.get("content", "").strip()
    upload = request.files.get("file")
    has_file = upload is not None and upload.filename != ""

    if not content and not has_file:
        return redirect(url_for("forum"))
    if len(content) > POST_MAX_CHARS:
        flash(f"Post może mieć najwyżej {POST_MAX_CHARS} znaków.")
        return redirect(url_for("forum"))

    attachment = None
    if has_file:
        data = upload.read(MAX_UPLOAD_BYTES + 1)
        ext = detect_type(data)
        if len(data) > MAX_UPLOAD_BYTES:
            reason, msg = "too_large", "Plik jest za duży (limit 5 MB)."
        elif ext is None:
            reason, msg = "type_not_allowed", "Niedozwolony typ pliku. Dozwolone: PNG, JPG, GIF, WEBP, PDF, TXT."
        else:
            reason = None
        if reason:
            audit("UPLOAD_REJECTED", logging.WARNING, reason=reason, filename=upload.filename[:100])
            flash(msg)
            return redirect(url_for("forum"))
        # losowa nazwa w magazynie: nie da się jej zgadnąć ani wstrzyknąć ścieżki (../../)
        stored_name = f"{uuid.uuid4().hex}.{ext}"
        original = secure_filename(upload.filename)[:200] or f"plik.{ext}"
        get_storage().save(stored_name, data, ALLOWED_TYPES[ext])
        attachment = Attachment(stored_name=stored_name, original_name=original,
                                mime_type=ALLOWED_TYPES[ext], size=len(data))

    post = Post(content=content, user_id=session["user_id"])
    if attachment:
        post.attachments.append(attachment)
    db.session.add(post)
    db.session.commit()
    audit("POST_CREATE", post_id=post.id, length=len(content))
    if attachment:
        audit("UPLOAD_OK", post_id=post.id, attachment_id=attachment.id,
              type=attachment.mime_type, size=attachment.size)
    return redirect(url_for("forum"))


@app.route("/files/<int:attachment_id>")
@login_required
def get_file(attachment_id):
    """Pliki są prywatne: dostępne tylko dla zalogowanych, przez ten widok."""
    att = db.get_or_404(Attachment, attachment_id)
    data = get_storage().load(att.stored_name)
    response = send_file(
        BytesIO(data),
        mimetype=att.mime_type,
        # obrazki wyświetlamy w poście, resztę (PDF, TXT) tylko do pobrania
        as_attachment=not att.is_image,
        download_name=att.original_name,
        max_age=0,
    )
    response.headers["Cache-Control"] = "private, no-store"
    # nawet gdyby plik zawierał HTML/JS, przeglądarka go nie wykona
    response.headers["Content-Security-Policy"] = "default-src 'none'; img-src 'self'; sandbox"
    return response


@app.route("/post/<int:post_id>/comment", methods=["POST"])
@login_required
def add_comment(post_id):
    post = db.get_or_404(Post, post_id)
    content = request.form.get("content", "").strip()
    if len(content) > COMMENT_MAX_CHARS:
        flash(f"Komentarz może mieć najwyżej {COMMENT_MAX_CHARS} znaków.")
    elif content:
        comment = Comment(content=content, user_id=session["user_id"], post_id=post.id)
        db.session.add(comment)
        db.session.commit()
        audit("COMMENT_CREATE", comment_id=comment.id, post_id=post.id, length=len(content))
    return redirect(url_for("forum"))


@app.route("/users")
@login_required
def users():
    q = request.args.get("q", "").strip()
    query = User.query
    if not current_user().is_admin:
        # zwykły użytkownik nie widzi kont administratorów na liście ani w wyszukiwarce
        query = query.filter(User.is_admin.is_(False))
    if q:
        # wyszukiwanie fragmentu loginu bez rozróżniania wielkości liter;
        # zapytanie jest parametryzowane przez SQLAlchemy, a autoescape sprawia,
        # że znaki % i _ wpisane przez użytkownika są traktowane dosłownie
        query = query.filter(
            db.func.lower(User.username).contains(q.lower(), autoescape=True)
        )
    return render_template("users.html", users=query.order_by(User.username).all(), q=q)


@app.route("/user/<int:user_id>")
@login_required
def profile(user_id):
    user = db.get_or_404(User, user_id)
    posts = Post.query.filter_by(user_id=user.id).order_by(Post.created_at.desc()).all()
    comments = (
        Comment.query.filter_by(user_id=user.id)
        .order_by(Comment.created_at.desc())
        .all()
    )
    return render_template("profile.html", user=user, posts=posts, comments=comments)


# ---------- AKCJE ADMINA ----------


@app.route("/comment/<int:comment_id>/delete", methods=["POST"])
@admin_required
def delete_comment(comment_id):
    comment = db.get_or_404(Comment, comment_id)
    author, post_id = comment.author.username, comment.post_id
    db.session.delete(comment)
    db.session.commit()
    audit("COMMENT_DELETE", comment_id=comment_id, post_id=post_id, author=author)
    flash("Komentarz usunięty.")
    return redirect(url_for("forum"))


@app.route("/post/<int:post_id>/delete", methods=["POST"])
@admin_required
def delete_post(post_id):
    post = db.get_or_404(Post, post_id)
    author, n_comments = post.author.username, len(post.comments)
    files = [a.stored_name for a in post.attachments]
    db.session.delete(post)  # komentarze i wpisy załączników usuwane razem z postem (cascade)
    db.session.commit()
    for name in files:  # same pliki trzeba usunąć z magazynu osobno
        get_storage().delete(name)
    audit("POST_DELETE", post_id=post_id, author=author, comments_deleted=n_comments,
          files_deleted=len(files))
    flash("Post usunięty razem z komentarzami.")
    return redirect(url_for("forum"))


@app.route("/admin/user/<int:user_id>/ban", methods=["POST"])
@admin_required
def ban_user(user_id):
    user = db.get_or_404(User, user_id)
    if user.is_admin:
        audit("BAN_REJECTED", logging.WARNING, target=user.username, reason="target_is_admin")
        abort(400)  # admina nie można zbanować (także samego siebie)

    duration = request.form.get("duration")
    if duration not in BAN_DURATIONS:
        audit("BAN_REJECTED", logging.WARNING, target=user.username, reason="bad_duration")
        abort(400)

    if BAN_DURATIONS[duration] is None:
        user.banned_permanent = True
        user.banned_until = None
        flash(f"Użytkownik {user.username} zbanowany na stałe.")
    else:
        user.banned_permanent = False
        user.banned_until = utcnow() + BAN_DURATIONS[duration]
        flash(
            f"Użytkownik {user.username} zbanowany do {user.banned_until.strftime('%Y-%m-%d %H:%M')} UTC."
        )
    db.session.commit()
    audit("BAN", logging.WARNING, target=user.username, duration=duration,
          until="permanent" if user.banned_permanent else user.banned_until.strftime("%Y-%m-%d %H:%M"))
    return redirect(url_for("profile", user_id=user.id))


@app.route("/admin/user/<int:user_id>/unban", methods=["POST"])
@admin_required
def unban_user(user_id):
    user = db.get_or_404(User, user_id)
    user.banned_permanent = False
    user.banned_until = None
    db.session.commit()
    audit("UNBAN", target=user.username)
    flash(f"Użytkownik {user.username} odbanowany.")
    return redirect(url_for("profile", user_id=user.id))


# ---------- KOMENDA DO NADANIA ROLI ADMINA (lokalnie) ----------
# Użycie w terminalu:  python -m flask --app app make-admin <login>


@app.cli.command("make-admin")
@click.argument("username")
def make_admin(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        print(f"Nie ma użytkownika '{username}'. Najpierw zarejestruj go na stronie.")
        return
    user.is_admin = True
    db.session.commit()
    audit("ADMIN_GRANTED", user=username, source="cli")
    print(f"Użytkownik '{username}' jest teraz administratorem.")


# ---------- START APLIKACJI ----------

# Kolumny dodane w nowszych wersjach aplikacji: nazwa -> definicja SQL
NEW_USER_COLUMNS = {
    "is_admin": "BOOLEAN NOT NULL DEFAULT FALSE",
    "banned_until": "TIMESTAMP NULL",
    "banned_permanent": "BOOLEAN NOT NULL DEFAULT FALSE",
    "email": "VARCHAR(254) NULL",
    "email_verified": "BOOLEAN NOT NULL DEFAULT FALSE",
    "failed_logins": "INTEGER NOT NULL DEFAULT 0",
    "locked_until": "TIMESTAMP NULL",
}


def upgrade_db():
    """Dopisuje brakujące kolumny do tabeli user, jeśli baza jest ze starszej wersji aplikacji.
    create_all() tworzy tylko brakujące TABELE, nie dodaje KOLUMN do istniejących."""
    existing = [c["name"] for c in db.inspect(db.engine).get_columns("user")]
    table = db.engine.dialect.identifier_preparer.quote(
        "user"
    )  # "user" to słowo zastrzeżone w Postgresie
    for name, definition in NEW_USER_COLUMNS.items():
        if name not in existing:
            try:
                with db.engine.begin() as conn:
                    conn.execute(
                        db.text(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")
                    )
                print(f"Baza zaktualizowana: dodano kolumnę user.{name}")
            except Exception:
                # przy kilku instancjach startujących naraz inna mogła dodać kolumnę pierwsza
                pass
    # unikalny e-mail (wiele NULL-i jest dozwolonych - stare konta bez maila)
    with db.engine.begin() as conn:
        conn.execute(db.text(
            f"CREATE UNIQUE INDEX IF NOT EXISTS ix_user_email ON {table} (email)"
        ))


def promote_admin_from_env():
    """Nadaje rolę admina użytkownikowi podanemu w zmiennej ADMIN_USERNAME (np. w Cloud Run).
    Konto musi już istnieć - zakłada się je normalnie przez stronę rejestracji."""
    username = os.environ.get("ADMIN_USERNAME")
    if not username:
        return
    user = User.query.filter_by(username=username).first()
    if user and not user.is_admin:
        user.is_admin = True
        db.session.commit()
        audit("ADMIN_GRANTED", user=username, source="env ADMIN_USERNAME")
        print(f"Nadano rolę admina użytkownikowi '{username}'")


with app.app_context():
    db.create_all()
    upgrade_db()
    promote_admin_from_env()


if __name__ == "__main__":
    app.run(debug=True)
