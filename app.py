import json
import logging
import os
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta, timezone
from functools import wraps

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
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)

# Klucz do podpisywania cookie sesji, SECRET_KEY = zmienna środowiskowa w chmurze
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-tylko-lokalnie")

# Adres bazy danych. Lokalnie: plik SQLite. DATABASE_URL = zmienna środowiskowa w chmurze.
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "sqlite:///forum.db"
)

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

    def ban_active(self):
        """Czy trwa ban czasowy."""
        return self.banned_until is not None and self.banned_until > utcnow()

    def is_banned(self):
        return self.banned_permanent or self.ban_active()

    def ban_message(self):
        if self.banned_permanent:
            return "Twoje konto zostało zablokowane na stałe."
        return f"Twoje konto jest zablokowane do {self.banned_until.strftime('%Y-%m-%d %H:%M')} UTC."


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


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey("post.id"), nullable=False)
    author = db.relationship("User")

# ---------- POMOCNICZE ----------


def current_user():
    """Zwraca zalogowanego użytkownika z bazy (albo None).
    Zbanowany użytkownik jest od razu wylogowywany, ban działa także na otwarte sesje.
    """
    if "user_id" not in session:
        return None
    user = db.session.get(User, session["user_id"])
    if user is None or user.is_banned():
        if user is not None:
            audit("SESSION_TERMINATED_BANNED", logging.WARNING, user=user.username)
        session.clear()
        return None
    return user


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


@app.context_processor
def inject_user():
    """Udostępnia zalogowanego użytkownika we wszystkich szablonach jako `me`."""
    return {"me": current_user()}


# ---------- WIDOKI (adresy URL) ----------


@app.route("/")
def index():
    return redirect(url_for("forum") if "user_id" in session else url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        # Sprawdzenie bez rozróżniania wielkości liter
        taken = User.query.filter(
            db.func.lower(User.username) == username.lower()
        ).first()

        if not username or not password:
            flash("Podaj login i hasło.")
            audit("REGISTER_FAIL", logging.WARNING, user=username, reason="empty_fields")
        elif taken:
            flash("Taki użytkownik już istnieje.")
            audit("REGISTER_FAIL", logging.WARNING, user=username, reason="username_taken")
        else:
            user = User(
                username=username, password_hash=generate_password_hash(password)
            )
            db.session.add(user)
            db.session.commit()
            audit("REGISTER_OK", user=user.username, user_id=user.id)
            flash("Konto utworzone, możesz się zalogować.")
            return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, request.form["password"]):
            if user.is_banned():
                audit("LOGIN_BLOCKED_BANNED", logging.WARNING, user=user.username)
                flash(user.ban_message())
                return render_template("login.html")
            session["user_id"] = user.id
            session["username"] = user.username
            audit("LOGIN_OK", user=user.username, admin=user.is_admin)
            return redirect(url_for("forum"))

        audit("LOGIN_FAIL", logging.WARNING, user=username,
              reason="bad_password" if user else "unknown_user")
        flash("Błędny login lub hasło.")

    return render_template("login.html")


@app.route("/logout")
def logout():
    if "user_id" in session:
        audit("LOGOUT")
    session.clear()
    return redirect(url_for("login"))


@app.route("/forum")
@login_required
def forum():
    posts = Post.query.order_by(Post.created_at.desc()).all()
    return render_template("forum.html", posts=posts)


@app.route("/post", methods=["POST"])
@login_required
def add_post():
    content = request.form["content"].strip()
    if content:
        post = Post(content=content, user_id=session["user_id"])
        db.session.add(post)
        db.session.commit()
        audit("POST_CREATE", post_id=post.id, length=len(content))
    return redirect(url_for("forum"))


@app.route("/post/<int:post_id>/comment", methods=["POST"])
@login_required
def add_comment(post_id):
    post = db.get_or_404(Post, post_id)
    content = request.form["content"].strip()
    if content:
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
    db.session.delete(post)  # komentarze usuwane razem z postem (cascade)
    db.session.commit()
    audit("POST_DELETE", post_id=post_id, author=author, comments_deleted=n_comments)
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
}


def upgrade_db():
    """Dopisuje brakujące kolumny do tabeli user, jeśli baza jest ze starszej wersji aplikacji.
    create_all() tworzy tylko brakujące TABELE, nie dodaje KOLUMN do istniejących."""
    existing = [c["name"] for c in db.inspect(db.engine).get_columns("user")]
    table = db.engine.dialect.identifier_preparer.quote(
        "user"
    )  # "user" to słowo zastrzeżone w Postgresie
    with db.engine.begin() as conn:
        for name, definition in NEW_USER_COLUMNS.items():
            if name not in existing:
                conn.execute(
                    db.text(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")
                )
                print(f"Baza zaktualizowana: dodano kolumnę user.{name}")


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
