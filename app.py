import os
from datetime import datetime, timedelta, timezone
from functools import wraps

import click
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Klucz do podpisywania ciasteczka sesji. Lokalnie wystarczy wartość domyślna,
# w chmurze ustawiamy go przez zmienną środowiskową SECRET_KEY.
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-tylko-lokalnie")

# Adres bazy danych. Lokalnie: plik SQLite. W chmurze można podać inną bazę przez DATABASE_URL.
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///forum.db")

db = SQLAlchemy(app)


def utcnow():
    """Aktualny czas UTC bez strefy (tak przechowujemy daty w bazie)."""
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
    is_admin = db.Column(db.Boolean, default=False, nullable=False)          # rola moderatora
    banned_until = db.Column(db.DateTime, nullable=True)                     # ban czasowy (do kiedy, UTC)
    banned_permanent = db.Column(db.Boolean, default=False, nullable=False)  # ban na stałe

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
    comments = db.relationship("Comment", backref="post", order_by="Comment.created_at",
                               cascade="all, delete-orphan")


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
    Zbanowany użytkownik jest od razu wylogowywany - ban działa także na otwarte sesje."""
    if "user_id" not in session:
        return None
    user = db.session.get(User, session["user_id"])
    if user is None or user.is_banned():
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

        # Sprawdzenie bez rozróżniania wielkości liter: "Admin" i "admin" to ten sam login
        taken = User.query.filter(db.func.lower(User.username) == username.lower()).first()

        if not username or not password:
            flash("Podaj login i hasło.")
        elif taken:
            flash("Taki użytkownik już istnieje.")
        else:
            user = User(username=username, password_hash=generate_password_hash(password))
            db.session.add(user)
            db.session.commit()
            flash("Konto utworzone, możesz się zalogować.")
            return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(username=request.form["username"].strip()).first()

        if user and check_password_hash(user.password_hash, request.form["password"]):
            if user.is_banned():
                flash(user.ban_message())
                return render_template("login.html")
            session["user_id"] = user.id
            session["username"] = user.username
            return redirect(url_for("forum"))

        flash("Błędny login lub hasło.")

    return render_template("login.html")


@app.route("/logout")
def logout():
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
        db.session.add(Post(content=content, user_id=session["user_id"]))
        db.session.commit()
    return redirect(url_for("forum"))


@app.route("/post/<int:post_id>/comment", methods=["POST"])
@login_required
def add_comment(post_id):
    post = db.get_or_404(Post, post_id)
    content = request.form["content"].strip()
    if content:
        db.session.add(Comment(content=content, user_id=session["user_id"], post_id=post.id))
        db.session.commit()
    return redirect(url_for("forum"))


@app.route("/users")
@login_required
def users():
    q = request.args.get("q", "").strip()
    query = User.query
    if q:
        # wyszukiwanie fragmentu loginu bez rozróżniania wielkości liter;
        # zapytanie jest parametryzowane przez SQLAlchemy, a autoescape sprawia,
        # że znaki % i _ wpisane przez użytkownika są traktowane dosłownie
        query = query.filter(db.func.lower(User.username).contains(q.lower(), autoescape=True))
    return render_template("users.html", users=query.order_by(User.username).all(), q=q)


@app.route("/user/<int:user_id>")
@login_required
def profile(user_id):
    user = db.get_or_404(User, user_id)
    posts = Post.query.filter_by(user_id=user.id).order_by(Post.created_at.desc()).all()
    comments = Comment.query.filter_by(user_id=user.id).order_by(Comment.created_at.desc()).all()
    return render_template("profile.html", user=user, posts=posts, comments=comments)


# ---------- AKCJE ADMINA ----------

@app.route("/comment/<int:comment_id>/delete", methods=["POST"])
@admin_required
def delete_comment(comment_id):
    comment = db.get_or_404(Comment, comment_id)
    db.session.delete(comment)
    db.session.commit()
    flash("Komentarz usunięty.")
    return redirect(url_for("forum"))


@app.route("/post/<int:post_id>/delete", methods=["POST"])
@admin_required
def delete_post(post_id):
    post = db.get_or_404(Post, post_id)
    db.session.delete(post)  # komentarze usuwane razem z postem (cascade)
    db.session.commit()
    flash("Post usunięty razem z komentarzami.")
    return redirect(url_for("forum"))


@app.route("/admin/user/<int:user_id>/ban", methods=["POST"])
@admin_required
def ban_user(user_id):
    user = db.get_or_404(User, user_id)
    if user.is_admin:
        abort(400)  # admina nie można zbanować (także samego siebie)

    duration = request.form.get("duration")
    if duration not in BAN_DURATIONS:
        abort(400)

    if BAN_DURATIONS[duration] is None:
        user.banned_permanent = True
        user.banned_until = None
        flash(f"Użytkownik {user.username} zbanowany na stałe.")
    else:
        user.banned_permanent = False
        user.banned_until = utcnow() + BAN_DURATIONS[duration]
        flash(f"Użytkownik {user.username} zbanowany do {user.banned_until.strftime('%Y-%m-%d %H:%M')} UTC.")
    db.session.commit()
    return redirect(url_for("profile", user_id=user.id))


@app.route("/admin/user/<int:user_id>/unban", methods=["POST"])
@admin_required
def unban_user(user_id):
    user = db.get_or_404(User, user_id)
    user.banned_permanent = False
    user.banned_until = None
    db.session.commit()
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
    table = db.engine.dialect.identifier_preparer.quote("user")  # "user" to słowo zastrzeżone w Postgresie
    with db.engine.begin() as conn:
        for name, definition in NEW_USER_COLUMNS.items():
            if name not in existing:
                conn.execute(db.text(f"ALTER TABLE {table} ADD COLUMN {name} {definition}"))
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
        print(f"Nadano rolę admina użytkownikowi '{username}'")


with app.app_context():
    db.create_all()
    upgrade_db()
    promote_admin_from_env()


if __name__ == "__main__":
    app.run(debug=True)
