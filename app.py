import os
from datetime import datetime, timezone
from functools import wraps

import click
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Klucz do podpisywania ciasteczka sesji. Lokalnie wystarczy wartość domyślna,
# w chmurze ustawimy go przez zmienną środowiskową.
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-tylko-lokalnie")

# Adres bazy danych. Lokalnie: plik SQLite. W chmurze podmienimy go na Cloud SQL.
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///forum.db")

db = SQLAlchemy(app)


# ---------- MODELE (tabele w bazie) ----------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)  # rola moderatora


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    author = db.relationship("User")
    # komentarze pod postem, posortowane od najstarszego
    comments = db.relationship("Comment", backref="post", order_by="Comment.created_at",
                               cascade="all, delete-orphan")


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey("post.id"), nullable=False)
    author = db.relationship("User")


# ---------- POMOCNICZE ----------

def current_user():
    """Zwraca zalogowanego użytkownika pobranego z bazy (albo None)."""
    if "user_id" not in session:
        return None
    return db.session.get(User, session["user_id"])


def login_required(view):
    """Dekorator: wpuszcza tylko zalogowanych."""
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

        if not username or not password:
            flash("Podaj login i hasło.")
        elif User.query.filter_by(username=username).first():
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


@app.route("/comment/<int:comment_id>/delete", methods=["POST"])
@admin_required
def delete_comment(comment_id):
    comment = db.get_or_404(Comment, comment_id)
    db.session.delete(comment)
    db.session.commit()
    flash("Komentarz usunięty.")
    return redirect(url_for("forum"))


# ---------- KOMENDA DO NADANIA ROLI ADMINA ----------
# Użycie w terminalu:  flask --app app make-admin <login>

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


def upgrade_db():
    """Dopisuje kolumnę is_admin do tabeli user, jeśli baza jest ze starej wersji aplikacji.
    create_all() tworzy tylko brakujące TABELE, nie dodaje KOLUMN do istniejących."""
    columns = [c["name"] for c in db.inspect(db.engine).get_columns("user")]
    if "is_admin" not in columns:
        table = db.engine.dialect.identifier_preparer.quote("user")  # "user" to słowo zastrzeżone w Postgresie
        with db.engine.begin() as conn:
            conn.execute(db.text(f"ALTER TABLE {table} ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT FALSE"))
        print("Baza zaktualizowana: dodano kolumnę user.is_admin")


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


# Przy starcie: utworzenie brakujących tabel, aktualizacja starej bazy, nadanie roli admina
with app.app_context():
    db.create_all()
    upgrade_db()
    promote_admin_from_env()


if __name__ == "__main__":
    app.run(debug=True)
