import os
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Klucz do podpisywania ciasteczka sesji. Lokalnie wystarczy wartość domyślna,
# w chmurze (L3/L4) ustawimy go przez zmienną środowiskową.
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-tylko-lokalnie")

# Adres bazy danych. Lokalnie: plik SQLite. W chmurze podmienimy go na Cloud SQL
# (np. postgresql://user:haslo@host/db) bez zmiany reszty kodu.
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///forum.db")

db = SQLAlchemy(app)


# ---------- MODELE (tabele w bazie) ----------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    author = db.relationship("User")


# ---------- POMOCNICZE ----------

def login_required(view):
    """Dekorator: wpuszcza tylko zalogowanych (czyli tych, którzy mają user_id w sesji)."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


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


@app.route("/forum", methods=["GET", "POST"])
@login_required
def forum():
    if request.method == "POST":
        content = request.form["content"].strip()
        if content:
            db.session.add(Post(content=content, user_id=session["user_id"]))
            db.session.commit()
        return redirect(url_for("forum"))

    posts = Post.query.order_by(Post.created_at.desc()).all()
    return render_template("forum.html", posts=posts)


# Utworzenie tabel przy starcie (jeśli jeszcze nie istnieją)
with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(debug=True)
