import os
import sqlite3
from functools import wraps

from flask import (
    Flask, request, redirect, url_for,
    render_template_string, abort
)
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import (
    generate_password_hash, check_password_hash
)
from markupsafe import escape

# --------------------------------------------------
# 1. Flask configuration
# --------------------------------------------------

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
if not app.config["SECRET_KEY"]:
    raise RuntimeError("Set the SECRET_KEY environment variable")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("HTTPS_ONLY") == "1",
)

CSRFProtect(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"


# --------------------------------------------------
# 2. Database
# --------------------------------------------------

def db():
    conn = sqlite3.connect("guestbook.db")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


with db() as con:
    con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
    """)


# --------------------------------------------------
# 3. User authentication
# --------------------------------------------------

class User(UserMixin):
    def __init__(self, row):
        self.id = row["id"]
        self.username = row["username"]
        self.role = row["role"]


@login_manager.user_loader
def load_user(user_id):
    with db() as con:
        row = con.execute(
            "SELECT * FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()

    return User(row) if row else None


# --------------------------------------------------
# 4. Authorization: administrator only
# --------------------------------------------------

def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if current_user.role != "admin":
            abort(403)
        return view(*args, **kwargs)

    return wrapped


# --------------------------------------------------
# 5. HTML template
# --------------------------------------------------

PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>{{ title }}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>
    <h2>{{ title }}</h2>

    {% if current_user.is_authenticated %}
        <p>
            Logged in as <b>{{ current_user.username }}</b>
            ({{ current_user.role }})
        </p>

        <form method="post" action="{{ url_for('logout') }}">
            <input type="hidden" name="csrf_token"
                   value="{{ csrf_token() }}">
            <button type="submit">Logout</button>
        </form>
        <hr>
    {% endif %}

    {{ body|safe }}
</body>
</html>
"""


def page(title, body, **context):
    rendered_body = render_template_string(body, **context)
    return render_template_string(
        PAGE, title=title, body=rendered_body, **context
    )


# --------------------------------------------------
# 6. Registration
# --------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("guestbook"))

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        if not username or len(username) > 50 or len(password) < 12:
            abort(
                400,
                "Username required; password must be at least 12 characters"
            )

        try:
            with db() as con:
                con.execute(
                    """
                    INSERT INTO users (username, password, role)
                    VALUES (?, ?, ?)
                    """,
                    (
                        username,
                        generate_password_hash(password),
                        "user"
                    )
                )
        except sqlite3.IntegrityError:
            abort(409, "Username already exists")

        return redirect(url_for("login"))

    return page("Register", """
        <form method="post">
            <input type="hidden" name="csrf_token"
                   value="{{ csrf_token() }}">

            <p>
                <input name="username" maxlength="50"
                       required placeholder="Username">
            </p>

            <p>
                <input name="password" type="password"
                       minlength="12" required
                       placeholder="Password (12+ characters)">
            </p>

            <button type="submit">Register</button>
        </form>

        <a href="{{ url_for('login') }}">Login</a>
    """)


# --------------------------------------------------
# 7. Login
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("guestbook"))

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        with db() as con:
            row = con.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,)
            ).fetchone()

        if row and check_password_hash(row["password"], password):
            login_user(User(row))
            return redirect(url_for("guestbook"))

        abort(401, "Invalid username or password")

    return page("Login", """
        <form method="post">
            <input type="hidden" name="csrf_token"
                   value="{{ csrf_token() }}">

            <p>
                <input name="username" required
                       placeholder="Username">
            </p>

            <p>
                <input name="password" type="password"
                       required placeholder="Password">
            </p>

            <button type="submit">Login</button>
        </form>

        <a href="{{ url_for('register') }}">Register</a>
    """)


# --------------------------------------------------
# 8. Logout
# --------------------------------------------------

@app.post("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


# --------------------------------------------------
# 9. Guestbook
# --------------------------------------------------

@app.route("/", methods=["GET", "POST"])
@login_required
def guestbook():
    if request.method == "POST":
        message = request.form["message"].strip()

        if not message or len(message) > 500:
            abort(400, "Message must contain 1–500 characters")

        with db() as con:
            con.execute(
                """
                INSERT INTO messages (user_id, message)
                VALUES (?, ?)
                """,
                (current_user.id, message)
            )

        return redirect(url_for("guestbook"))

    with db() as con:
        messages = con.execute("""
            SELECT users.username, messages.message
            FROM messages
            JOIN users ON users.id = messages.user_id
            ORDER BY messages.id DESC
        """).fetchall()

    items = "".join(
        f"<li><b>{escape(m['username'])}</b>: "
        f"{escape(m['message'])}</li>"
        for m in messages
    )

    return page("Guestbook", f"""
        <form method="post">
            <input type="hidden" name="csrf_token"
                   value="{{{{ csrf_token() }}}}">

            <input name="message" maxlength="500"
                   required placeholder="Your message">

            <button type="submit">Post</button>
        </form>

        <h3>Messages</h3>
        <ul>{items}</ul>

        <a href="{{{{ url_for('admin') }}}}">Admin page</a>
    """)


# --------------------------------------------------
# 10. Administrator page
# --------------------------------------------------

@app.get("/admin")
@admin_required
def admin():
    return page(
        "Admin",
        "<p>Authorized administrator only.</p>"
    )


# --------------------------------------------------
# 11. Start web server
# --------------------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
