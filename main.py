import sqlite3
import random, string
from flask import Flask, make_response, request, redirect, render_template
from werkzeug.security import generate_password_hash, check_password_hash
import markdown
import bleach
from waitress import serve

# DB初期化
def init_db():
    conn = sqlite3.connect("database.db")
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT DEFAULT 'user'
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session TEXT UNIQUE,
            username TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            code TEXT UNIQUE,
            title TEXT,
            text TEXT
        )
    """)

    conn.commit()
    conn.close()

init_db()

# Flask
app = Flask(__name__, static_folder="static", template_folder="templates")

def generate_code(length=32):
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))

# 認証ヘルパー
def get_login_user():
    session = request.cookies.get("session")
    if not session:
        return None

    conn = sqlite3.connect("database.db")
    cur = conn.cursor()
    cur.execute("""
        SELECT users.username, users.role
        FROM sessions
        JOIN users ON sessions.username = users.username
        WHERE sessions.session=?
    """, (session,))
    user = cur.fetchone()
    conn.close()
    return user  # (username, role) or None

def require_admin():
    user = get_login_user()
    return user and user[1] == "admin"

# ルート
@app.get("/")
def index():
    conn = sqlite3.connect("database.db")
    cur = conn.cursor()
    cur.execute("SELECT code, title, username FROM reports ORDER BY id DESC")
    reports = cur.fetchall()
    conn.close()

    return render_template("index.html", reports=reports)

# 記事詳細（Markdown）
@app.get("/report/<code>")
def report_detail(code):
    conn = sqlite3.connect("database.db")
    cur = conn.cursor()
    cur.execute(
        "SELECT title, text, username FROM reports WHERE code=?",
        (code,)
    )
    report = cur.fetchone()
    conn.close()

    if not report:
        return "記事が見つかりません"

    html = markdown.markdown(
        report[1],
        extensions=["fenced_code", "tables"]
    )

    allowed_tags = set(bleach.sanitizer.ALLOWED_TAGS)
    allowed_tags.update([
        "p", "pre", "code",
        "h1", "h2", "h3",
        "table", "tr", "td", "th"
    ])

    html = bleach.clean(
        html,
        tags=allowed_tags,
        strip=True
    )

    # print(html)

    user = get_login_user()

    return render_template(
        "report.html",
        title=report[0],
        html=html,
        author=report[2],
        code=code,
        is_admin=(user and user[1] == "admin")
    )

# ログイン / ログアウト
@app.get("/login")
def login():
    return render_template("login.html")

@app.post("/login/callback")
def login_callback():
    username = request.form["name"]
    password = request.form["password"]

    conn = sqlite3.connect("database.db")
    cur = conn.cursor()
    cur.execute(
        "SELECT username, password FROM users WHERE username=?",
        (username,)
    )
    user = cur.fetchone()
    conn.close()

    if not user or not check_password_hash(user[1], password):
        return "ユーザー名またはパスワードが違います"

    session_code = generate_code()

    conn = sqlite3.connect("database.db")
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO sessions (session, username) VALUES (?, ?)",
        (session_code, user[0])
    )
    conn.commit()
    conn.close()

    response = make_response(redirect("/admin/panel"))
    response.set_cookie(
        "session",
        session_code,
        max_age=3600,
        httponly=True,
        samesite="Lax"
    )
    return response

@app.get("/logout")
def logout():
    response = make_response(redirect("/"))
    response.delete_cookie("session")
    return response

# 管理画面
@app.get("/admin/panel")
def admin_panel():
    if not require_admin():
        return "権限がありません"
    return render_template("admin.html")

@app.post("/admin/create")
def admin_create():
    user = get_login_user()
    if not user or user[1] != "admin":
        return "権限がありません"

    title = request.form["title"]
    text = request.form["text"]
    code = generate_code(12)

    conn = sqlite3.connect("database.db")
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO reports (username, code, title, text) VALUES (?, ?, ?, ?)",
        (user[0], code, title, text)
    )
    conn.commit()
    conn.close()

    return redirect("/")

@app.post("/admin/delete/<code>")
def admin_delete(code):
    if not require_admin():
        return "権限がありません"

    conn = sqlite3.connect("database.db")
    cur = conn.cursor()
    cur.execute("DELETE FROM reports WHERE code=?", (code,))
    conn.commit()
    conn.close()

    return redirect("/")

# 起動
if __name__ == "__main__":
    # app.run("0.0.0.0", port=5008, debug=True)
    serve(app, host='0.0.0.0', port=5008)