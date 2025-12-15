import sqlite3
from werkzeug.security import generate_password_hash
import getpass

DB_NAME = "database.db"

def create_user(username, password, role="user"):
    password_hash = generate_password_hash(password)

    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()

    try:
        cur.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, password_hash, role)
        )
        conn.commit()
        print(f"ユーザー '{username}' を作成しました（role={role}）")
    except sqlite3.IntegrityError:
        print("そのユーザー名は既に存在します")
    finally:
        conn.close()

if __name__ == "__main__":
    print("=== 新規ユーザー作成 ===")

    username = input("ユーザー名: ").strip()
    password = getpass.getpass("パスワード: ")
    password_confirm = getpass.getpass("パスワード（確認）: ")

    if password != password_confirm:
        print("パスワードが一致しません")
        exit(1)

    role = input("role (admin/user) [user]: ").strip() or "user"
    if role not in ("admin", "user"):
        print("role は admin または user です")
        exit(1)

    create_user(username, password, role)