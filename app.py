# ================================================================
#  KENYANKRABZ BARISTA INTELLIGENCE SYSTEM — LEVEL 9 BACKEND
#  Multi-user • Admin • Logs • Export • ML-Ready API Hooks
# ================================================================

from flask import Flask, render_template, request, redirect, jsonify, session
import sqlite3, os, json
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "kenyankrabz_barista_secret_2025"

DB = "barista.db"


# ---------------------------------------------------------------
#  DB CONNECTION
# ---------------------------------------------------------------
def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------
#  INITIALIZE DATABASE
# ---------------------------------------------------------------
def init_db():
    conn = db()
    cur = conn.cursor()

    # Users
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        is_admin INTEGER DEFAULT 0,
        banned INTEGER DEFAULT 0
    );
    """)

    # Espresso
    cur.execute("""
    CREATE TABLE IF NOT EXISTS espresso(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        coffee TEXT,
        dose REAL,
        yield_out REAL,
        time_sec REAL,
        grind TEXT,
        temp REAL,
        pressure REAL,
        notes TEXT,
        diagnostics TEXT,
        timestamp TEXT
    );
    """)

    # V60
    cur.execute("""
    CREATE TABLE IF NOT EXISTS v60(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        coffee TEXT,
        dose REAL,
        water REAL,
        ratio TEXT,
        grind TEXT,
        temp REAL,
        bloom_weight REAL,
        bloom_time REAL,
        pours TEXT,
        drawdown REAL,
        notes TEXT,
        rating INTEGER,
        timestamp TEXT
    );
    """)

    # Milk
    cur.execute("""
    CREATE TABLE IF NOT EXISTS milk(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        milk_type TEXT,
        pitcher TEXT,
        stretch_time REAL,
        target_temp REAL,
        art_shape TEXT,
        notes TEXT,
        timestamp TEXT
    );
    """)

    # Water
    cur.execute("""
    CREATE TABLE IF NOT EXISTS water(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        gh REAL,
        kh REAL,
        tds REAL,
        additives TEXT,
        notes TEXT,
        timestamp TEXT
    );
    """)

    # Journal
    cur.execute("""
    CREATE TABLE IF NOT EXISTS journal(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        title TEXT,
        body TEXT,
        tags TEXT,
        timestamp TEXT
    );
    """)

    conn.commit()
    conn.close()

init_db()


# ---------------------------------------------------------------
#  LOGIN CHECK
# ---------------------------------------------------------------
def require_login():
    return "user_id" in session


# ---------------------------------------------------------------
#  REGISTER
# ---------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = generate_password_hash(request.form["password"])

        try:
            conn = db()
            conn.execute(
                "INSERT INTO users(username,password) VALUES(?,?)",
                (username, password)
            )
            conn.commit()
        except:
            return "Username already exists"

        return redirect("/login")

    return render_template("login.html", mode="register")


# ---------------------------------------------------------------
#  LOGIN
# ---------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        conn = db()
        user = conn.execute(
            "SELECT * FROM users WHERE username=?",
            (username,)
        ).fetchone()

        if not user:
            return "Invalid username"

        if not check_password_hash(user["password"], password):
            return "Invalid password"

        if user["banned"] == 1:
            return "You are banned."

        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["admin"] = user["is_admin"]

        return redirect("/")

    return render_template("login.html", mode="login")


# ---------------------------------------------------------------
#  LOGOUT
# ---------------------------------------------------------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# ---------------------------------------------------------------
#  HOME — LOAD USER DATA
# ---------------------------------------------------------------
@app.route("/")
def home():
    if not require_login():
        return redirect("/login")

    uid = session["user_id"]
    conn = db()

    espresso = conn.execute("SELECT * FROM espresso WHERE user_id=? ORDER BY id DESC", (uid,)).fetchall()
    v60 = conn.execute("SELECT * FROM v60 WHERE user_id=? ORDER BY id DESC", (uid,)).fetchall()
    milk = conn.execute("SELECT * FROM milk WHERE user_id=? ORDER BY id DESC", (uid,)).fetchall()
    water = conn.execute("SELECT * FROM water WHERE user_id=? ORDER BY id DESC", (uid,)).fetchall()
    journal = conn.execute("SELECT * FROM journal WHERE user_id=? ORDER BY id DESC", (uid,)).fetchall()

    return render_template(
        "index.html",
        espresso=[dict(x) for x in espresso],
        v60=[dict(x) for x in v60],
        milk=[dict(x) for x in milk],
        water=[dict(x) for x in water],
        journal=[dict(x) for x in journal]
    )


# ---------------------------------------------------------------
#  ADD ENTRIES
# ---------------------------------------------------------------
@app.route("/espresso/add", methods=["POST"])
def add_espresso():
    if not require_login(): return redirect("/login")
    uid = session["user_id"]
    f = request.form

    # Diagnosis
    try:
        ratio = float(f["yield"]) / float(f["dose"])
        if ratio < 1.6:
            diag = "Under Extracted"
        elif ratio > 2.4:
            diag = "Over Extracted"
        else:
            diag = "Balanced"
    except:
        diag = "N/A"

    conn = db()
    conn.execute("""
        INSERT INTO espresso(user_id,coffee,dose,yield_out,time_sec,grind,temp,pressure,notes,diagnostics,timestamp)
        VALUES(?,?,?,?,?,?,?,?,?,?,?)
    """, (
        uid, f["coffee"], f["dose"], f["yield"], f["time"],
        f["grind"], f["temp"], f["pressure"], f["notes"], diag,
        datetime.now().isoformat()
    ))
    conn.commit()
    return redirect("/")


@app.route("/v60/add", methods=["POST"])
def add_v60():
    if not require_login(): return redirect("/login")
    uid = session["user_id"]
    f = request.form
    conn = db()
    conn.execute("""
        INSERT INTO v60(user_id,coffee,dose,water,ratio,grind,temp,bloom_weight,bloom_time,pours,drawdown,notes,rating,timestamp)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        uid, f["coffee"], f["dose"], f["water"], f["ratio"], f["grind"],
        f["temp"], f["bloom_weight"], f["bloom_time"], f["pours"],
        f["drawdown"], f["notes"], f["rating"], datetime.now().isoformat()
    ))
    conn.commit()
    return redirect("/")


@app.route("/milk/add", methods=["POST"])
def add_milk():
    if not require_login(): return redirect("/login")
    uid = session["user_id"]
    f = request.form
    conn = db()
    conn.execute("""
        INSERT INTO milk(user_id,milk_type,pitcher,stretch_time,target_temp,art_shape,notes,timestamp)
        VALUES(?,?,?,?,?,?,?,?)
    """, (
        uid, f["milk_type"], f["pitcher"], f["stretch_time"], f["target_temp"],
        f["art_shape"], f["notes"], datetime.now().isoformat()
    ))
    conn.commit()
    return redirect("/")


@app.route("/water/add", methods=["POST"])
def add_water():
    if not require_login(): return redirect("/login")
    uid = session["user_id"]
    f = request.form
    conn = db()
    conn.execute("""
        INSERT INTO water(user_id,gh,kh,tds,additives,notes,timestamp)
        VALUES(?,?,?,?,?,?,?)
    """, (
        uid, f["gh"], f["kh"], f["tds"], f["additives"], f["notes"],
        datetime.now().isoformat()
    ))
    conn.commit()
    return redirect("/")


@app.route("/journal/add", methods=["POST"])
def add_journal():
    if not require_login(): return redirect("/login")
    uid = session["user_id"]
    f = request.form
    conn = db()
    conn.execute("""
        INSERT INTO journal(user_id,title,body,tags,timestamp)
        VALUES(?,?,?,?,?)
    """, (
        uid, f["title"], f["body"], f["tags"],
        datetime.now().isoformat()
    ))
    conn.commit()
    return redirect("/")


# ---------------------------------------------------------------
#  EXPORT USER DATA (JSON)
# ---------------------------------------------------------------
@app.route("/export")
def export_user():
    if not require_login(): return redirect("/login")

    uid = session["user_id"]
    conn = db()

    result = {
        "espresso": [dict(x) for x in conn.execute("SELECT * FROM espresso WHERE user_id=?", (uid,)).fetchall()],
        "v60": [dict(x) for x in conn.execute("SELECT * FROM v60 WHERE user_id=?", (uid,)).fetchall()],
        "milk": [dict(x) for x in conn.execute("SELECT * FROM milk WHERE user_id=?", (uid,)).fetchall()],
        "water": [dict(x) for x in conn.execute("SELECT * FROM water WHERE user_id=?", (uid,)).fetchall()],
        "journal": [dict(x) for x in conn.execute("SELECT * FROM journal WHERE user_id=?", (uid,)).fetchall()]
    }

    return jsonify(result)


# ---------------------------------------------------------------
#  ADMIN PANEL
# ---------------------------------------------------------------
@app.route("/admin")
def admin():
    if session.get("admin") != 1:
        return "Unauthorized"

    conn = db()
    users = conn.execute("SELECT * FROM users").fetchall()
    espresso = conn.execute("SELECT * FROM espresso").fetchall()
    v60 = conn.execute("SELECT * FROM v60").fetchall()
    milk = conn.execute("SELECT * FROM milk").fetchall()
    water = conn.execute("SELECT * FROM water").fetchall()
    journal = conn.execute("SELECT * FROM journal").fetchall()

    return render_template(
        "admin.html",
        users=users,
        espresso=espresso,
        v60=v60,
        milk=milk,
        water=water,
        journal=journal
    )


@app.route("/admin/ban/<uid>")
def admin_ban(uid):
    if session.get("admin") != 1: return "Unauthorized"
    conn = db()
    conn.execute("UPDATE users SET banned=1 WHERE id=?", (uid,))
    conn.commit()
    return redirect("/admin")


@app.route("/admin/unban/<uid>")
def admin_unban(uid):
    if session.get("admin") != 1: return "Unauthorized"
    conn = db()
    conn.execute("UPDATE users SET banned=0 WHERE id=?", (uid,))
    conn.commit()
    return redirect("/admin")


@app.route("/admin/delete/<table>/<row_id>")
def admin_delete(table, row_id):
    if session.get("admin") != 1:
        return "Unauthorized"
    conn = db()
    conn.execute(f"DELETE FROM {table} WHERE id=?", (row_id,))
    conn.commit()
    return redirect("/admin")


# ---------------------------------------------------------------
#  LEVEL-9 ML HOOK (placeholder for future upgrades)
# ---------------------------------------------------------------
@app.route("/ml/upload", methods=["POST"])
def upload_ml_frame():
    """
    Placeholder endpoint for Level-10:
    - Real extraction AI
    - Flow-rate ML
    - Crema histogram ML
    """
    return jsonify({"status": "ok", "message": "ML frame received"})


# ---------------------------------------------------------------
#  RUN APP
# ---------------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)
