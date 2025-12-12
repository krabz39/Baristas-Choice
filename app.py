# ================================================================
#  KENYANKRABZ BARISTA INTELLIGENCE SYSTEM — LEVEL 11 BACKEND
#  Inline errors • Super Admin • Admin • Logs • Export • ML Hooks
#  Postgres Edition (persistent DB)
# ================================================================

from flask import Flask, render_template, request, redirect, jsonify, session
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
import psycopg2.extras
import os

app = Flask(__name__)
app.secret_key = "kenyankrabz_barista_secret_2025"

# ----------------------------------------------------------------
# DATABASE CONFIG (Postgres)
# ----------------------------------------------------------------
# Example env var (Render/Neon gives you this):
# DATABASE_URL = "postgresql://user:password@host:port/dbname"
DB_URL = os.getenv("DATABASE_URL")

if not DB_URL:
    raise RuntimeError(
        "DATABASE_URL environment variable is not set. "
        "Set it to your Postgres connection string."
    )


def db():
    """Get a new Postgres connection with dict-style rows."""
    return psycopg2.connect(
        DB_URL,
        cursor_factory=psycopg2.extras.RealDictCursor
    )


# ----------------------------------------------------------------
# INIT DB (CREATE TABLES IF NOT EXISTS)
# ----------------------------------------------------------------
def init_db():
    conn = db()
    cur = conn.cursor()

    # Users
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        is_admin INTEGER DEFAULT 0,
        banned INTEGER DEFAULT 0
    );
    """)

    # Espresso
    cur.execute("""
    CREATE TABLE IF NOT EXISTS espresso(
        id SERIAL PRIMARY KEY,
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
        id SERIAL PRIMARY KEY,
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
        id SERIAL PRIMARY KEY,
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
        id SERIAL PRIMARY KEY,
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
        id SERIAL PRIMARY KEY,
        user_id INTEGER,
        title TEXT,
        body TEXT,
        tags TEXT,
        timestamp TEXT
    );
    """)

    conn.commit()
    cur.close()
    conn.close()


init_db()


# ----------------------------------------------------------------
# CREATE SUPER ADMIN (username = kenyankrabz)
# ----------------------------------------------------------------
def create_default_super_admin():
    conn = db()
    cur = conn.cursor()

    cur.execute(
        "SELECT * FROM users WHERE username = %s",
        ("kenyankrabz",)
    )
    existing = cur.fetchone()

    if not existing:
        cur.execute(
            """
            INSERT INTO users(username, password, is_admin)
            VALUES(%s, %s, 2)
            """,
            (
                "kenyankrabz",
                generate_password_hash("krabz2025")
            )
        )
        conn.commit()

    cur.close()
    conn.close()


create_default_super_admin()


# ----------------------------------------------------------------
# LOGIN CHECK
# ----------------------------------------------------------------
def require_login():
    return session.get("user_id") is not None


# ----------------------------------------------------------------
# REGISTER (with inline errors)
# ----------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    error = None

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()

        if len(username) < 3:
            error = "⚠ Username must be at least 3 characters."
            return render_template("login.html", mode="register", error=error)

        if len(password) < 4:
            error = "⚠ Password too short."
            return render_template("login.html", mode="register", error=error)

        try:
            conn = db()
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO users(username,password) VALUES(%s,%s)",
                (username, generate_password_hash(password))
            )
            conn.commit()
            cur.close()
            conn.close()
        except Exception:
            error = "❌ Username already taken"
            return render_template("login.html", mode="register", error=error)

        return redirect("/login")

    return render_template("login.html", mode="register")


# ----------------------------------------------------------------
# LOGIN (inline errors + no redirect error page)
# ----------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        conn = db()
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM users WHERE username=%s",
            (username,)
        )
        user = cur.fetchone()
        cur.close()
        conn.close()

        if not user:
            error = "❌ No account with that username."
            return render_template("login.html", mode="login", error=error)

        if not check_password_hash(user["password"], password):
            error = "❌ Incorrect password."
            return render_template("login.html", mode="login", error=error)

        if user["banned"] == 1:
            error = "⛔ Your account is banned."
            return render_template("login.html", mode="login", error=error)

        # SUCCESS LOGIN
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["admin"] = user["is_admin"]

        if user["is_admin"] in [1, 2]:
            return redirect("/admin")

        return redirect("/")

    return render_template("login.html", mode="login")


# ----------------------------------------------------------------
# LOGOUT
# ----------------------------------------------------------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# ----------------------------------------------------------------
# HOME
# ----------------------------------------------------------------
@app.route("/")
def home():
    if not require_login():
        return redirect("/login")

    uid = session["user_id"]
    conn = db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM espresso WHERE user_id=%s", (uid,))
    espresso = cur.fetchall()

    cur.execute("SELECT * FROM v60 WHERE user_id=%s", (uid,))
    v60 = cur.fetchall()

    cur.execute("SELECT * FROM milk WHERE user_id=%s", (uid,))
    milk = cur.fetchall()

    cur.execute("SELECT * FROM water WHERE user_id=%s", (uid,))
    water = cur.fetchall()

    cur.execute("SELECT * FROM journal WHERE user_id=%s", (uid,))
    journal = cur.fetchall()

    cur.close()
    conn.close()

    return render_template(
        "index.html",
        espresso=[dict(x) for x in espresso],
        v60=[dict(x) for x in v60],
        milk=[dict(x) for x in milk],
        water=[dict(x) for x in water],
        journal=[dict(x) for x in journal]
    )


# ----------------------------------------------------------------
# ADD LOGS
# ----------------------------------------------------------------
@app.route("/espresso/add", methods=["POST"])
def add_espresso():
    if not require_login():
        return redirect("/login")

    uid = session["user_id"]
    f = request.form

    try:
        ratio = float(f["yield"]) / float(f["dose"])
        diag = "Balanced"
        if ratio < 1.6:
            diag = "Under Extracted"
        if ratio > 2.4:
            diag = "Over Extracted"
    except Exception:
        diag = "N/A"

    conn = db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO espresso(user_id,coffee,dose,yield_out,time_sec,grind,temp,pressure,notes,diagnostics,timestamp)
        VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """, (
        uid, f["coffee"], f["dose"], f["yield"], f["time"],
        f["grind"], f["temp"], f["pressure"], f["notes"], diag,
        datetime.now().isoformat()
    ))
    conn.commit()
    cur.close()
    conn.close()

    return redirect("/")


@app.route("/v60/add", methods=["POST"])
def add_v60():
    if not require_login():
        return redirect("/login")
    uid = session["user_id"]
    f = request.form

    conn = db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO v60(user_id,coffee,dose,water,ratio,grind,temp,bloom_weight,bloom_time,pours,drawdown,notes,rating,timestamp)
        VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """, (
        uid, f["coffee"], f["dose"], f["water"], f["ratio"], f["grind"],
        f["temp"], f["bloom_weight"], f["bloom_time"], f["pours"],
        f["drawdown"], f["notes"], f["rating"], datetime.now().isoformat()
    ))
    conn.commit()
    cur.close()
    conn.close()
    return redirect("/")


@app.route("/milk/add", methods=["POST"])
def add_milk():
    if not require_login():
        return redirect("/login")
    uid = session["user_id"]
    f = request.form

    conn = db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO milk(user_id,milk_type,pitcher,stretch_time,target_temp,art_shape,notes,timestamp)
        VALUES(%s,%s,%s,%s,%s,%s,%s,%s)
    """, (
        uid, f["milk_type"], f["pitcher"], f["stretch_time"], f["target_temp"],
        f["art_shape"], f["notes"], datetime.now().isoformat()
    ))
    conn.commit()
    cur.close()
    conn.close()
    return redirect("/")


@app.route("/water/add", methods=["POST"])
def add_water():
    if not require_login():
        return redirect("/login")
    uid = session["user_id"]
    f = request.form

    conn = db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO water(user_id,gh,kh,tds,additives,notes,timestamp)
        VALUES(%s,%s,%s,%s,%s,%s,%s)
    """, (
        uid, f["gh"], f["kh"], f["tds"], f["additives"], f["notes"],
        datetime.now().isoformat()
    ))
    conn.commit()
    cur.close()
    conn.close()
    return redirect("/")


@app.route("/journal/add", methods=["POST"])
def add_journal():
    if not require_login():
        return redirect("/login")
    uid = session["user_id"]
    f = request.form

    conn = db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO journal(user_id,title,body,tags,timestamp)
        VALUES(%s,%s,%s,%s,%s)
    """, (
        uid, f["title"], f["body"], f["tags"], datetime.now().isoformat()
    ))
    conn.commit()
    cur.close()
    conn.close()
    return redirect("/")


# ----------------------------------------------------------------
# EXPORT
# ----------------------------------------------------------------
@app.route("/export")
def export_user():
    if not require_login():
        return redirect("/login")

    uid = session["user_id"]
    conn = db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM espresso WHERE user_id=%s", (uid,))
    espresso = cur.fetchall()

    cur.execute("SELECT * FROM v60 WHERE user_id=%s", (uid,))
    v60 = cur.fetchall()

    cur.execute("SELECT * FROM milk WHERE user_id=%s", (uid,))
    milk = cur.fetchall()

    cur.execute("SELECT * FROM water WHERE user_id=%s", (uid,))
    water = cur.fetchall()

    cur.execute("SELECT * FROM journal WHERE user_id=%s", (uid,))
    journal = cur.fetchall()

    cur.close()
    conn.close()

    return jsonify({
        "espresso": [dict(x) for x in espresso],
        "v60": [dict(x) for x in v60],
        "milk": [dict(x) for x in milk],
        "water": [dict(x) for x in water],
        "journal": [dict(x) for x in journal]
    })


# ----------------------------------------------------------------
# ADMIN PANEL + MSG SUPPORT
# ----------------------------------------------------------------
@app.route("/admin")
def admin():
    # If not admin → back to login (prevents template crash)
    if session.get("admin") not in [1, 2]:
        return redirect("/login")

    msg = request.args.get("msg")

    conn = db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM users")
    users = cur.fetchall()

    cur.execute("SELECT * FROM espresso")
    espresso = cur.fetchall()

    cur.execute("SELECT * FROM v60")
    v60 = cur.fetchall()

    cur.execute("SELECT * FROM milk")
    milk = cur.fetchall()

    cur.execute("SELECT * FROM water")
    water = cur.fetchall()

    cur.execute("SELECT * FROM journal")
    journal = cur.fetchall()

    cur.close()
    conn.close()

    return render_template(
        "admin.html",
        users=users,
        espresso=espresso,
        v60=v60,
        milk=milk,
        water=water,
        journal=journal,
        msg=msg,
        error=None
    )


# ----------------------------------------------------------------
# SUPER ADMIN ACTIONS (return msg to trigger toast)
# ----------------------------------------------------------------
@app.route("/admin/delete_user/<uid>")
def delete_user(uid):
    if session.get("admin") != 2:
        return redirect("/admin?msg=unauth")

    if int(uid) == session["user_id"]:
        return redirect("/admin?msg=selfblock")

    conn = db()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id=%s", (uid,))
    conn.commit()
    cur.close()
    conn.close()
    return redirect("/admin?msg=deleted")


@app.route("/admin/promote/<uid>")
def admin_promote(uid):
    if session.get("admin") != 2:
        return redirect("/admin?msg=unauth")

    conn = db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET is_admin=1 WHERE id=%s", (uid,))
    conn.commit()
    cur.close()
    conn.close()
    return redirect("/admin?msg=promoted")


@app.route("/admin/demote/<uid>")
def admin_demote(uid):
    if session.get("admin") != 2:
        return redirect("/admin?msg=unauth")

    conn = db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET is_admin=0 WHERE id=%s", (uid,))
    conn.commit()
    cur.close()
    conn.close()
    return redirect("/admin?msg=demoted")


# ----------------------------------------------------------------
# BAN / UNBAN (toast ready)
# ----------------------------------------------------------------
@app.route("/admin/ban/<uid>")
def admin_ban(uid):
    if session.get("admin") not in [1, 2]:
        return redirect("/admin?msg=unauth")

    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id=%s", (uid,))
    target = cur.fetchone()

    if target and target["is_admin"] == 2:
        cur.close()
        conn.close()
        return redirect("/admin?msg=cantsuper")

    cur.execute("UPDATE users SET banned=1 WHERE id=%s", (uid,))
    conn.commit()
    cur.close()
    conn.close()
    return redirect("/admin?msg=banned")


@app.route("/admin/unban/<uid>")
def admin_unban(uid):
    if session.get("admin") not in [1, 2]:
        return redirect("/admin?msg=unauth")

    conn = db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET banned=0 WHERE id=%s", (uid,))
    conn.commit()
    cur.close()
    conn.close()
    return redirect("/admin?msg=unbanned")


# ----------------------------------------------------------------
# ML HOOK
# ----------------------------------------------------------------
@app.route("/ml/upload", methods=["POST"])
def upload_ml_frame():
    return jsonify({"status": "ok", "message": "ML frame received"})


# ----------------------------------------------------------------
# RUN
# ----------------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)
