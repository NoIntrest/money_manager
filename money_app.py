#!/usr/bin/env python3
"""
💰 Vault — Money Manager (v4 — hardened)
Fixes applied:
  1.  Secret key raises error in production if not set
  2.  Rate limiting on auth routes (Flask-Limiter, in-memory)
  3.  Internal errors are logged server-side; generic messages sent to client
  4.  anthropic_key column removed (deprecated, migrated away)
  5.  Connection pooling via ThreadedConnectionPool (max 3 for Render free tier)
  6.  Procfile sets --workers 1 so in-memory rates cache is safe
  7.  debug=False (reads DEBUG env var instead)
  8.  All imports at the top
  9.  try/finally via context manager — no leaked connections
  10. Shared get_cursor() helper removes repeated DB boilerplate
  11. XSS: user data never injected via innerHTML in the frontend
  12. Loading skeletons on dashboard & transactions
Run locally: pip install flask flask-limiter requests psycopg2-binary bcrypt
On Render:   set DATABASE_URL + SECRET_KEY env vars
"""

# ── Imports ────────────────────────────────────────────────────────────────────
import os
import json
import logging
import hashlib
from contextlib import contextmanager
from datetime import datetime, date
from functools import wraps

import bcrypt
import psycopg2
import psycopg2.extras
from psycopg2.pool import ThreadedConnectionPool
import requests as req
from flask import Flask, request, jsonify, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ── App & logging ──────────────────────────────────────────────────────────────
app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Secret key ─────────────────────────────────────────────────────────────────
# Render sets the RENDER env var automatically on all its services.
# If we're on Render and SECRET_KEY isn't set, we refuse to start rather than
# silently using a guessable key.
_SECRET = os.environ.get("SECRET_KEY")
if not _SECRET:
    if os.environ.get("RENDER"):
        raise RuntimeError(
            "SECRET_KEY environment variable must be set in production. "
            "Add it in Render → Environment."
        )
    _SECRET = "vault-local-dev-key-DO-NOT-USE-IN-PROD"
    logger.warning("WARNING: using insecure dev secret key — set SECRET_KEY in production")

app.secret_key = _SECRET

# ── Rate limiter (in-memory — works fine with 1 Gunicorn worker) ───────────────
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],          # no global limit; apply per-route
    storage_uri="memory://",    # no Redis needed
)

# ── Config ─────────────────────────────────────────────────────────────────────
DATABASE_URL = os.environ.get("DATABASE_URL", "")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL   = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
DEBUG        = os.environ.get("DEBUG", "false").lower() == "true"

# ── Connection pool ────────────────────────────────────────────────────────────
# Render free PostgreSQL allows ~5 concurrent connections.
# We cap at 3 to leave headroom for migrations / psql sessions.
_pool: ThreadedConnectionPool | None = None

def get_pool() -> ThreadedConnectionPool:
    global _pool
    if _pool is None:
        if not DATABASE_URL:
            raise RuntimeError(
                "DATABASE_URL is not set. "
                "Add a PostgreSQL database in Render and link it to this service."
            )
        url = DATABASE_URL.replace("postgres://", "postgresql://", 1)
        _pool = ThreadedConnectionPool(1, 3, dsn=url)
    return _pool

@contextmanager
def get_cursor(dict_cursor: bool = False):
    """
    Context manager that borrows a connection from the pool, yields
    (conn, cursor), commits on success, rolls back on error, and always
    returns the connection to the pool.

    Usage:
        with get_cursor(dict_cursor=True) as (conn, cur):
            cur.execute(...)
    """
    pool = get_pool()
    conn = pool.getconn()
    try:
        factory = psycopg2.extras.RealDictCursor if dict_cursor else None
        cur = conn.cursor(cursor_factory=factory) if factory else conn.cursor()
        try:
            yield conn, cur
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()
    finally:
        pool.putconn(conn)

# ── Database init ──────────────────────────────────────────────────────────────

def init_db():
    """Create / migrate tables. Safe to run on every startup."""
    with get_cursor() as (conn, cur):
        # Users — note: anthropic_key column is dropped if it still exists
        # from an older deployment
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id         SERIAL PRIMARY KEY,
                email      TEXT UNIQUE NOT NULL,
                password   TEXT NOT NULL,
                currency   TEXT DEFAULT 'USD',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Migration: drop the unused anthropic_key column if present
        cur.execute("""
            ALTER TABLE users DROP COLUMN IF EXISTS anthropic_key
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id         SERIAL PRIMARY KEY,
                user_id    INTEGER NOT NULL REFERENCES users(id),
                type       TEXT NOT NULL,
                amount     NUMERIC(14,2) NOT NULL,
                currency   TEXT DEFAULT 'USD',
                category   TEXT,
                note       TEXT,
                date       TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS budgets (
                id          SERIAL PRIMARY KEY,
                user_id     INTEGER NOT NULL REFERENCES users(id),
                month       TEXT NOT NULL,
                category    TEXT NOT NULL,
                goal_amount NUMERIC(14,2) NOT NULL,
                currency    TEXT DEFAULT 'USD',
                UNIQUE (user_id, month, category)
            )
        """)

# ── Auth helpers ───────────────────────────────────────────────────────────────

def hash_pw(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def check_pw(pw: str, hashed: str) -> bool:
    """Supports both bcrypt and legacy SHA-256 hashes."""
    if hashed.startswith("$2b$") or hashed.startswith("$2a$"):
        try:
            return bcrypt.checkpw(pw.encode(), hashed.encode())
        except Exception:
            return False
    return hashlib.sha256(pw.encode()).hexdigest() == hashed

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

# ── Auth routes ────────────────────────────────────────────────────────────────

@app.route("/api/signup", methods=["POST"])
@limiter.limit("10 per minute")   # brute-force protection
def signup():
    data     = request.json or {}
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")
    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    try:
        with get_cursor(dict_cursor=True) as (conn, cur):
            try:
                cur.execute(
                    "INSERT INTO users (email, password) VALUES (%s, %s)",
                    (email, hash_pw(password))
                )
            except psycopg2.errors.UniqueViolation:
                conn.rollback()
                return jsonify({"error": "Email already registered"}), 409
            cur.execute("SELECT * FROM users WHERE email=%s", (email,))
            user = cur.fetchone()
        session["user_id"] = user["id"]
        session["email"]   = email
        return jsonify({"success": True, "email": email, "currency": "USD"})
    except Exception as e:
        logger.error("signup error: %s", e)
        return jsonify({"error": "Could not create account. Please try again."}), 500

@app.route("/api/login", methods=["POST"])
@limiter.limit("15 per minute")   # brute-force protection
def login():
    data     = request.json or {}
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")
    try:
        with get_cursor(dict_cursor=True) as (conn, cur):
            cur.execute("SELECT * FROM users WHERE email=%s", (email,))
            user = cur.fetchone()
            if not user or not check_pw(password, user["password"]):
                return jsonify({"error": "Invalid email or password"}), 401
            # Upgrade legacy SHA-256 hash to bcrypt on first login
            if not (user["password"].startswith("$2b$") or user["password"].startswith("$2a$")):
                cur.execute(
                    "UPDATE users SET password=%s WHERE id=%s",
                    (hash_pw(password), user["id"])
                )
        session["user_id"] = user["id"]
        session["email"]   = user["email"]
        return jsonify({"success": True, "email": user["email"], "currency": user["currency"] or "USD"})
    except Exception as e:
        logger.error("login error: %s", e)
        return jsonify({"error": "Login failed. Please try again."}), 500

@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"success": True})

@app.route("/api/me")
def me():
    if "user_id" not in session:
        return jsonify({"logged_in": False})
    try:
        with get_cursor(dict_cursor=True) as (_, cur):
            cur.execute(
                "SELECT email, currency FROM users WHERE id=%s",
                (session["user_id"],)
            )
            user = cur.fetchone()
        return jsonify({
            "logged_in":   True,
            "email":       user["email"],
            "currency":    user["currency"] or "USD",
            "groq_ready":  bool(GROQ_API_KEY),
            "groq_model":  GROQ_MODEL,
        })
    except Exception as e:
        logger.error("me error: %s", e)
        return jsonify({"error": "Could not load user data."}), 500

# ── Settings ───────────────────────────────────────────────────────────────────

@app.route("/api/settings", methods=["POST"])
@login_required
def update_settings():
    data = request.json or {}
    if "currency" not in data:
        return jsonify({"error": "No settings provided"}), 400
    try:
        with get_cursor() as (_, cur):
            cur.execute(
                "UPDATE users SET currency=%s WHERE id=%s",
                (data["currency"], session["user_id"])
            )
        return jsonify({"success": True})
    except Exception as e:
        logger.error("settings error: %s", e)
        return jsonify({"error": "Could not save settings."}), 500

# ── Live Currency Rates ────────────────────────────────────────────────────────
# Safe to keep in-memory: Procfile forces --workers 1 so there's only one process.

_rates_cache = {"ts": 0, "data": {}}

@app.route("/api/rates")
def get_rates():
    import time
    now = time.time()
    if now - _rates_cache["ts"] < 3600 and _rates_cache["data"]:
        return jsonify(_rates_cache["data"])
    try:
        r = req.get("https://api.exchangerate-api.com/v4/latest/USD", timeout=5)
        rates = r.json().get("rates", {})
        _rates_cache["ts"]   = now
        _rates_cache["data"] = rates
        return jsonify(rates)
    except Exception as e:
        logger.warning("Exchange rate fetch failed: %s", e)
        fallback = {
            "USD":1,"EUR":0.92,"GBP":0.79,"INR":83.1,"JPY":149.5,
            "CAD":1.36,"AUD":1.53,"CHF":0.88,"CNY":7.24,"SGD":1.34,
            "AED":3.67,"MXN":17.2,"BRL":4.97,"KRW":1325,"THB":35.1,
        }
        return jsonify(fallback)

# ── Transactions ───────────────────────────────────────────────────────────────

@app.route("/api/transactions", methods=["GET"])
@login_required
def get_transactions():
    month = request.args.get("month", datetime.now().strftime("%Y-%m"))
    try:
        with get_cursor(dict_cursor=True) as (_, cur):
            cur.execute(
                "SELECT * FROM transactions WHERE user_id=%s AND date LIKE %s ORDER BY date DESC, id DESC",
                (session["user_id"], f"{month}%")
            )
            rows = cur.fetchall()
        return jsonify([{**dict(r), "amount": float(r["amount"])} for r in rows])
    except Exception as e:
        logger.error("get_transactions error: %s", e)
        return jsonify({"error": "Could not load transactions."}), 500

@app.route("/api/transactions", methods=["POST"])
@login_required
def add_transaction():
    data      = request.json or {}
    tx_type   = data.get("type")
    amount    = data.get("amount")
    currency  = data.get("currency", "USD")
    category  = data.get("category", "Other")
    note      = data.get("note", "")
    tx_date   = data.get("date", str(date.today()))
    if tx_type not in ("income", "expense"):
        return jsonify({"error": "Type must be income or expense"}), 400
    try:
        amount = float(amount)
        if amount <= 0:
            raise ValueError()
    except (TypeError, ValueError):
        return jsonify({"error": "Amount must be a positive number"}), 400
    try:
        with get_cursor() as (_, cur):
            cur.execute(
                "INSERT INTO transactions (user_id, type, amount, currency, category, note, date) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s)",
                (session["user_id"], tx_type, amount, currency, category, note, tx_date)
            )
        return jsonify({"success": True})
    except Exception as e:
        logger.error("add_transaction error: %s", e)
        return jsonify({"error": "Could not save transaction."}), 500

@app.route("/api/transactions/<int:tx_id>", methods=["DELETE"])
@login_required
def delete_transaction(tx_id):
    try:
        with get_cursor() as (_, cur):
            cur.execute(
                "DELETE FROM transactions WHERE id=%s AND user_id=%s",
                (tx_id, session["user_id"])
            )
        return jsonify({"success": True})
    except Exception as e:
        logger.error("delete_transaction error: %s", e)
        return jsonify({"error": "Could not delete transaction."}), 500

@app.route("/api/summary")
@login_required
def summary():
    month = request.args.get("month", datetime.now().strftime("%Y-%m"))
    try:
        with get_cursor(dict_cursor=True) as (_, cur):
            cur.execute("SELECT currency FROM users WHERE id=%s", (session["user_id"],))
            user = cur.fetchone()
            cur.execute(
                "SELECT type, category, amount, currency FROM transactions "
                "WHERE user_id=%s AND date LIKE %s",
                (session["user_id"], f"{month}%")
            )
            rows = cur.fetchall()
    except Exception as e:
        logger.error("summary error: %s", e)
        return jsonify({"error": "Could not load summary."}), 500

    user_currency = (user["currency"] or "USD") if user else "USD"
    rates = _rates_cache.get("data", {})

    def to_display(amount, from_cur):
        from_cur = from_cur or "USD"
        if not rates or from_cur == user_currency:
            return float(amount)
        usd = float(amount) / rates.get(from_cur, 1)
        return usd * rates.get(user_currency, 1)

    income   = sum(to_display(r["amount"], r["currency"]) for r in rows if r["type"] == "income")
    expenses = sum(to_display(r["amount"], r["currency"]) for r in rows if r["type"] == "expense")
    cats = {}
    for r in rows:
        if r["type"] == "expense":
            cats[r["category"]] = cats.get(r["category"], 0) + to_display(r["amount"], r["currency"])

    return jsonify({
        "income":           income,
        "expenses":         expenses,
        "balance":          income - expenses,
        "categories":       cats,
        "display_currency": user_currency,
    })

# ── AI Budget Advisor (Groq) ───────────────────────────────────────────────────

@app.route("/api/ai-chat", methods=["POST"])
@login_required
@limiter.limit("30 per minute")
def ai_chat():
    data         = request.json or {}
    user_message = data.get("message", "").strip()
    if not user_message:
        return jsonify({"error": "No message provided"}), 400
    if not GROQ_API_KEY:
        return jsonify({"error": "no_key"}), 200

    try:
        with get_cursor(dict_cursor=True) as (_, cur):
            cur.execute("SELECT currency FROM users WHERE id=%s", (session["user_id"],))
            user = cur.fetchone()
            cur.execute(
                "SELECT type, amount, currency, category, note, date "
                "FROM transactions WHERE user_id=%s ORDER BY date DESC LIMIT 50",
                (session["user_id"],)
            )
            txs = cur.fetchall()
    except Exception as e:
        logger.error("ai_chat DB error: %s", e)
        return jsonify({"error": "Could not load your data."}), 500

    currency = (user["currency"] or "USD") if user else "USD"
    tx_summary = "\n".join([
        f"- {t['date']} | {t['type'].upper()} | {t['currency'] or currency}{float(t['amount']):.2f} "
        f"| {t['category']} | {t['note'] or ''}"
        for t in txs
    ]) or "No transactions yet."

    income_total  = sum(float(t["amount"]) for t in txs if t["type"] == "income")
    expense_total = sum(float(t["amount"]) for t in txs if t["type"] == "expense")

    system_prompt = (
        f"You are Vault AI, a friendly and insightful personal finance advisor.\n"
        f"The user's preferred currency is {currency}.\n"
        f"Recent transactions (last 50):\n{tx_summary}\n\n"
        f"Summary: income={currency}{income_total:.2f}, "
        f"expenses={currency}{expense_total:.2f}, "
        f"balance={currency}{income_total - expense_total:.2f}\n\n"
        f"Give practical, specific, actionable advice based on THEIR data. "
        f"Be warm but direct. Keep responses concise (3-5 sentences) unless asked for detail. "
        f"Use {currency} for all amounts."
    )

    try:
        response = req.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
            json={
                "model":      GROQ_MODEL,
                "max_tokens": 500,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": user_message},
                ],
            },
            timeout=30,
        )
        if response.status_code != 200:
            err = response.json().get("error", {}).get("message", "Groq API error")
            return jsonify({"error": err}), 400
        reply = response.json()["choices"][0]["message"]["content"]
        return jsonify({"reply": reply})
    except Exception as e:
        logger.error("ai_chat groq error: %s", e)
        return jsonify({"error": "AI request failed. Please try again."}), 500

# ── Budget ─────────────────────────────────────────────────────────────────────

@app.route("/api/budget", methods=["GET"])
@login_required
def get_budget():
    month = request.args.get("month", datetime.now().strftime("%Y-%m"))
    try:
        with get_cursor(dict_cursor=True) as (_, cur):
            cur.execute(
                "SELECT category, goal_amount, currency FROM budgets "
                "WHERE user_id=%s AND month=%s",
                (session["user_id"], month)
            )
            rows = cur.fetchall()
        return jsonify([{**dict(r), "goal_amount": float(r["goal_amount"])} for r in rows])
    except Exception as e:
        logger.error("get_budget error: %s", e)
        return jsonify({"error": "Could not load budget goals."}), 500

@app.route("/api/budget", methods=["POST"])
@login_required
def save_budget():
    data     = request.json or {}
    month    = data.get("month", datetime.now().strftime("%Y-%m"))
    goals    = data.get("goals", [])   # [{category, goal_amount, currency}]
    currency = data.get("currency", "USD")
    if not isinstance(goals, list):
        return jsonify({"error": "goals must be a list"}), 400
    try:
        with get_cursor() as (_, cur):
            # Delete existing goals for this month, then re-insert
            cur.execute(
                "DELETE FROM budgets WHERE user_id=%s AND month=%s",
                (session["user_id"], month)
            )
            for g in goals:
                cat    = g.get("category", "").strip()
                amount = g.get("goal_amount", 0)
                try:
                    amount = float(amount)
                except (TypeError, ValueError):
                    amount = 0
                if cat and amount > 0:
                    cur.execute(
                        "INSERT INTO budgets (user_id, month, category, goal_amount, currency) "
                        "VALUES (%s,%s,%s,%s,%s)",
                        (session["user_id"], month, cat, amount, currency)
                    )
        return jsonify({"success": True})
    except Exception as e:
        logger.error("save_budget error: %s", e)
        return jsonify({"error": "Could not save budget goals."}), 500

@app.route("/api/budget/progress")
@login_required
def get_budget_progress():
    month = request.args.get("month", datetime.now().strftime("%Y-%m"))
    try:
        with get_cursor(dict_cursor=True) as (_, cur):
            # User currency
            cur.execute("SELECT currency FROM users WHERE id=%s", (session["user_id"],))
            user = cur.fetchone()
            # Goals
            cur.execute(
                "SELECT category, goal_amount, currency FROM budgets "
                "WHERE user_id=%s AND month=%s",
                (session["user_id"], month)
            )
            goals = {r["category"]: float(r["goal_amount"]) for r in cur.fetchall()}
            # Actual spending per category for this month
            cur.execute(
                "SELECT category, SUM(amount) AS total FROM transactions "
                "WHERE user_id=%s AND type='expense' AND date LIKE %s "
                "GROUP BY category",
                (session["user_id"], f"{month}%")
            )
            spent = {r["category"]: float(r["total"]) for r in cur.fetchall()}
            # For savings: income - expenses
            cur.execute(
                "SELECT type, SUM(amount) AS total FROM transactions "
                "WHERE user_id=%s AND date LIKE %s GROUP BY type",
                (session["user_id"], f"{month}%")
            )
            totals = {r["type"]: float(r["total"]) for r in cur.fetchall()}
        income   = totals.get("income", 0)
        expenses = totals.get("expense", 0)
        rows = []
        for cat, goal in goals.items():
            if cat == "Savings":
                actual = income - expenses   # actual savings balance
            else:
                actual = spent.get(cat, 0)
            rows.append({"category": cat, "goal": goal, "actual": round(actual, 2)})
        return jsonify({"progress": rows, "display_currency": (user["currency"] or "USD") if user else "USD"})
    except Exception as e:
        logger.error("get_budget_progress error: %s", e)
        return jsonify({"error": "Could not load progress."}), 500

# ── Health ─────────────────────────────────────────────────────────────────────

@app.route("/api/health")
def health():
    if not DATABASE_URL:
        return jsonify({"status": "error", "reason": "DATABASE_URL not set"}), 500
    try:
        with get_cursor() as (_, cur):
            cur.execute("SELECT 1")
        return jsonify({"status": "ok", "db": "connected"})
    except Exception as e:
        logger.error("health check failed: %s", e)
        return jsonify({"status": "error", "reason": "DB unreachable"}), 500

# ── Frontend ───────────────────────────────────────────────────────────────────

# Run migrations whenever the module is imported (covers Gunicorn on Render as
# well as local `python money_app.py` — safe to call multiple times).
try:
    init_db()
except Exception as _init_err:
    logger.warning("init_db() skipped at import time (DATABASE_URL not set?): %s", _init_err)

@app.route("/")
def index():
    return FRONTEND

# ── HTML ───────────────────────────────────────────────────────────────────────

FRONTEND = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Vault — Money Manager</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=Fraunces:ital,wght@0,400;0,700;0,900;1,400&family=Outfit:wght@300;400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet"/>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
:root {
  --bg:       #faf7f2;
  --surface:  #ffffff;
  --surface2: #f5f0e8;
  --border:   #e8e0d0;
  --ink:      #1c1710;
  --ink2:     #5c5040;
  --ink3:     #a09070;

  --red:      #e03c2a;
  --red-dim:  #b02e1e;
  --red-soft: #fdf0ee;
  --orange:   #f07020;
  --orange-soft: #fef4ec;
  --amber:    #e8a020;
  --amber-soft: #fef9ec;
  --green:    #2a9a50;
  --green-dim:#1e7a3a;
  --green-soft:#eef7f2;

  --grad-hero: linear-gradient(135deg, #1c1710 0%, #3a2010 100%);
  --grad-card: linear-gradient(135deg, #e03c2a, #f07020);
  --shadow:    0 4px 24px rgba(28,23,16,0.10);
  --shadow-lg: 0 8px 48px rgba(28,23,16,0.16);
}

*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
html,body{height:100%;background:var(--bg);color:var(--ink);font-family:'Outfit',sans-serif;}

body::after{
  content:'';position:fixed;inset:0;pointer-events:none;z-index:0;
  background:
    radial-gradient(ellipse at 0% 0%, rgba(224,60,42,0.06) 0%, transparent 50%),
    radial-gradient(ellipse at 100% 100%, rgba(42,154,80,0.06) 0%, transparent 50%);
}

/* ── Auth ───────────────────────────────────────────────────── */
#auth-screen{
  display:flex;align-items:center;justify-content:center;
  min-height:100vh;padding:20px;position:relative;z-index:1;
}
.auth-split{
  width:100%;max-width:900px;
  display:grid;grid-template-columns:1fr 1fr;
  border-radius:16px;overflow:hidden;box-shadow:var(--shadow-lg);
}
.auth-left{
  background:var(--grad-hero);
  padding:56px 48px;display:flex;flex-direction:column;justify-content:space-between;
  position:relative;overflow:hidden;
}
.auth-left::before{
  content:'';position:absolute;top:-80px;right:-80px;
  width:260px;height:260px;border-radius:50%;
  background:rgba(240,112,32,0.2);
}
.auth-left::after{
  content:'';position:absolute;bottom:-60px;left:-60px;
  width:200px;height:200px;border-radius:50%;
  background:rgba(42,154,80,0.15);
}
.auth-brand{position:relative;z-index:1;}
.auth-logo{
  font-family:'Fraunces',serif;font-size:2.4rem;font-weight:900;
  color:#ffffff;letter-spacing:-0.02em;margin-bottom:8px;
}
.auth-logo span{color:var(--orange);}
.auth-tagline{font-size:0.85rem;color:rgba(255,255,255,0.55);letter-spacing:0.1em;text-transform:uppercase;}
.auth-features{position:relative;z-index:1;display:flex;flex-direction:column;gap:14px;}
.auth-feat{display:flex;align-items:center;gap:12px;color:rgba(255,255,255,0.8);font-size:0.82rem;}
.auth-feat-icon{width:28px;height:28px;border-radius:8px;background:rgba(255,255,255,0.1);display:flex;align-items:center;justify-content:center;font-size:0.9rem;flex-shrink:0;}

.auth-right{background:var(--surface);padding:56px 48px;}
.auth-tabs{display:flex;gap:0;margin-bottom:36px;border-bottom:2px solid var(--border);}
.auth-tab{
  flex:1;padding:10px;cursor:pointer;
  font-size:0.78rem;letter-spacing:0.12em;text-transform:uppercase;font-weight:600;
  color:var(--ink3);border-bottom:2px solid transparent;margin-bottom:-2px;
  transition:all 0.2s;background:none;border-top:none;border-left:none;border-right:none;
}
.auth-tab.active{color:var(--red);border-bottom-color:var(--red);}
.auth-field-label{font-size:0.7rem;letter-spacing:0.14em;text-transform:uppercase;color:var(--ink3);margin-bottom:7px;display:block;}
.auth-input{
  width:100%;padding:12px 16px;margin-bottom:16px;
  background:var(--surface2);border:1.5px solid var(--border);
  border-radius:8px;color:var(--ink);font-family:'Outfit',sans-serif;font-size:0.92rem;
  transition:border-color 0.18s,box-shadow 0.18s;
}
.auth-input:focus{outline:none;border-color:var(--orange);box-shadow:0 0 0 3px rgba(240,112,32,0.12);}
.auth-btn{
  width:100%;padding:14px;margin-top:4px;
  background:var(--grad-card);border:none;border-radius:8px;
  color:#fff;font-family:'Outfit',sans-serif;font-size:0.9rem;font-weight:600;
  letter-spacing:0.06em;cursor:pointer;transition:opacity 0.2s,transform 0.15s;
}
.auth-btn:hover{opacity:0.9;transform:translateY(-1px);}
.auth-error{
  background:var(--red-soft);border:1px solid rgba(224,60,42,0.3);color:var(--red);
  padding:10px 14px;border-radius:8px;font-size:0.78rem;margin-bottom:14px;display:none;
}

/* ── App Layout ──────────────────────────────────────────────── */
#app-screen{display:none;min-height:100vh;position:relative;z-index:1;}
.sidebar{
  position:fixed;left:0;top:0;bottom:0;width:248px;
  background:var(--ink);display:flex;flex-direction:column;
  padding:0;z-index:100;
}
.sidebar-logo{
  padding:28px 24px 24px;
  font-family:'Fraunces',serif;font-size:1.6rem;font-weight:900;
  color:#fff;letter-spacing:-0.02em;
  border-bottom:1px solid rgba(255,255,255,0.08);
}
.sidebar-logo span{color:var(--orange);}
.sidebar-logo small{display:block;font-family:'Outfit',sans-serif;font-size:0.65rem;font-weight:400;color:rgba(255,255,255,0.35);letter-spacing:0.15em;text-transform:uppercase;margin-top:2px;}
.nav{padding:20px 0;flex:1;}
.nav-section-label{
  font-size:0.6rem;letter-spacing:0.2em;text-transform:uppercase;
  color:rgba(255,255,255,0.25);padding:12px 24px 6px;
}
.nav-item{
  display:flex;align-items:center;gap:12px;
  padding:11px 24px;cursor:pointer;
  font-size:0.86rem;color:rgba(255,255,255,0.55);
  transition:all 0.15s;border-left:3px solid transparent;
  font-weight:500;
}
.nav-item:hover{color:rgba(255,255,255,0.9);background:rgba(255,255,255,0.04);}
.nav-item.active{color:#fff;border-left-color:var(--orange);background:rgba(240,112,32,0.12);}
.nav-icon{width:20px;text-align:center;font-size:1rem;flex-shrink:0;}
.sidebar-bottom{padding:16px;border-top:1px solid rgba(255,255,255,0.08);}
.user-card{
  display:flex;align-items:center;gap:10px;
  padding:10px 12px;border-radius:10px;
  background:rgba(255,255,255,0.05);
}
.user-av{
  width:34px;height:34px;border-radius:50%;flex-shrink:0;
  background:var(--grad-card);
  display:flex;align-items:center;justify-content:center;
  font-weight:700;font-size:0.85rem;color:#fff;
}
.user-email{font-size:0.72rem;color:rgba(255,255,255,0.55);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.logout-btn{background:none;border:none;color:rgba(255,255,255,0.3);cursor:pointer;font-size:1rem;padding:4px;transition:color 0.2s;}
.logout-btn:hover{color:var(--red);}

.main{margin-left:248px;padding:40px 48px;min-height:100vh;}
.page{display:none;animation:fadeUp 0.35s ease both;}
.page.active{display:block;}
.page-header{margin-bottom:32px;}
.page-title{font-family:'Fraunces',serif;font-size:2rem;font-weight:700;letter-spacing:-0.02em;margin-bottom:4px;}
.page-sub{font-size:0.78rem;color:var(--ink3);letter-spacing:0.1em;text-transform:uppercase;}

/* ── Skeleton loading ────────────────────────────────────────── */
.skeleton{
  background:linear-gradient(90deg,var(--surface2) 25%,var(--border) 50%,var(--surface2) 75%);
  background-size:200% 100%;
  animation:shimmer 1.4s infinite;
  border-radius:8px;
}
@keyframes shimmer{from{background-position:200% 0;}to{background-position:-200% 0;}}
.skel-amount{height:2.2rem;width:140px;margin-top:6px;}
.skel-text{height:0.9rem;width:100%;}
.skel-text.short{width:60%;}

/* ── Month Nav ───────────────────────────────────────────────── */
.month-nav-row{display:flex;align-items:center;gap:12px;margin-bottom:28px;}
.mnav{
  background:var(--surface);border:1.5px solid var(--border);
  color:var(--ink);padding:8px 14px;border-radius:8px;cursor:pointer;
  font-size:0.9rem;font-weight:600;transition:all 0.15s;
}
.mnav:hover{border-color:var(--orange);color:var(--orange);}
.mlabel{
  font-family:'Fraunces',serif;font-size:1.05rem;font-weight:700;
  min-width:160px;text-align:center;
}
.currency-badge{
  margin-left:auto;
  display:flex;align-items:center;gap:8px;
  background:var(--surface);border:1.5px solid var(--border);
  border-radius:8px;padding:6px 14px;
  font-size:0.8rem;font-weight:600;color:var(--ink2);
}
.currency-badge span{font-size:1rem;}

/* ── Dashboard Cards ─────────────────────────────────────────── */
.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:18px;margin-bottom:28px;}
.card{border-radius:14px;padding:26px;position:relative;overflow:hidden;}
.card-hero{
  background:var(--grad-hero);color:#fff;
  grid-column:1/-1;display:flex;align-items:center;justify-content:space-between;
  padding:28px 36px;
}
.card-hero-left .card-label{font-size:0.7rem;letter-spacing:0.15em;text-transform:uppercase;color:rgba(255,255,255,0.5);margin-bottom:8px;}
.card-hero-left .card-amount{font-family:'JetBrains Mono',monospace;font-size:2.4rem;font-weight:500;letter-spacing:-0.02em;}
.card-hero-right{text-align:right;}
.card-hero-right .card-label{font-size:0.65rem;color:rgba(255,255,255,0.4);letter-spacing:0.12em;text-transform:uppercase;margin-bottom:6px;}
.card-hero-right .mini-stat{font-family:'JetBrains Mono',monospace;font-size:1rem;font-weight:500;margin-bottom:2px;}
.card-hero-right .mini-stat.inc{color:#6ee7a0;}
.card-hero-right .mini-stat.exp{color:#fca89a;}
.card.income{background:var(--green-soft);border:1.5px solid rgba(42,154,80,0.2);}
.card.expense{background:var(--red-soft);border:1.5px solid rgba(224,60,42,0.2);}
.card-label{font-size:0.68rem;letter-spacing:0.14em;text-transform:uppercase;color:var(--ink3);margin-bottom:10px;}
.card-amount{font-family:'JetBrains Mono',monospace;font-size:1.7rem;font-weight:500;letter-spacing:-0.02em;}
.card.income .card-amount{color:var(--green);}
.card.expense .card-amount{color:var(--red);}
.card-icon{position:absolute;right:20px;top:20px;font-size:1.4rem;opacity:0.2;}

/* ── Dashboard Grid ──────────────────────────────────────────── */
.dash-grid{display:grid;grid-template-columns:3fr 2fr;gap:20px;}
.widget{background:var(--surface);border:1.5px solid var(--border);border-radius:14px;padding:24px;}
.widget-title{font-size:0.7rem;letter-spacing:0.15em;text-transform:uppercase;color:var(--ink3);margin-bottom:18px;display:flex;align-items:center;justify-content:space-between;}
.chart-wrap{position:relative;height:210px;display:flex;align-items:center;justify-content:center;}
.no-data{color:var(--ink3);font-size:0.82rem;text-align:center;padding:32px;}

/* Convert widget */
.convert-widget{background:linear-gradient(135deg,var(--orange-soft),var(--amber-soft));border:1.5px solid rgba(240,112,32,0.2);border-radius:14px;padding:24px;}
.convert-title{font-size:0.7rem;letter-spacing:0.15em;text-transform:uppercase;color:var(--orange);margin-bottom:16px;display:flex;align-items:center;gap:8px;}
.convert-row{display:flex;align-items:center;gap:10px;margin-bottom:12px;}
.convert-input{
  flex:1;padding:10px 14px;
  background:#fff;border:1.5px solid rgba(240,112,32,0.25);
  border-radius:8px;font-family:'JetBrains Mono',monospace;font-size:0.9rem;
  color:var(--ink);transition:border-color 0.18s;
}
.convert-input:focus{outline:none;border-color:var(--orange);}
.convert-select{
  padding:10px 12px;background:#fff;border:1.5px solid rgba(240,112,32,0.25);
  border-radius:8px;font-family:'Outfit',sans-serif;font-size:0.82rem;
  color:var(--ink);cursor:pointer;
}
.convert-arrow{color:var(--orange);font-size:1rem;font-weight:700;}
.convert-result{
  background:#fff;border-radius:10px;padding:14px 16px;
  font-family:'JetBrains Mono',monospace;font-size:1.15rem;font-weight:500;
  color:var(--green);text-align:center;border:1.5px solid rgba(42,154,80,0.2);
}
.convert-rate{font-size:0.72rem;color:var(--ink3);text-align:center;margin-top:8px;}

/* Recent mini list */
.tx-mini{display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid var(--border);}
.tx-mini:last-child{border-bottom:none;}
.tx-mini-left{}
.tx-mini-cat{font-size:0.84rem;font-weight:500;margin-bottom:2px;}
.tx-mini-note{font-size:0.7rem;color:var(--ink3);}
.tx-mini-right{text-align:right;}
.tx-mini-amt{font-family:'JetBrains Mono',monospace;font-size:0.88rem;font-weight:500;}
.tx-mini-amt.income{color:var(--green);}
.tx-mini-amt.expense{color:var(--red);}
.tx-mini-date{font-size:0.68rem;color:var(--ink3);}

/* ── Transactions Page ───────────────────────────────────────── */
.tx-toolbar{display:flex;gap:12px;margin-bottom:22px;align-items:center;flex-wrap:wrap;}
.filter-btns{display:flex;gap:6px;}
.filter-btn{
  padding:7px 16px;background:var(--surface);border:1.5px solid var(--border);
  border-radius:20px;font-size:0.76rem;font-weight:600;color:var(--ink3);
  cursor:pointer;transition:all 0.15s;letter-spacing:0.06em;text-transform:uppercase;
}
.filter-btn.active{border-color:var(--orange);color:var(--orange);background:var(--orange-soft);}
.tx-list{display:flex;flex-direction:column;gap:8px;}
.tx-row{
  background:var(--surface);border:1.5px solid var(--border);
  border-radius:12px;padding:16px 20px;
  display:flex;align-items:center;gap:14px;
  transition:border-color 0.15s,box-shadow 0.15s;
}
.tx-row:hover{border-color:var(--orange);box-shadow:0 2px 12px rgba(240,112,32,0.08);}
.tx-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0;}
.tx-dot.income{background:var(--green);box-shadow:0 0 0 3px rgba(42,154,80,0.15);}
.tx-dot.expense{background:var(--red);box-shadow:0 0 0 3px rgba(224,60,42,0.15);}
.tx-info{flex:1;}
.tx-cat{font-size:0.88rem;font-weight:600;margin-bottom:2px;}
.tx-note{font-size:0.72rem;color:var(--ink3);}
.tx-date{font-size:0.72rem;color:var(--ink3);font-family:'JetBrains Mono',monospace;}
.tx-cur{font-size:0.68rem;color:var(--ink3);font-family:'JetBrains Mono',monospace;}
.tx-amount{font-family:'JetBrains Mono',monospace;font-size:1rem;font-weight:600;}
.tx-amount.income{color:var(--green);}
.tx-amount.expense{color:var(--red);}
.tx-del{background:none;border:none;color:var(--ink3);cursor:pointer;font-size:0.9rem;padding:4px 8px;opacity:0;transition:all 0.15s;border-radius:6px;}
.tx-row:hover .tx-del{opacity:1;}
.tx-del:hover{background:var(--red-soft);color:var(--red);}

/* ── Add Entry ───────────────────────────────────────────────── */
.add-form{max-width:580px;}
.add-card{background:var(--surface);border:1.5px solid var(--border);border-radius:16px;padding:36px 40px;}
.type-toggle{display:flex;gap:0;border:1.5px solid var(--border);border-radius:10px;overflow:hidden;margin-bottom:28px;}
.type-btn{
  flex:1;padding:12px;border:none;cursor:pointer;
  font-family:'Outfit',sans-serif;font-size:0.82rem;font-weight:600;
  letter-spacing:0.08em;text-transform:uppercase;
  background:transparent;color:var(--ink3);transition:all 0.2s;
}
.type-btn.active.income{background:var(--green-soft);color:var(--green);}
.type-btn.active.expense{background:var(--red-soft);color:var(--red);}
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:14px;}
.form-field{margin-bottom:18px;}
.form-field label{font-size:0.68rem;letter-spacing:0.14em;text-transform:uppercase;color:var(--ink3);display:block;margin-bottom:7px;}
.form-field input, .form-field select{
  width:100%;padding:11px 14px;
  background:var(--surface2);border:1.5px solid var(--border);
  border-radius:8px;color:var(--ink);font-family:'Outfit',sans-serif;font-size:0.9rem;
  transition:border-color 0.18s;
}
.form-field input:focus, .form-field select:focus{outline:none;border-color:var(--orange);box-shadow:0 0 0 3px rgba(240,112,32,0.1);}
.amount-wrap{position:relative;}
.amount-pfx{position:absolute;left:14px;top:50%;transform:translateY(-50%);color:var(--ink3);font-family:'JetBrains Mono',monospace;font-size:0.9rem;pointer-events:none;}
.amount-wrap input{padding-left:30px;}
.cat-pills{display:flex;flex-wrap:wrap;gap:7px;margin-bottom:18px;}
.cat-pill{
  padding:6px 14px;background:var(--surface2);border:1.5px solid var(--border);
  border-radius:20px;font-size:0.76rem;cursor:pointer;transition:all 0.15s;color:var(--ink2);font-weight:500;
}
.cat-pill.active{border-color:var(--orange);color:var(--orange);background:var(--orange-soft);}
.submit-btn{
  width:100%;padding:14px;background:var(--grad-card);border:none;border-radius:10px;
  color:#fff;font-family:'Outfit',sans-serif;font-size:0.9rem;font-weight:700;
  letter-spacing:0.08em;text-transform:uppercase;cursor:pointer;
  transition:opacity 0.2s,transform 0.15s;margin-top:4px;
}
.submit-btn:hover{opacity:0.9;transform:translateY(-1px);}
.form-error{background:var(--red-soft);border:1px solid rgba(224,60,42,0.3);color:var(--red);padding:10px 14px;border-radius:8px;font-size:0.78rem;margin-top:12px;display:none;}

/* ── AI Advisor Page ─────────────────────────────────────────── */
.ai-layout{display:grid;grid-template-columns:1fr 320px;gap:24px;align-items:start;}
.chat-card{background:var(--surface);border:1.5px solid var(--border);border-radius:16px;overflow:hidden;display:flex;flex-direction:column;height:560px;}
.chat-header{
  padding:18px 24px;border-bottom:1.5px solid var(--border);
  display:flex;align-items:center;gap:12px;
  background:linear-gradient(90deg,var(--red-soft),var(--orange-soft));
}
.ai-avatar{
  width:36px;height:36px;border-radius:50%;
  background:var(--grad-card);display:flex;align-items:center;justify-content:center;
  font-size:1.1rem;flex-shrink:0;
}
.ai-name{font-weight:700;font-size:0.9rem;}
.ai-status{font-size:0.7rem;color:var(--green);display:flex;align-items:center;gap:5px;}
.ai-status::before{content:'';width:6px;height:6px;border-radius:50%;background:var(--green);display:inline-block;}
.chat-messages{flex:1;overflow-y:auto;padding:20px;display:flex;flex-direction:column;gap:14px;}
.msg{max-width:80%;display:flex;flex-direction:column;gap:4px;}
.msg.user{align-self:flex-end;align-items:flex-end;}
.msg.ai{align-self:flex-start;align-items:flex-start;}
.msg-bubble{padding:12px 16px;border-radius:12px;font-size:0.84rem;line-height:1.6;}
.msg.user .msg-bubble{background:var(--grad-card);color:#fff;border-bottom-right-radius:3px;}
.msg.ai .msg-bubble{background:var(--surface2);border:1px solid var(--border);color:var(--ink);border-bottom-left-radius:3px;}
.msg-time{font-size:0.65rem;color:var(--ink3);}
.chat-input-row{padding:16px;border-top:1.5px solid var(--border);display:flex;gap:10px;background:var(--surface);}
.chat-input{
  flex:1;padding:10px 16px;border:1.5px solid var(--border);border-radius:10px;
  font-family:'Outfit',sans-serif;font-size:0.88rem;color:var(--ink);
  background:var(--surface2);resize:none;transition:border-color 0.18s;
}
.chat-input:focus{outline:none;border-color:var(--orange);}
.chat-send{
  padding:10px 18px;background:var(--grad-card);border:none;border-radius:10px;
  color:#fff;font-size:1rem;cursor:pointer;transition:opacity 0.2s;flex-shrink:0;
}
.chat-send:hover{opacity:0.85;}
.chat-send:disabled{opacity:0.4;cursor:not-allowed;}

.ai-sidebar{}
.ai-tips-card{background:var(--surface);border:1.5px solid var(--border);border-radius:16px;padding:22px;margin-bottom:16px;}
.ai-tips-title{font-size:0.7rem;letter-spacing:0.14em;text-transform:uppercase;color:var(--ink3);margin-bottom:14px;}
.ai-tip-btn{
  width:100%;text-align:left;padding:10px 14px;margin-bottom:8px;
  background:var(--surface2);border:1.5px solid var(--border);border-radius:8px;
  font-family:'Outfit',sans-serif;font-size:0.78rem;color:var(--ink2);cursor:pointer;
  transition:all 0.15s;font-weight:500;line-height:1.4;
}
.ai-tip-btn:hover{border-color:var(--orange);color:var(--orange);background:var(--orange-soft);}
.ai-key-card{background:var(--amber-soft);border:1.5px solid rgba(232,160,32,0.3);border-radius:16px;padding:22px;}
.ai-key-title{font-size:0.7rem;letter-spacing:0.14em;text-transform:uppercase;color:var(--amber);margin-bottom:10px;}

/* ── Settings Page ───────────────────────────────────────────── */
.settings-grid{display:grid;grid-template-columns:1fr 1fr;gap:20px;max-width:800px;}
.settings-card{background:var(--surface);border:1.5px solid var(--border);border-radius:16px;padding:28px;}
.settings-section-title{font-size:0.7rem;letter-spacing:0.14em;text-transform:uppercase;color:var(--orange);margin-bottom:18px;display:flex;align-items:center;gap:8px;}
.curr-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:16px;}
.curr-opt{
  padding:10px 6px;text-align:center;
  background:var(--surface2);border:1.5px solid var(--border);
  border-radius:8px;cursor:pointer;font-size:0.76rem;font-weight:600;
  transition:all 0.15s;color:var(--ink2);
}
.curr-opt.active{background:var(--orange-soft);border-color:var(--orange);color:var(--orange);}
.curr-sym{font-size:1.1rem;display:block;margin-bottom:2px;}
.save-btn{
  padding:10px 22px;background:var(--grad-card);border:none;border-radius:8px;
  color:#fff;font-family:'Outfit',sans-serif;font-size:0.82rem;font-weight:700;
  cursor:pointer;transition:opacity 0.2s;
}
.save-btn:hover{opacity:0.85;}
.rates-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;}
.rate-row{
  display:flex;justify-content:space-between;align-items:center;
  padding:9px 12px;background:var(--surface2);border-radius:8px;font-size:0.8rem;
}
.rate-code{font-weight:700;color:var(--ink2);}
.rate-val{font-family:'JetBrains Mono',monospace;color:var(--green);font-size:0.78rem;}

/* ── Toast ───────────────────────────────────────────────────── */
.toast{
  position:fixed;bottom:28px;right:28px;
  background:var(--green);color:#fff;
  padding:12px 22px;border-radius:10px;font-size:0.84rem;font-weight:600;
  display:none;animation:slideIn 0.3s ease;z-index:999;box-shadow:var(--shadow);
}

/* ── Animations ──────────────────────────────────────────────── */
@keyframes fadeUp{from{opacity:0;transform:translateY(14px);}to{opacity:1;transform:translateY(0);}}
@keyframes slideIn{from{opacity:0;transform:translateX(20px);}to{opacity:1;transform:translateX(0);}}
.typing{display:inline-flex;gap:4px;padding:14px 16px;}
.typing span{width:7px;height:7px;border-radius:50%;background:var(--ink3);animation:blink 1.2s infinite;}
.typing span:nth-child(2){animation-delay:0.2s;}
.typing span:nth-child(3){animation-delay:0.4s;}
@keyframes blink{0%,80%,100%{opacity:0.2;}40%{opacity:1;}}

.empty{text-align:center;padding:56px 20px;color:var(--ink3);}
.empty-icon{font-size:2.4rem;opacity:0.3;margin-bottom:10px;}
.empty-text{font-size:0.84rem;}

/* ── Budget Page ─────────────────────────────────────────────── */
.budget-tabs{display:flex;gap:0;border:1.5px solid var(--border);border-radius:10px;overflow:hidden;margin-bottom:28px;max-width:360px;}
.budget-tab{flex:1;padding:10px 20px;border:none;cursor:pointer;font-family:'Outfit',sans-serif;font-size:0.78rem;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;background:transparent;color:var(--ink3);transition:all 0.18s;}
.budget-tab.active{background:var(--orange-soft);color:var(--orange);}
.budget-income-card{background:var(--surface);border:1.5px solid var(--border);border-radius:14px;padding:24px 28px;margin-bottom:20px;display:flex;align-items:center;gap:20px;flex-wrap:wrap;}
.budget-income-label{font-size:0.68rem;letter-spacing:0.14em;text-transform:uppercase;color:var(--ink3);margin-bottom:6px;}
.budget-income-input{font-family:'JetBrains Mono',monospace;font-size:1.5rem;font-weight:500;width:200px;padding:10px 14px;background:var(--surface2);border:1.5px solid var(--border);border-radius:8px;color:var(--ink);transition:border-color 0.18s;}
.budget-income-input:focus{outline:none;border-color:var(--orange);box-shadow:0 0 0 3px rgba(240,112,32,0.1);}
.budget-remaining{margin-left:auto;text-align:right;}
.budget-remaining-label{font-size:0.65rem;letter-spacing:0.12em;text-transform:uppercase;color:var(--ink3);margin-bottom:4px;}
.budget-remaining-amt{font-family:'JetBrains Mono',monospace;font-size:1.3rem;font-weight:600;}
.budget-remaining-amt.ok{color:var(--green);}
.budget-remaining-amt.over{color:var(--red);}
.budget-cats-card{background:var(--surface);border:1.5px solid var(--border);border-radius:14px;overflow:hidden;margin-bottom:20px;}
.budget-cat-row{display:flex;align-items:center;gap:16px;padding:14px 24px;border-bottom:1px solid var(--border);}
.budget-cat-row:last-child{border-bottom:none;}
.budget-cat-name{min-width:160px;font-size:0.86rem;font-weight:500;color:var(--ink);}
.budget-cat-input{width:140px;padding:8px 12px;background:var(--surface2);border:1.5px solid var(--border);border-radius:8px;font-family:'JetBrains Mono',monospace;font-size:0.9rem;color:var(--ink);transition:border-color 0.18s;}
.budget-cat-input:focus{outline:none;border-color:var(--orange);}
.budget-cat-pct{font-size:0.75rem;color:var(--ink3);font-family:'JetBrains Mono',monospace;min-width:50px;text-align:right;}
.budget-slider{flex:1;-webkit-appearance:none;height:4px;border-radius:2px;background:var(--border);cursor:pointer;accent-color:var(--orange);}
.budget-save-btn{padding:13px 32px;background:var(--grad-card);border:none;border-radius:10px;color:#fff;font-family:'Outfit',sans-serif;font-size:0.88rem;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;cursor:pointer;transition:opacity 0.2s,transform 0.15s;margin-bottom:28px;}
.budget-save-btn:hover{opacity:0.9;transform:translateY(-1px);}
.progress-grid{display:flex;flex-direction:column;gap:14px;}
.progress-row{background:var(--surface);border:1.5px solid var(--border);border-radius:12px;padding:18px 22px;}
.progress-row-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;}
.progress-cat{font-size:0.88rem;font-weight:600;}
.progress-nums{font-family:'JetBrains Mono',monospace;font-size:0.82rem;color:var(--ink2);}
.progress-track{height:8px;background:var(--border);border-radius:4px;overflow:hidden;}
.progress-fill{height:100%;border-radius:4px;transition:width 0.6s ease;}
.progress-fill.ok{background:var(--green);}
.progress-fill.warn{background:var(--amber);}
.progress-fill.over{background:var(--red);}
.progress-status{font-size:0.72rem;margin-top:6px;font-weight:500;}
.progress-status.ok{color:var(--green);}
.progress-status.warn{color:var(--amber);}
.progress-status.over{color:var(--red);}
.budget-special-badge{font-size:0.65rem;padding:2px 8px;border-radius:20px;background:var(--amber-soft);color:var(--amber);border:1px solid rgba(232,160,32,0.3);margin-left:8px;font-weight:600;letter-spacing:0.06em;text-transform:uppercase;vertical-align:middle;}

@media(max-width:900px){
  .sidebar{width:200px;}
  .main{margin-left:200px;padding:28px;}
  .cards{grid-template-columns:1fr;}
  .card-hero{grid-column:1;}
  .dash-grid{grid-template-columns:1fr;}
  .ai-layout{grid-template-columns:1fr;}
  .settings-grid{grid-template-columns:1fr;}
  .auth-split{grid-template-columns:1fr;}
  .auth-left{display:none;}
  .budget-cat-row{flex-wrap:wrap;}
  .budget-slider{width:100%;}
}
</style>
</head>
<body>

<!-- ── Auth ───────────────────────────────────────────────────── -->
<div id="auth-screen">
  <div class="auth-split">
    <div class="auth-left">
      <div class="auth-brand">
        <div class="auth-logo">Vau<span>lt</span></div>
        <div class="auth-tagline">Smart Money Manager</div>
      </div>
      <div class="auth-features">
        <div class="auth-feat"><div class="auth-feat-icon">💰</div> Track income &amp; expenses</div>
        <div class="auth-feat"><div class="auth-feat-icon">🌍</div> Live currency conversion</div>
        <div class="auth-feat"><div class="auth-feat-icon">🤖</div> AI budget advisor</div>
        <div class="auth-feat"><div class="auth-feat-icon">📊</div> Visual spending insights</div>
      </div>
    </div>
    <div class="auth-right">
      <div class="auth-tabs">
        <button class="auth-tab active" onclick="switchTab('login')">Sign In</button>
        <button class="auth-tab" onclick="switchTab('signup')">Sign Up</button>
      </div>
      <div class="auth-error" id="auth-error"></div>
      <label class="auth-field-label">Email Address</label>
      <input class="auth-input" type="email" id="auth-email" placeholder="you@example.com"/>
      <label class="auth-field-label">Password</label>
      <input class="auth-input" type="password" id="auth-password" placeholder="••••••••"/>
      <button class="auth-btn" id="auth-btn" onclick="submitAuth()">Sign In →</button>
    </div>
  </div>
</div>

<!-- ── App ────────────────────────────────────────────────────── -->
<div id="app-screen">
  <div class="sidebar">
    <div class="sidebar-logo">Vau<span>lt</span><small>Money Manager</small></div>
    <nav class="nav">
      <div class="nav-section-label">Main</div>
      <div class="nav-item active" onclick="showPage('dashboard')"><span class="nav-icon">◈</span> Dashboard</div>
      <div class="nav-item" onclick="showPage('transactions')"><span class="nav-icon">≡</span> Transactions</div>
      <div class="nav-item" onclick="showPage('add')"><span class="nav-icon">＋</span> Add Entry</div>
      <div class="nav-section-label">Tools</div>
      <div class="nav-item" onclick="showPage('ai')"><span class="nav-icon">🤖</span> AI Advisor</div>
      <div class="nav-item" onclick="showPage('budget')"><span class="nav-icon">📋</span> Budget</div>
      <div class="nav-item" onclick="showPage('settings')"><span class="nav-icon">⚙</span> Settings</div>
    </nav>
    <div class="sidebar-bottom">
      <div class="user-card">
        <div class="user-av" id="user-av">–</div>
        <span class="user-email" id="user-email-display">–</span>
        <button class="logout-btn" onclick="logout()" title="Logout">⏻</button>
      </div>
    </div>
  </div>

  <main class="main">

    <!-- Dashboard -->
    <div class="page active" id="page-dashboard">
      <div class="page-header">
        <div class="page-title">Dashboard</div>
        <div class="page-sub">Your financial overview</div>
      </div>
      <div class="month-nav-row">
        <button class="mnav" onclick="changeMonth(-1)">←</button>
        <div class="mlabel" id="month-label">—</div>
        <button class="mnav" onclick="changeMonth(1)">→</button>
        <div class="currency-badge"><span id="curr-flag">$</span> <span id="curr-code-badge">USD</span></div>
      </div>
      <div class="cards">
        <div class="card card-hero">
          <div class="card-hero-left">
            <div class="card-label">Net Balance</div>
            <div class="card-amount" id="dash-balance">—</div>
          </div>
          <div class="card-hero-right">
            <div class="card-label">This Month</div>
            <div class="mini-stat inc" id="dash-income-mini">—</div>
            <div class="mini-stat exp" id="dash-expense-mini">—</div>
          </div>
        </div>
        <div class="card income">
          <div class="card-icon">↑</div>
          <div class="card-label">Total Income</div>
          <div class="card-amount" id="dash-income">—</div>
        </div>
        <div class="card expense">
          <div class="card-icon">↓</div>
          <div class="card-label">Total Expenses</div>
          <div class="card-amount" id="dash-expense">—</div>
        </div>
        <div class="card" style="background:var(--amber-soft);border:1.5px solid rgba(232,160,32,0.2);">
          <div class="card-icon">%</div>
          <div class="card-label">Savings Rate</div>
          <div class="card-amount" id="dash-savings" style="color:var(--amber);">—</div>
        </div>
      </div>
      <div class="dash-grid">
        <div class="widget">
          <div class="widget-title">Spending by Category <span id="chart-month-label" style="font-size:0.65rem;"></span></div>
          <div class="chart-wrap">
            <canvas id="pie-chart" width="180" height="180" style="max-width:180px;max-height:180px;"></canvas>
            <div class="no-data" id="pie-no-data" style="display:none;">No expense data yet</div>
          </div>
        </div>
        <div style="display:flex;flex-direction:column;gap:16px;">
          <div class="convert-widget">
            <div class="convert-title">🌍 Live Converter</div>
            <div class="convert-row">
              <input class="convert-input" type="number" id="conv-amount" value="100" oninput="doConvert()"/>
              <select class="convert-select" id="conv-from" onchange="doConvert()"></select>
              <span class="convert-arrow">→</span>
              <select class="convert-select" id="conv-to" onchange="doConvert()"></select>
            </div>
            <div class="convert-result" id="conv-result">—</div>
            <div class="convert-rate" id="conv-rate"></div>
          </div>
          <div class="widget">
            <div class="widget-title">Recent Activity</div>
            <div id="recent-list"><div class="no-data">No transactions yet</div></div>
          </div>
        </div>
      </div>
    </div>

    <!-- Transactions -->
    <div class="page" id="page-transactions">
      <div class="page-header">
        <div class="page-title">Transactions</div>
        <div class="page-sub">All your entries</div>
      </div>
      <div class="tx-toolbar">
        <div class="month-nav-row" style="margin-bottom:0;">
          <button class="mnav" onclick="changeMonth(-1)">←</button>
          <div class="mlabel" id="month-label-2">—</div>
          <button class="mnav" onclick="changeMonth(1)">→</button>
        </div>
        <div class="filter-btns">
          <button class="filter-btn active" onclick="setFilter('all',this)">All</button>
          <button class="filter-btn" onclick="setFilter('income',this)">Income</button>
          <button class="filter-btn" onclick="setFilter('expense',this)">Expenses</button>
        </div>
      </div>
      <div class="tx-list" id="tx-list"></div>
    </div>

    <!-- Add Entry -->
    <div class="page" id="page-add">
      <div class="page-header">
        <div class="page-title">Add Entry</div>
        <div class="page-sub">Record income or expense</div>
      </div>
      <div class="add-form">
        <div class="add-card">
          <div class="type-toggle">
            <button class="type-btn income active" id="btn-income" onclick="setType('income')">⬆ Income</button>
            <button class="type-btn expense" id="btn-expense" onclick="setType('expense')">⬇ Expense</button>
          </div>
          <div class="form-row">
            <div class="form-field">
              <label>Amount</label>
              <div class="amount-wrap">
                <span class="amount-pfx" id="add-sym">$</span>
                <input type="number" id="add-amount" placeholder="0.00" min="0.01" step="0.01"/>
              </div>
            </div>
            <div class="form-field">
              <label>Currency</label>
              <select id="add-currency"></select>
            </div>
          </div>
          <div id="cat-section">
            <div class="form-field">
              <label>Category</label>
              <div class="cat-pills" id="cat-pills"></div>
            </div>
          </div>
          <div class="form-row">
            <div class="form-field">
              <label>Date</label>
              <input type="date" id="add-date"/>
            </div>
            <div class="form-field">
              <label>Note <span style="color:var(--ink3);font-size:0.65rem;">(optional)</span></label>
              <input type="text" id="add-note" placeholder="e.g. Monthly salary..."/>
            </div>
          </div>
          <button class="submit-btn" onclick="submitTransaction()">Add Entry →</button>
          <div class="form-error" id="add-error"></div>
        </div>
      </div>
    </div>

    <!-- AI Advisor -->
    <div class="page" id="page-ai">
      <div class="page-header">
        <div class="page-title">AI Advisor</div>
        <div class="page-sub">Powered by Groq · Free · Fast</div>
      </div>
      <div class="ai-layout">
        <div class="chat-card">
          <div class="chat-header">
            <div class="ai-avatar">🤖</div>
            <div>
              <div class="ai-name">Vault AI</div>
              <div class="ai-status">Online · Knows your finances</div>
            </div>
          </div>
          <div class="chat-messages" id="chat-messages">
            <div class="msg ai">
              <div class="msg-bubble">Hi! I'm your personal finance advisor. I have access to all your transaction data. Ask me anything — spending habits, saving tips, budget breakdowns, or how to cut costs. What would you like to know?</div>
              <div class="msg-time">Vault AI</div>
            </div>
          </div>
          <div class="chat-input-row">
            <input class="chat-input" id="chat-input" type="text" placeholder="Ask about your finances..." onkeydown="if(event.key==='Enter')sendChat()"/>
            <button class="chat-send" id="chat-send" onclick="sendChat()">➤</button>
          </div>
        </div>
        <div class="ai-sidebar">
          <div class="ai-tips-card">
            <div class="ai-tips-title">💡 Quick Questions</div>
            <button class="ai-tip-btn" onclick="askQuick('How am I spending my money this month?')">How am I spending my money?</button>
            <button class="ai-tip-btn" onclick="askQuick('What are my biggest expense categories?')">What are my biggest expenses?</button>
            <button class="ai-tip-btn" onclick="askQuick('Give me 3 tips to save more money based on my habits.')">Tips to save more money</button>
            <button class="ai-tip-btn" onclick="askQuick('Am I on track with my spending this month?')">Am I on track this month?</button>
            <button class="ai-tip-btn" onclick="askQuick('Create a simple budget plan for next month based on my history.')">Build a budget plan</button>
          </div>
          <div class="ai-key-card" id="ai-status-card">
            <div class="ai-key-title">⚡ Groq AI</div>
            <div id="ai-status-msg" style="font-size:0.74rem;line-height:1.6;">Checking status...</div>
            <p style="font-size:0.68rem;color:var(--ink3);margin-top:10px;">Model: <code id="groq-model-badge" style="font-size:0.68rem;background:var(--surface2);padding:1px 5px;border-radius:4px;">llama-3.3-70b-versatile</code></p>
          </div>
        </div>
      </div>
    </div>

    <!-- Budget -->
    <div class="page" id="page-budget">
      <div class="page-header">
        <div class="page-title">Budget</div>
        <div class="page-sub">Plan &amp; track your monthly goals</div>
      </div>
      <div class="month-nav-row">
        <button class="mnav" onclick="changeMonth(-1)">←</button>
        <div class="mlabel" id="month-label-budget">—</div>
        <button class="mnav" onclick="changeMonth(1)">→</button>
      </div>
      <div class="budget-tabs">
        <button class="budget-tab active" id="btab-setup" onclick="switchBudgetTab('setup')">Set Goals</button>
        <button class="budget-tab" id="btab-progress" onclick="switchBudgetTab('progress')">Progress</button>
      </div>

      <!-- Set Goals view -->
      <div id="budget-setup-view">
        <div class="budget-income-card">
          <div>
            <div class="budget-income-label">Monthly Income / Reference Budget</div>
            <input class="budget-income-input" type="number" id="budget-income" placeholder="0.00" oninput="onBudgetIncomeChange()"/>
          </div>
          <div class="budget-remaining">
            <div class="budget-remaining-label">Unallocated</div>
            <div class="budget-remaining-amt ok" id="budget-remaining-amt">—</div>
          </div>
        </div>
        <div class="budget-cats-card" id="budget-cats-card">
          <!-- Rows injected by JS -->
        </div>
        <button class="budget-save-btn" onclick="saveBudget()">Save Budget Goals →</button>
      </div>

      <!-- Progress view -->
      <div id="budget-progress-view" style="display:none;">
        <div class="progress-grid" id="progress-grid"></div>
        <div style="margin-top:20px;">
          <button class="budget-save-btn" style="background:var(--surface);border:1.5px solid var(--border);color:var(--ink2);" onclick="switchBudgetTab('setup')">← Edit Goals</button>
        </div>
      </div>
    </div>

    <!-- Settings -->
    <div class="page" id="page-settings">
      <div class="page-header">
        <div class="page-title">Settings</div>
        <div class="page-sub">Preferences &amp; currency</div>
      </div>
      <div class="settings-grid">
        <div class="settings-card">
          <div class="settings-section-title">💱 Display Currency</div>
          <div class="curr-grid" id="curr-grid"></div>
          <button class="save-btn" onclick="saveCurrency()">Save Preference</button>
          <p style="font-size:0.72rem;color:var(--ink3);margin-top:10px;">Transactions are stored as entered. Display currency is for reference.</p>
        </div>
        <div class="settings-card">
          <div class="settings-section-title">🌍 Live Exchange Rates</div>
          <p style="font-size:0.72rem;color:var(--ink3);margin-bottom:14px;">Rates vs USD · Updated hourly</p>
          <div class="rates-grid" id="rates-grid"><div style="color:var(--ink3);font-size:0.8rem;">Loading...</div></div>
        </div>
        <div class="settings-card" style="grid-column:1/-1;">
          <div class="settings-section-title">⚡ AI Advisor — Groq</div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:18px;">
            <div>
              <p style="font-size:0.78rem;color:var(--ink2);line-height:1.7;margin-bottom:10px;">
                The AI advisor uses <strong>Groq's free tier</strong> — up to 14,400 requests/day running Llama 3. No credit card needed.
              </p>
              <p style="font-size:0.72rem;color:var(--ink3);line-height:1.7;">
                1. Sign up free at <strong>console.groq.com</strong><br/>
                2. Create an API key<br/>
                3. Add it as <code style="background:var(--surface2);padding:1px 6px;border-radius:4px;">GROQ_API_KEY</code> in your Render environment variables
              </p>
            </div>
            <div>
              <label style="font-size:0.68rem;letter-spacing:0.12em;text-transform:uppercase;color:var(--ink3);display:block;margin-bottom:7px;">Active Model</label>
              <div style="padding:11px 14px;background:var(--surface2);border:1.5px solid var(--border);border-radius:8px;font-family:'JetBrains Mono',monospace;font-size:0.85rem;color:var(--green);" id="settings-groq-model">llama-3.3-70b-versatile</div>
              <p style="font-size:0.7rem;color:var(--ink3);margin-top:8px;">Other free models: <code>llama-3.1-8b-instant</code>, <code>llama3-70b-8192</code></p>
              <p style="font-size:0.7rem;color:var(--ink3);margin-top:4px;">Set <code>GROQ_MODEL</code> env var in Render to change model.</p>
            </div>
          </div>
        </div>
      </div>
    </div>

  </main>
</div>

<div class="toast" id="toast">✓ Done!</div>

<script>
// ── State ────────────────────────────────────────────────────────
const CURRENCIES = [
  {code:'USD',sym:'$',flag:'🇺🇸'},{code:'GBP',sym:'£',flag:'🇬🇧'},
  {code:'EUR',sym:'€',flag:'🇪🇺'},{code:'INR',sym:'₹',flag:'🇮🇳'},
  {code:'JPY',sym:'¥',flag:'🇯🇵'},{code:'CAD',sym:'C$',flag:'🇨🇦'},
  {code:'AUD',sym:'A$',flag:'🇦🇺'},{code:'AED',sym:'د.إ',flag:'🇦🇪'},
  {code:'SGD',sym:'S$',flag:'🇸🇬'},{code:'CHF',sym:'Fr',flag:'🇨🇭'},
  {code:'CNY',sym:'¥',flag:'🇨🇳'},{code:'MXN',sym:'$',flag:'🇲🇽'},
];

const CATS = {
  expense:['🍔 Food','🏠 Rent','🚗 Transport','🛍 Shopping','💊 Health','🎬 Entertainment','📱 Bills','✈️ Travel','📚 Education','🎁 Gifts','💼 Work','📦 Other'],
  income:['💰 Salary','🔧 Freelance','💵 Investment','🎁 Gift','💳 Refund','📦 Other']
};

let userCurrency = 'USD';
let currentType  = 'income';
let selectedCat  = '';
let allTx        = [];
let txFilter     = 'all';
let liveRates    = {};
let pieChart     = null;
let authMode     = 'login';

const _now = new Date();
let currentMonth = _now.getFullYear() + '-' + String(_now.getMonth()+1).padStart(2,'0');

// ── Helpers ──────────────────────────────────────────────────────
function getCurrInfo(code){ return CURRENCIES.find(c=>c.code===code)||{code,sym:code,flag:''}; }
function fmt(n, code){
  const c = getCurrInfo(code||userCurrency);
  return c.sym + Math.abs(n).toFixed(2);
}
function localToday(){
  const d=new Date();
  return d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0');
}
function toast(msg,color='var(--green)'){
  const t=document.getElementById('toast');
  t.textContent='✓ '+msg; t.style.background=color; t.style.display='block';
  setTimeout(()=>t.style.display='none',2500);
}

// Safe DOM helpers — no innerHTML with user data
function el(tag, attrs={}, ...children){
  const e=document.createElement(tag);
  for(const [k,v] of Object.entries(attrs)){
    if(k==='class') e.className=v;
    else if(k.startsWith('on')) e.addEventListener(k.slice(2),v);
    else e.setAttribute(k,v);
  }
  for(const child of children){
    if(child==null) continue;
    e.appendChild(typeof child==='string' ? document.createTextNode(child) : child);
  }
  return e;
}

// Skeleton loader helper
function skelRow(){
  const row=document.createElement('div');
  row.style.cssText='padding:14px 0;border-bottom:1px solid var(--border);';
  row.innerHTML='<div class="skeleton skel-text short" style="margin-bottom:8px;"></div><div class="skeleton skel-text" style="width:40%;"></div>';
  return row;
}

// ── Auth ─────────────────────────────────────────────────────────
function switchTab(mode){
  authMode=mode;
  document.querySelectorAll('.auth-tab').forEach((t,i)=>t.classList.toggle('active',(mode==='login'&&i===0)||(mode==='signup'&&i===1)));
  document.getElementById('auth-btn').textContent=mode==='login'?'Sign In →':'Create Account →';
  document.getElementById('auth-error').style.display='none';
}
async function submitAuth(){
  const email=document.getElementById('auth-email').value.trim();
  const password=document.getElementById('auth-password').value;
  const errEl=document.getElementById('auth-error');
  errEl.style.display='none';
  if(!email){errEl.textContent='Please enter your email.';errEl.style.display='block';return;}
  if(!password||password.length<6){errEl.textContent='Password must be at least 6 characters.';errEl.style.display='block';return;}
  const btn=document.getElementById('auth-btn');
  btn.textContent='Please wait...';btn.disabled=true;
  try{
    const endpoint=authMode==='login'?'/api/login':'/api/signup';
    const res=await fetch(endpoint,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email,password})});
    let data;
    try{ data=await res.json(); }
    catch(e){
      errEl.textContent='Server error — the database may not be connected yet. Check Render environment variables (DATABASE_URL).';
      errEl.style.display='block';return;
    }
    if(!res.ok){errEl.textContent=data.error||'Something went wrong.';errEl.style.display='block';return;}
    userCurrency=data.currency||'USD';
    showApp(data.email);
  }catch(e){
    errEl.textContent='Network error: '+e.message;errEl.style.display='block';
  }finally{
    btn.textContent=authMode==='login'?'Sign In →':'Create Account →';btn.disabled=false;
  }
}
document.addEventListener('keydown',e=>{if(e.key==='Enter'&&document.getElementById('auth-screen').style.display!=='none')submitAuth();});
async function logout(){
  await fetch('/api/logout',{method:'POST'});
  document.getElementById('app-screen').style.display='none';
  document.getElementById('auth-screen').style.display='flex';
}

// ── App Init ─────────────────────────────────────────────────────
async function showApp(email){
  document.getElementById('auth-screen').style.display='none';
  document.getElementById('app-screen').style.display='block';
  document.getElementById('user-email-display').textContent=email;
  document.getElementById('user-av').textContent=email[0].toUpperCase();
  updateCurrencyUI();
  updateMonthLabels();
  buildCurrencyPickers();
  buildCurrencyGrid();
  await fetchRates();
  buildConverterSelects();
  loadDashboard();
  document.getElementById('add-date').value=localToday();
  setupCatPills();
  showPage('dashboard');
}

// ── Currency ─────────────────────────────────────────────────────
function updateCurrencyUI(){
  const c=getCurrInfo(userCurrency);
  document.getElementById('curr-flag').textContent=c.sym;
  document.getElementById('curr-code-badge').textContent=userCurrency;
  document.getElementById('add-sym').textContent=c.sym;
  document.querySelectorAll('.curr-opt').forEach(el=>el.classList.toggle('active',el.dataset.code===userCurrency));
}
function buildCurrencyGrid(){
  const grid=document.getElementById('curr-grid');
  grid.innerHTML='';
  CURRENCIES.forEach(c=>{
    const div=el('div',{'class':'curr-opt'+(c.code===userCurrency?' active':''),'data-code':c.code,'onclick':()=>selectCurrency(c.code,div)});
    const sym=el('span',{'class':'curr-sym'},c.flag);
    div.appendChild(sym);
    div.appendChild(document.createTextNode(c.code));
    grid.appendChild(div);
  });
}
function selectCurrency(code,divEl){
  userCurrency=code;
  document.querySelectorAll('.curr-opt').forEach(e=>e.classList.remove('active'));
  divEl.classList.add('active');
}
async function saveCurrency(){
  const res=await fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({currency:userCurrency})});
  if(res.ok){ updateCurrencyUI(); buildCurrencyPickers(); toast('Currency saved!'); loadDashboard(); }
}
function buildCurrencyPickers(){
  const addCur=document.getElementById('add-currency');
  if(!addCur) return;
  addCur.innerHTML='';
  CURRENCIES.forEach(c=>{
    const opt=document.createElement('option');
    opt.value=c.code;
    opt.textContent=c.flag+' '+c.code;
    if(c.code===userCurrency) opt.selected=true;
    addCur.appendChild(opt);
  });
}

// ── Live Rates ────────────────────────────────────────────────────
async function fetchRates(){
  try{
    const res=await fetch('/api/rates');
    liveRates=await res.json();
    buildRatesGrid();
  }catch(e){console.warn('Rates unavailable',e);}
}
function buildRatesGrid(){
  const grid=document.getElementById('rates-grid');
  if(!grid) return;
  grid.innerHTML='';
  const show=['EUR','GBP','INR','JPY','CAD','AUD','AED','SGD','CHF','CNY'];
  show.forEach(code=>{
    const r=liveRates[code];
    const row=el('div',{'class':'rate-row'},
      el('span',{'class':'rate-code'},code),
      el('span',{'class':'rate-val'},r?r.toFixed(4):'—')
    );
    grid.appendChild(row);
  });
}
function buildConverterSelects(){
  const makeOpts=sel=>{
    sel.innerHTML='';
    CURRENCIES.forEach(c=>{
      const opt=document.createElement('option');
      opt.value=c.code; opt.textContent=c.flag+' '+c.code;
      sel.appendChild(opt);
    });
  };
  const from=document.getElementById('conv-from');
  const to=document.getElementById('conv-to');
  makeOpts(from); makeOpts(to);
  from.value=userCurrency;
  to.value=userCurrency==='USD'?'EUR':'USD';
  doConvert();
}
function doConvert(){
  const amount=parseFloat(document.getElementById('conv-amount').value)||0;
  const from=document.getElementById('conv-from').value;
  const to=document.getElementById('conv-to').value;
  if(!liveRates[from]||!liveRates[to]){document.getElementById('conv-result').textContent='—';return;}
  const amtUSD=amount/liveRates[from];
  const result=amtUSD*liveRates[to];
  const toSym=getCurrInfo(to).sym;
  const fromSym=getCurrInfo(from).sym;
  document.getElementById('conv-result').textContent=toSym+result.toFixed(2);
  const rate=(liveRates[to]/liveRates[from]);
  document.getElementById('conv-rate').textContent='1 '+from+' = '+toSym+rate.toFixed(4)+' '+to+' · Live rate';
}

// ── Navigation ────────────────────────────────────────────────────
function showPage(name){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
  document.getElementById('page-'+name).classList.add('active');
  const map={dashboard:0,transactions:1,add:2,ai:3,budget:4,settings:5};
  document.querySelectorAll('.nav-item')[map[name]]?.classList.add('active');
  if(name==='dashboard')loadDashboard();
  if(name==='transactions')loadTransactions();
  if(name==='settings'){fetchRates();buildRatesGrid();}
  if(name==='budget'){loadBudgetPage();}
}

// ── Month ─────────────────────────────────────────────────────────
function changeMonth(dir){
  let [y,m]=currentMonth.split('-').map(Number);
  m+=dir;
  if(m>12){m=1;y++;} if(m<1){m=12;y--;}
  currentMonth=y+'-'+String(m).padStart(2,'0');
  updateMonthLabels();
  const active=document.querySelector('.page.active');
  if(active?.id==='page-dashboard') loadDashboard();
  else if(active?.id==='page-transactions') loadTransactions();
  else if(active?.id==='page-budget') loadBudgetPage();
}
function updateMonthLabels(){
  const [y,m]=currentMonth.split('-').map(Number);
  const label=new Date(y,m-1,1).toLocaleDateString('en-GB',{month:'long',year:'numeric'});
  document.getElementById('month-label').textContent=label;
  document.getElementById('month-label-2').textContent=label;
  const el2=document.getElementById('chart-month-label');
  if(el2) el2.textContent=label;
  const el3=document.getElementById('month-label-budget');
  if(el3) el3.textContent=label;
}

// ── Dashboard ─────────────────────────────────────────────────────
function showDashboardSkeleton(){
  // Show skeleton in cards while loading
  ['dash-balance','dash-income','dash-expense','dash-savings'].forEach(id=>{
    const e=document.getElementById(id);
    if(e){ e.innerHTML='<div class="skeleton skel-amount"></div>'; }
  });
  document.getElementById('dash-income-mini').textContent='—';
  document.getElementById('dash-expense-mini').textContent='—';
  const list=document.getElementById('recent-list');
  list.innerHTML='';
  for(let i=0;i<4;i++) list.appendChild(skelRow());
}

async function loadDashboard(){
  showDashboardSkeleton();
  try{
    const [sumRes,txRes]=await Promise.all([
      fetch('/api/summary?month='+currentMonth),
      fetch('/api/transactions?month='+currentMonth)
    ]);
    const sum=await sumRes.json();
    const txs=await txRes.json();

    const sym=getCurrInfo(userCurrency).sym;
    const bal=sum.balance;

    const balEl=document.getElementById('dash-balance');
    balEl.textContent=(bal<0?'-':'')+sym+Math.abs(bal).toFixed(2);
    balEl.style.color=bal>=0?'#6ee7a0':'#fca89a';

    document.getElementById('dash-income').textContent=sym+sum.income.toFixed(2);
    document.getElementById('dash-expense').textContent=sym+sum.expenses.toFixed(2);
    document.getElementById('dash-income-mini').textContent='↑ '+sym+sum.income.toFixed(2)+' income';
    document.getElementById('dash-expense-mini').textContent='↓ '+sym+sum.expenses.toFixed(2)+' spent';

    const savings=sum.income>0?Math.round(((sum.income-sum.expenses)/sum.income)*100):0;
    document.getElementById('dash-savings').textContent=savings+'%';

    // Pie chart
    const canvas=document.getElementById('pie-chart');
    const noData=document.getElementById('pie-no-data');
    const cats=sum.categories;
    if(pieChart){pieChart.destroy();pieChart=null;}
    if(Object.keys(cats).length===0){
      canvas.style.display='none';noData.style.display='block';
    } else {
      canvas.style.display='block';noData.style.display='none';
      const colors=['#e03c2a','#f07020','#e8a020','#2a9a50','#f5c842','#e87040','#c03020','#d4600a','#b8901a','#1a7a40'];
      pieChart=new Chart(canvas,{
        type:'doughnut',
        data:{labels:Object.keys(cats),datasets:[{data:Object.values(cats),backgroundColor:colors,borderWidth:0,hoverOffset:6}]},
        options:{responsive:true,plugins:{legend:{display:false},tooltip:{callbacks:{label:ctx=>sym+ctx.parsed.toFixed(2)}}},cutout:'62%'}
      });
    }

    // Recent list — built with DOM API (no innerHTML with user data)
    const list=document.getElementById('recent-list');
    list.innerHTML='';
    if(txs.length===0){
      list.innerHTML='<div class="no-data">No transactions yet</div>';
      return;
    }
    txs.slice(0,5).forEach(t=>{
      const txSym=getCurrInfo(t.currency||userCurrency).sym;
      const row=el('div',{'class':'tx-mini'});
      const left=el('div',{'class':'tx-mini-left'});
      left.appendChild(el('div',{'class':'tx-mini-cat'},t.category||'—'));
      if(t.note) left.appendChild(el('div',{'class':'tx-mini-note'},t.note));
      const right=el('div',{'class':'tx-mini-right'});
      const amt=el('div',{'class':'tx-mini-amt '+t.type},(t.type==='income'?'+':'-')+txSym+t.amount.toFixed(2));
      const dateEl=el('div',{'class':'tx-mini-date'},t.date);
      right.appendChild(amt); right.appendChild(dateEl);
      row.appendChild(left); row.appendChild(right);
      list.appendChild(row);
    });
  }catch(e){
    console.error('Dashboard load error',e);
  }
}

// ── Transactions ──────────────────────────────────────────────────
function setFilter(f,elBtn){
  txFilter=f;
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  elBtn.classList.add('active');
  renderTx();
}

function showTransactionsSkeleton(){
  const list=document.getElementById('tx-list');
  list.innerHTML='';
  for(let i=0;i<6;i++){
    const row=document.createElement('div');
    row.style.cssText='background:var(--surface);border:1.5px solid var(--border);border-radius:12px;padding:20px;margin-bottom:8px;';
    row.innerHTML='<div class="skeleton skel-text short" style="margin-bottom:10px;"></div><div class="skeleton skel-text" style="width:30%;"></div>';
    list.appendChild(row);
  }
}

async function loadTransactions(){
  showTransactionsSkeleton();
  try{
    const res=await fetch('/api/transactions?month='+currentMonth);
    allTx=await res.json();
    renderTx();
  }catch(e){
    console.error('Transaction load error',e);
    document.getElementById('tx-list').innerHTML='<div class="empty"><div class="empty-text">Failed to load transactions.</div></div>';
  }
}

// Build transaction rows with DOM API — no innerHTML with user-supplied data
function renderTx(){
  const filtered=txFilter==='all'?allTx:allTx.filter(t=>t.type===txFilter);
  const list=document.getElementById('tx-list');
  list.innerHTML='';
  if(filtered.length===0){
    const empty=el('div',{'class':'empty'},el('div',{'class':'empty-icon'},'◈'),el('div',{'class':'empty-text'},'No transactions found'));
    list.appendChild(empty);
    return;
  }
  filtered.forEach(t=>{
    const txSym=getCurrInfo(t.currency||userCurrency).sym;
    const row=el('div',{'class':'tx-row'});
    row.appendChild(el('div',{'class':'tx-dot '+t.type}));
    const info=el('div',{'class':'tx-info'});
    info.appendChild(el('div',{'class':'tx-cat'},t.category||'—'));
    if(t.note) info.appendChild(el('div',{'class':'tx-note'},t.note));
    row.appendChild(info);
    row.appendChild(el('div',{'class':'tx-date'},t.date));
    row.appendChild(el('div',{'class':'tx-cur'},t.currency||userCurrency));
    row.appendChild(el('div',{'class':'tx-amount '+t.type},(t.type==='income'?'+':'-')+txSym+t.amount.toFixed(2)));
    const del=el('button',{'class':'tx-del','title':'Delete','onclick':()=>deleteTx(t.id)},'✕');
    row.appendChild(del);
    list.appendChild(row);
  });
}

async function deleteTx(id){
  if(!confirm('Delete this transaction?')) return;
  await fetch('/api/transactions/'+id,{method:'DELETE'});
  allTx=allTx.filter(t=>t.id!==id);
  renderTx();
  loadDashboard();
}

// ── Add Entry ─────────────────────────────────────────────────────
function setType(type){
  currentType=type;
  document.getElementById('btn-income').className='type-btn income'+(type==='income'?' active':'');
  document.getElementById('btn-expense').className='type-btn expense'+(type==='expense'?' active':'');
  document.getElementById('cat-section').style.display=type==='expense'?'block':'none';
  selectedCat='';
  setupCatPills();
}
function setupCatPills(){
  const cats=CATS[currentType]||[];
  const container=document.getElementById('cat-pills');
  if(!container) return;
  container.innerHTML='';
  cats.forEach(c=>{
    const pill=el('div',{'class':'cat-pill'+(c===selectedCat?' active':''),'onclick':()=>selectCat(pill,c)},c);
    container.appendChild(pill);
  });
}
function selectCat(pillEl,cat){
  selectedCat=cat;
  document.querySelectorAll('.cat-pill').forEach(p=>p.classList.remove('active'));
  pillEl.classList.add('active');
}
async function submitTransaction(){
  const amount=document.getElementById('add-amount').value;
  const currency=document.getElementById('add-currency').value||userCurrency;
  const txDate=document.getElementById('add-date').value;
  const note=document.getElementById('add-note').value.trim();
  const errEl=document.getElementById('add-error');
  errEl.style.display='none';
  if(!amount||isNaN(parseFloat(amount))||parseFloat(amount)<=0){
    errEl.textContent='Please enter a valid amount greater than 0.';errEl.style.display='block';return;
  }
  if(!txDate){errEl.textContent='Please select a date.';errEl.style.display='block';return;}
  const category=currentType==='expense'?selectedCat||'Other':'Income';
  const res=await fetch('/api/transactions',{
    method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({type:currentType,amount:parseFloat(amount),currency,category,note,date:txDate})
  });
  const data=await res.json();
  if(!res.ok){errEl.textContent=data.error;errEl.style.display='block';return;}
  document.getElementById('add-amount').value='';
  document.getElementById('add-note').value='';
  document.getElementById('add-date').value=localToday();
  selectedCat='';
  setupCatPills();
  toast('Entry added!');
}

// ── AI Chat ───────────────────────────────────────────────────────
function askQuick(msg){
  document.getElementById('chat-input').value=msg;
  sendChat();
}
async function sendChat(){
  const input=document.getElementById('chat-input');
  const msg=input.value.trim();
  if(!msg) return;
  input.value='';
  appendMsg('user',msg);
  const send=document.getElementById('chat-send');
  send.disabled=true;
  const typingId='typing-'+Date.now();
  const messages=document.getElementById('chat-messages');
  const typingDiv=el('div',{'class':'msg ai','id':typingId},
    el('div',{'class':'msg-bubble'},
      el('div',{'class':'typing'},el('span'),el('span'),el('span'))
    )
  );
  messages.appendChild(typingDiv);
  messages.scrollTop=messages.scrollHeight;
  try{
    const res=await fetch('/api/ai-chat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message:msg})});
    const data=await res.json();
    document.getElementById(typingId)?.remove();
    send.disabled=false;
    if(data.error==='no_key'){
      appendMsg('ai','⚠️ Groq API key not set. Add GROQ_API_KEY to your Render environment variables.\n\nGet a free key at console.groq.com');
    } else if(data.error){
      appendMsg('ai','⚠️ Error: '+data.error);
    } else {
      appendMsg('ai',data.reply);
    }
  }catch(e){
    document.getElementById(typingId)?.remove();
    send.disabled=false;
    appendMsg('ai','⚠️ Network error. Please try again.');
  }
}

// Safe message renderer — uses createTextNode, never innerHTML
function appendMsg(role,text){
  const messages=document.getElementById('chat-messages');
  const time=new Date().toLocaleTimeString('en-GB',{hour:'2-digit',minute:'2-digit'});
  const label=role==='user'?'You':'Vault AI';
  const bubble=document.createElement('div');
  bubble.className='msg-bubble';
  text.split('\n').forEach((line,i)=>{
    if(i>0) bubble.appendChild(document.createElement('br'));
    bubble.appendChild(document.createTextNode(line));
  });
  const timeDiv=el('div',{'class':'msg-time'},label+' · '+time);
  const div=el('div',{'class':'msg '+role});
  div.appendChild(bubble);
  div.appendChild(timeDiv);
  messages.appendChild(div);
  messages.scrollTop=messages.scrollHeight;
}

// ── Budget ────────────────────────────────────────────────────────
const BUDGET_CATS = [
  '🍔 Food','🏠 Rent','🚗 Transport','🛍 Shopping','💊 Health',
  '🎬 Entertainment','📱 Bills','✈️ Travel','📚 Education','🎁 Gifts','💼 Work','📦 Other',
  'Savings'   // special: treated as income - expenses
];

let budgetGoals   = {};  // {category: amount}
let budgetTab     = 'setup';

function switchBudgetTab(tab){
  budgetTab=tab;
  document.getElementById('btab-setup').classList.toggle('active', tab==='setup');
  document.getElementById('btab-progress').classList.toggle('active', tab==='progress');
  document.getElementById('budget-setup-view').style.display   = tab==='setup'   ? '' : 'none';
  document.getElementById('budget-progress-view').style.display = tab==='progress' ? '' : 'none';
  if(tab==='progress') renderBudgetProgress();
}

async function loadBudgetPage(){
  // Load saved goals for this month
  try{
    const res = await fetch('/api/budget?month='+currentMonth);
    const rows = await res.json();
    budgetGoals = {};
    if(Array.isArray(rows)) rows.forEach(r=>{ budgetGoals[r.category]=r.goal_amount; });
  }catch(e){ console.warn('budget load error',e); }
  renderBudgetSetup();
}

function onBudgetIncomeChange(){
  updateBudgetRemaining();
}

function updateBudgetRemaining(){
  const income = parseFloat(document.getElementById('budget-income').value)||0;
  const allocated = Object.values(budgetGoals).reduce((a,b)=>a+(b||0),0);
  const remaining = income - allocated;
  const el2 = document.getElementById('budget-remaining-amt');
  const sym  = getCurrInfo(userCurrency).sym;
  el2.textContent = (remaining<0?'-':'') + sym + Math.abs(remaining).toFixed(2);
  el2.className   = 'budget-remaining-amt ' + (remaining<0?'over':'ok');
}

function renderBudgetSetup(){
  const container = document.getElementById('budget-cats-card');
  container.innerHTML='';
  const sym = getCurrInfo(userCurrency).sym;

  BUDGET_CATS.forEach(cat=>{
    const row = el('div',{'class':'budget-cat-row'});

    // Category label
    const nameWrap = el('div',{'class':'budget-cat-name'});
    nameWrap.appendChild(document.createTextNode(cat));
    if(cat==='Savings'){
      const badge = el('span',{'class':'budget-special-badge'},'auto');
      nameWrap.appendChild(badge);
    }
    row.appendChild(nameWrap);

    // Amount input
    const input = el('input',{
      'class':'budget-cat-input',
      'type':'number',
      'placeholder': sym+'0',
      'value': budgetGoals[cat]!=null ? budgetGoals[cat].toFixed(2) : '',
      'min':'0','step':'0.01'
    });
    input.addEventListener('input', ()=>{
      const v = parseFloat(input.value)||0;
      budgetGoals[cat] = v;
      updateBudgetRemaining();
      pctEl.textContent = getPctLabel(cat, income());
    });
    row.appendChild(input);

    // Slider (0 to income or 50000)
    const slider = el('input',{
      'class':'budget-slider',
      'type':'range',
      'min':'0','step':'100',
      'value': budgetGoals[cat]||0
    });
    // Sync slider max with income input dynamically
    const syncMax = ()=>{ slider.max = Math.max(parseFloat(document.getElementById('budget-income').value)||50000, 50000); };
    syncMax();
    slider.addEventListener('input', ()=>{
      const v = parseFloat(slider.value)||0;
      input.value = v.toFixed(2);
      budgetGoals[cat] = v;
      updateBudgetRemaining();
      pctEl.textContent = getPctLabel(cat, income());
    });
    input.addEventListener('input', ()=>{ slider.value = parseFloat(input.value)||0; });
    document.getElementById('budget-income').addEventListener('input', syncMax);
    row.appendChild(slider);

    // Percentage label
    const pctEl = el('div',{'class':'budget-cat-pct'}, getPctLabel(cat, income()));
    row.appendChild(pctEl);

    container.appendChild(row);
  });

  updateBudgetRemaining();

  function income(){ return parseFloat(document.getElementById('budget-income').value)||0; }
  function getPctLabel(cat, inc){
    if(!inc) return '—';
    const v = budgetGoals[cat]||0;
    return Math.round((v/inc)*100)+'%';
  }
}

async function saveBudget(){
  const income = parseFloat(document.getElementById('budget-income').value)||0;
  const goals  = BUDGET_CATS
    .filter(cat=> (budgetGoals[cat]||0) > 0)
    .map(cat=>({ category: cat, goal_amount: budgetGoals[cat], currency: userCurrency }));
  if(goals.length===0){
    toast('Set at least one goal amount first.', 'var(--amber)');
    return;
  }
  try{
    const res = await fetch('/api/budget',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ month: currentMonth, goals, currency: userCurrency })
    });
    const data = await res.json();
    if(!res.ok){ toast(data.error||'Could not save.','var(--red)'); return; }
    toast('Budget saved!');
    switchBudgetTab('progress');
  }catch(e){
    toast('Save failed.','var(--red)');
  }
}

async function renderBudgetProgress(){
  const grid = document.getElementById('progress-grid');
  grid.innerHTML='<div class="no-data">Loading...</div>';
  try{
    const res  = await fetch('/api/budget/progress?month='+currentMonth);
    const data = await res.json();
    const rows = data.progress||[];
    grid.innerHTML='';
    if(rows.length===0){
      grid.innerHTML='<div class="empty"><div class="empty-icon">📋</div><div class="empty-text">No budget goals set yet.<br/>Switch to Set Goals to create your plan.</div></div>';
      return;
    }
    const sym = getCurrInfo(userCurrency).sym;
    rows.forEach(r=>{
      const pct     = r.goal>0 ? Math.min((r.actual/r.goal)*100, 100) : 0;
      const overPct = r.goal>0 ? (r.actual/r.goal)*100 : 0;
      const isSavings = r.category==='Savings';
      // For savings: green if actual >= goal, amber if within 20%, red if way under
      let state;
      if(isSavings){
        state = r.actual>=r.goal ? 'ok' : (r.actual>=r.goal*0.75 ? 'warn' : 'over');
      } else {
        state = overPct<=80 ? 'ok' : overPct<=100 ? 'warn' : 'over';
      }

      const row = el('div',{'class':'progress-row'});
      const header = el('div',{'class':'progress-row-header'});
      const catEl  = el('div',{'class':'progress-cat'}, r.category);
      if(isSavings){
        const badge = el('span',{'class':'budget-special-badge'},'savings');
        catEl.appendChild(badge);
      }
      const numsEl = el('div',{'class':'progress-nums'}, sym+r.actual.toFixed(2)+' / '+sym+r.goal.toFixed(2));
      header.appendChild(catEl);
      header.appendChild(numsEl);
      row.appendChild(header);

      const track = el('div',{'class':'progress-track'});
      const fill  = el('div',{'class':'progress-fill '+state});
      fill.style.width = pct.toFixed(1)+'%';
      track.appendChild(fill);
      row.appendChild(track);

      let statusText;
      if(isSavings){
        const diff = r.actual - r.goal;
        statusText = diff>=0 ? '✓ Goal met! '+sym+diff.toFixed(2)+' ahead' : sym+Math.abs(diff).toFixed(2)+' short of goal';
      } else {
        const rem = r.goal - r.actual;
        statusText = rem>0 ? sym+rem.toFixed(2)+' remaining' : sym+Math.abs(rem).toFixed(2)+' over budget';
      }
      row.appendChild(el('div',{'class':'progress-status '+state}, statusText));
      grid.appendChild(row);
    });
  }catch(e){
    grid.innerHTML='<div class="empty"><div class="empty-text">Failed to load progress.</div></div>';
  }
}

// ── Boot ──────────────────────────────────────────────────────────
(async()=>{
  const res=await fetch('/api/me');
  const data=await res.json();
  if(data.logged_in){
    userCurrency=data.currency||'USD';
    const model=data.groq_model||'llama-3.3-70b-versatile';
    const mb=document.getElementById('groq-model-badge');
    const sb=document.getElementById('settings-groq-model');
    if(mb) mb.textContent=model;
    if(sb) sb.textContent=model;
    const statusMsg=document.getElementById('ai-status-msg');
    if(statusMsg){
      if(data.groq_ready){
        statusMsg.innerHTML='<span style="color:var(--green);">✓ Groq is configured and ready.</span><br/><span style="font-size:0.68rem;color:var(--ink3);">Free tier · ~14,400 requests/day</span>';
      } else {
        statusMsg.innerHTML='<span style="color:var(--amber);">⚠ GROQ_API_KEY not set.</span><br/><span style="font-size:0.68rem;color:var(--ink3);">Add it in Render → Environment → GROQ_API_KEY<br/>Get a free key at console.groq.com</span>';
      }
    }
    showApp(data.email);
  }
})();
</script>
</body>
</html>"""

if __name__ == "__main__":
    init_db()
    print("\n💰 Vault — Money Manager v4")
    print("═" * 44)
    print("  Open:  http://localhost:5000")
    print("  Stop:  Ctrl+C")
    print("  DB:    PostgreSQL (persistent)")
    print("═" * 44 + "\n")
    app.run(debug=DEBUG, port=5000)