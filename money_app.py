#!/usr/bin/env python3
"""
💰 Money Managing App — MVP
Run: pip install flask && python money_app.py
Then open: http://localhost:5000
"""

from flask import Flask, request, jsonify, session, redirect, url_for
import sqlite3, hashlib, os, json
from datetime import datetime, date
from functools import wraps

app = Flask(__name__)
app.secret_key = os.urandom(24)
DB = "money_app.db"

# ─── Database ────────────────────────────────────────────────────────────────

def get_db():
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            amount REAL NOT NULL,
            category TEXT,
            note TEXT,
            date TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    """)
    db.commit()
    db.close()

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

# ─── Auth Routes ─────────────────────────────────────────────────────────────

@app.route("/api/signup", methods=["POST"])
def signup():
    data = request.json
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    db = get_db()
    try:
        db.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, hash_pw(password)))
        db.commit()
        user = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        session["user_id"] = user["id"]
        session["email"] = email
        return jsonify({"success": True, "email": email})
    except sqlite3.IntegrityError:
        return jsonify({"error": "Email already registered"}), 409
    finally:
        db.close()

@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email=? AND password=?", (email, hash_pw(password))).fetchone()
    db.close()
    if not user:
        return jsonify({"error": "Invalid email or password"}), 401
    session["user_id"] = user["id"]
    session["email"] = user["email"]
    return jsonify({"success": True, "email": user["email"]})

@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"success": True})

@app.route("/api/me")
def me():
    if "user_id" not in session:
        return jsonify({"logged_in": False})
    return jsonify({"logged_in": True, "email": session.get("email")})

# ─── Transaction Routes ───────────────────────────────────────────────────────

@app.route("/api/transactions", methods=["GET"])
@login_required
def get_transactions():
    month = request.args.get("month", datetime.now().strftime("%Y-%m"))
    db = get_db()
    rows = db.execute(
        "SELECT * FROM transactions WHERE user_id=? AND date LIKE ? ORDER BY date DESC, id DESC",
        (session["user_id"], f"{month}%")
    ).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/transactions", methods=["POST"])
@login_required
def add_transaction():
    data = request.json
    tx_type = data.get("type")
    amount = data.get("amount")
    category = data.get("category", "Other")
    note = data.get("note", "")
    tx_date = data.get("date", str(date.today()))
    if tx_type not in ("income", "expense"):
        return jsonify({"error": "Type must be income or expense"}), 400
    try:
        amount = float(amount)
        if amount <= 0:
            raise ValueError()
    except (TypeError, ValueError):
        return jsonify({"error": "Amount must be a positive number"}), 400
    db = get_db()
    db.execute(
        "INSERT INTO transactions (user_id, type, amount, category, note, date) VALUES (?,?,?,?,?,?)",
        (session["user_id"], tx_type, amount, category, note, tx_date)
    )
    db.commit()
    db.close()
    return jsonify({"success": True})

@app.route("/api/transactions/<int:tx_id>", methods=["DELETE"])
@login_required
def delete_transaction(tx_id):
    db = get_db()
    db.execute("DELETE FROM transactions WHERE id=? AND user_id=?", (tx_id, session["user_id"]))
    db.commit()
    db.close()
    return jsonify({"success": True})

@app.route("/api/summary")
@login_required
def summary():
    month = request.args.get("month", datetime.now().strftime("%Y-%m"))
    db = get_db()
    rows = db.execute(
        "SELECT type, category, amount FROM transactions WHERE user_id=? AND date LIKE ?",
        (session["user_id"], f"{month}%")
    ).fetchall()
    db.close()
    income = sum(r["amount"] for r in rows if r["type"] == "income")
    expenses = sum(r["amount"] for r in rows if r["type"] == "expense")
    cats = {}
    for r in rows:
        if r["type"] == "expense":
            cats[r["category"]] = cats.get(r["category"], 0) + r["amount"]
    return jsonify({
        "income": income,
        "expenses": expenses,
        "balance": income - expenses,
        "categories": cats
    })

# ─── Frontend (Single HTML Page) ─────────────────────────────────────────────

@app.route("/")
def index():
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Vault — Money Manager</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:ital,wght@0,400;0,700;1,400&family=DM+Mono:wght@300;400;500&family=DM+Sans:wght@300;400;500&display=swap" rel="stylesheet"/>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
:root {
  --bg: #0a0a0f;
  --surface: #12121a;
  --surface2: #1a1a26;
  --border: #2a2a3a;
  --gold: #c9a84c;
  --gold-light: #e8c96a;
  --gold-dim: #7a6230;
  --green: #4caf82;
  --red: #cf6679;
  --text: #e8e4d8;
  --muted: #6b6880;
  --accent: #7b6cff;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html, body { height: 100%; background: var(--bg); color: var(--text); font-family: 'DM Sans', sans-serif; }

/* Noise texture overlay */
body::before {
  content: '';
  position: fixed; inset: 0;
  background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.04'/%3E%3C/svg%3E");
  pointer-events: none; z-index: 9999; opacity: 0.6;
}

/* Auth Screen */
#auth-screen {
  display: flex; align-items: center; justify-content: center;
  min-height: 100vh; padding: 20px;
  background: radial-gradient(ellipse at 30% 20%, #1e1a2e 0%, var(--bg) 60%),
              radial-gradient(ellipse at 80% 80%, #1a1510 0%, transparent 50%);
}
.auth-box {
  width: 100%; max-width: 420px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 56px 48px;
  position: relative;
  animation: fadeUp 0.6s ease both;
}
.auth-box::before {
  content: '';
  position: absolute; top: 0; left: 48px; right: 48px; height: 1px;
  background: linear-gradient(90deg, transparent, var(--gold), transparent);
}
.auth-logo {
  font-family: 'Playfair Display', serif;
  font-size: 2rem; font-weight: 700;
  color: var(--gold); letter-spacing: 0.08em;
  margin-bottom: 6px;
}
.auth-tagline {
  font-size: 0.8rem; color: var(--muted);
  letter-spacing: 0.15em; text-transform: uppercase;
  margin-bottom: 44px;
}
.auth-tabs {
  display: flex; gap: 0; margin-bottom: 32px;
  border-bottom: 1px solid var(--border);
}
.auth-tab {
  flex: 1; padding: 10px; cursor: pointer;
  font-size: 0.8rem; letter-spacing: 0.12em; text-transform: uppercase;
  color: var(--muted); border-bottom: 2px solid transparent;
  margin-bottom: -1px; transition: all 0.2s; text-align: center;
  background: none; border-top: none; border-left: none; border-right: none;
}
.auth-tab.active { color: var(--gold); border-bottom-color: var(--gold); }
.field { margin-bottom: 20px; }
.field label {
  display: block; font-size: 0.7rem; letter-spacing: 0.15em;
  text-transform: uppercase; color: var(--muted); margin-bottom: 8px;
}
.field input {
  width: 100%; padding: 12px 16px;
  background: var(--bg); border: 1px solid var(--border);
  border-radius: 3px; color: var(--text);
  font-family: 'DM Mono', monospace; font-size: 0.9rem;
  transition: border-color 0.2s;
}
.field input:focus { outline: none; border-color: var(--gold-dim); }
.btn-primary {
  width: 100%; padding: 14px;
  background: linear-gradient(135deg, var(--gold), var(--gold-dim));
  border: none; border-radius: 3px;
  font-family: 'DM Sans', sans-serif;
  font-size: 0.85rem; letter-spacing: 0.12em; text-transform: uppercase;
  color: #0a0805; font-weight: 600; cursor: pointer;
  transition: opacity 0.2s, transform 0.15s;
  margin-top: 8px;
}
.btn-primary:hover { opacity: 0.9; transform: translateY(-1px); }
.auth-error {
  background: rgba(207, 102, 121, 0.1); border: 1px solid rgba(207,102,121,0.3);
  color: var(--red); padding: 10px 14px; border-radius: 3px;
  font-size: 0.8rem; margin-bottom: 16px; display: none;
}

/* App Screen */
#app-screen { display: none; min-height: 100vh; }
.sidebar {
  position: fixed; left: 0; top: 0; bottom: 0; width: 240px;
  background: var(--surface); border-right: 1px solid var(--border);
  display: flex; flex-direction: column; padding: 32px 0; z-index: 100;
}
.sidebar-logo {
  font-family: 'Playfair Display', serif; font-size: 1.5rem; font-weight: 700;
  color: var(--gold); padding: 0 28px 32px; border-bottom: 1px solid var(--border);
  letter-spacing: 0.06em;
}
.sidebar-logo span { font-style: italic; }
.nav { padding: 24px 0; flex: 1; }
.nav-item {
  display: flex; align-items: center; gap: 12px;
  padding: 12px 28px; cursor: pointer;
  font-size: 0.85rem; color: var(--muted);
  transition: all 0.15s; border-left: 2px solid transparent;
}
.nav-item:hover { color: var(--text); background: rgba(255,255,255,0.02); }
.nav-item.active { color: var(--gold); border-left-color: var(--gold); background: rgba(201,168,76,0.05); }
.nav-icon { width: 18px; text-align: center; font-size: 1rem; }
.sidebar-user {
  padding: 20px 28px; border-top: 1px solid var(--border);
  display: flex; align-items: center; gap: 10px;
}
.user-avatar {
  width: 32px; height: 32px; border-radius: 50%;
  background: linear-gradient(135deg, var(--gold-dim), var(--accent));
  display: flex; align-items: center; justify-content: center;
  font-size: 0.75rem; font-weight: 600; color: var(--text); flex-shrink: 0;
}
.user-email { font-size: 0.75rem; color: var(--muted); flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.logout-btn {
  background: none; border: none; color: var(--muted);
  cursor: pointer; font-size: 0.85rem; padding: 4px;
  transition: color 0.2s;
}
.logout-btn:hover { color: var(--red); }

.main { margin-left: 240px; padding: 48px; min-height: 100vh; }
.page { display: none; animation: fadeUp 0.4s ease both; }
.page.active { display: block; }
.page-title {
  font-family: 'Playfair Display', serif; font-size: 2rem; font-weight: 700;
  margin-bottom: 8px;
}
.page-subtitle { font-size: 0.8rem; color: var(--muted); letter-spacing: 0.1em; text-transform: uppercase; margin-bottom: 40px; }

/* Month picker */
.month-row { display: flex; align-items: center; gap: 16px; margin-bottom: 36px; }
.month-nav {
  background: var(--surface); border: 1px solid var(--border);
  color: var(--text); padding: 8px 14px; border-radius: 3px; cursor: pointer;
  font-size: 0.9rem; transition: border-color 0.2s;
}
.month-nav:hover { border-color: var(--gold-dim); }
.month-label { font-family: 'Playfair Display', serif; font-size: 1.1rem; min-width: 140px; text-align: center; }

/* Dashboard cards */
.cards { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 36px; }
.card {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 4px; padding: 28px; position: relative; overflow: hidden;
}
.card::after {
  content: ''; position: absolute; bottom: 0; left: 0; right: 0; height: 2px;
}
.card.income::after { background: var(--green); }
.card.expense::after { background: var(--red); }
.card.balance::after { background: var(--gold); }
.card-label {
  font-size: 0.7rem; letter-spacing: 0.18em; text-transform: uppercase;
  color: var(--muted); margin-bottom: 14px;
}
.card-amount {
  font-family: 'DM Mono', monospace; font-size: 1.9rem; font-weight: 500;
  letter-spacing: -0.02em;
}
.card.income .card-amount { color: var(--green); }
.card.expense .card-amount { color: var(--red); }
.card.balance .card-amount { color: var(--gold); }
.card-icon {
  position: absolute; right: 24px; top: 24px;
  font-size: 1.4rem; opacity: 0.25;
}

.dashboard-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }
.widget {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 4px; padding: 28px;
}
.widget-title {
  font-size: 0.7rem; letter-spacing: 0.15em; text-transform: uppercase;
  color: var(--muted); margin-bottom: 20px;
}
.chart-wrap { position: relative; height: 220px; display: flex; align-items: center; justify-content: center; }
.no-data { color: var(--muted); font-size: 0.85rem; text-align: center; padding: 40px; }

/* Recent transactions in widget */
.tx-mini { display: flex; justify-content: space-between; align-items: center; padding: 10px 0; border-bottom: 1px solid var(--border); }
.tx-mini:last-child { border-bottom: none; }
.tx-mini-left { display: flex; flex-direction: column; gap: 3px; }
.tx-mini-cat { font-size: 0.82rem; }
.tx-mini-note { font-size: 0.72rem; color: var(--muted); }
.tx-mini-amount { font-family: 'DM Mono', monospace; font-size: 0.88rem; font-weight: 500; }
.tx-mini-amount.inc { color: var(--green); }
.tx-mini-amount.exp { color: var(--red); }

/* Transactions page */
.tx-controls { display: flex; gap: 14px; margin-bottom: 28px; align-items: center; flex-wrap: wrap; }
.tx-filter-btns { display: flex; gap: 8px; }
.filter-btn {
  padding: 8px 16px; background: var(--surface); border: 1px solid var(--border);
  border-radius: 3px; color: var(--muted); font-size: 0.78rem;
  letter-spacing: 0.1em; text-transform: uppercase; cursor: pointer;
  transition: all 0.15s;
}
.filter-btn.active { border-color: var(--gold-dim); color: var(--gold); background: rgba(201,168,76,0.05); }
.tx-list { display: flex; flex-direction: column; gap: 10px; }
.tx-row {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 4px; padding: 18px 22px;
  display: flex; align-items: center; gap: 16px;
  transition: border-color 0.15s;
}
.tx-row:hover { border-color: var(--border); }
.tx-type-dot {
  width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0;
}
.tx-type-dot.income { background: var(--green); box-shadow: 0 0 8px var(--green); }
.tx-type-dot.expense { background: var(--red); box-shadow: 0 0 8px var(--red); }
.tx-info { flex: 1; }
.tx-cat { font-size: 0.9rem; margin-bottom: 3px; }
.tx-note { font-size: 0.75rem; color: var(--muted); }
.tx-date { font-size: 0.75rem; color: var(--muted); font-family: 'DM Mono', monospace; }
.tx-amount { font-family: 'DM Mono', monospace; font-size: 1rem; font-weight: 500; }
.tx-amount.income { color: var(--green); }
.tx-amount.expense { color: var(--red); }
.tx-del {
  background: none; border: none; color: var(--muted);
  cursor: pointer; font-size: 0.9rem; padding: 4px 8px;
  opacity: 0; transition: all 0.15s; border-radius: 3px;
}
.tx-row:hover .tx-del { opacity: 1; }
.tx-del:hover { background: rgba(207,102,121,0.15); color: var(--red); }

/* Add transaction page */
.add-form {
  max-width: 560px;
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 4px; padding: 40px 48px; position: relative;
}
.add-form::before {
  content: ''; position: absolute; top: 0; left: 48px; right: 48px; height: 1px;
  background: linear-gradient(90deg, transparent, var(--gold-dim), transparent);
}
.type-toggle { display: flex; gap: 0; margin-bottom: 32px; border: 1px solid var(--border); border-radius: 3px; overflow: hidden; }
.type-btn {
  flex: 1; padding: 12px; border: none; cursor: pointer;
  font-family: 'DM Sans', sans-serif; font-size: 0.8rem;
  letter-spacing: 0.12em; text-transform: uppercase; font-weight: 500;
  background: transparent; color: var(--muted); transition: all 0.2s;
}
.type-btn.active.income { background: rgba(76,175,130,0.15); color: var(--green); }
.type-btn.active.expense { background: rgba(207,102,121,0.15); color: var(--red); }
.amount-field { position: relative; margin-bottom: 20px; }
.amount-prefix {
  position: absolute; left: 16px; top: 50%; transform: translateY(-50%);
  font-family: 'DM Mono', monospace; color: var(--muted); font-size: 1rem;
  pointer-events: none;
}
.amount-field input {
  padding-left: 36px; font-size: 1.1rem;
}
select {
  width: 100%; padding: 12px 16px;
  background: var(--bg); border: 1px solid var(--border);
  border-radius: 3px; color: var(--text);
  font-family: 'DM Sans', sans-serif; font-size: 0.9rem;
  transition: border-color 0.2s; cursor: pointer; appearance: none;
}
select:focus { outline: none; border-color: var(--gold-dim); }
.success-toast {
  position: fixed; bottom: 32px; right: 32px;
  background: var(--surface); border: 1px solid var(--green);
  border-radius: 4px; padding: 14px 22px;
  font-size: 0.85rem; color: var(--green);
  display: none; animation: slideIn 0.3s ease;
  z-index: 1000;
}
.cat-pills { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 20px; }
.cat-pill {
  padding: 6px 14px; background: var(--bg); border: 1px solid var(--border);
  border-radius: 20px; font-size: 0.78rem; cursor: pointer;
  transition: all 0.15s; color: var(--muted);
}
.cat-pill.active { border-color: var(--gold-dim); color: var(--gold); background: rgba(201,168,76,0.08); }

@keyframes fadeUp {
  from { opacity: 0; transform: translateY(16px); }
  to { opacity: 1; transform: translateY(0); }
}
@keyframes slideIn {
  from { opacity: 0; transform: translateX(20px); }
  to { opacity: 1; transform: translateX(0); }
}

.empty-state { text-align: center; padding: 60px 20px; color: var(--muted); }
.empty-icon { font-size: 2.5rem; margin-bottom: 12px; opacity: 0.3; }
.empty-text { font-size: 0.85rem; }

@media (max-width: 900px) {
  .sidebar { width: 200px; }
  .main { margin-left: 200px; padding: 32px; }
  .cards { grid-template-columns: 1fr; }
  .dashboard-grid { grid-template-columns: 1fr; }
}
@media (max-width: 640px) {
  .sidebar { display: none; }
  .main { margin-left: 0; padding: 20px; }
}
</style>
</head>
<body>

<!-- AUTH -->
<div id="auth-screen">
  <div class="auth-box">
    <div class="auth-logo">Vault</div>
    <div class="auth-tagline">Personal Money Manager</div>
    <div class="auth-tabs">
      <button class="auth-tab active" onclick="switchTab('login')">Sign In</button>
      <button class="auth-tab" onclick="switchTab('signup')">Create Account</button>
    </div>
    <div class="auth-error" id="auth-error"></div>
    <div class="field">
      <label>Email Address</label>
      <input type="email" id="auth-email" placeholder="you@example.com" autocomplete="email"/>
    </div>
    <div class="field">
      <label>Password</label>
      <input type="password" id="auth-password" placeholder="••••••••" autocomplete="current-password"/>
    </div>
    <button class="btn-primary" onclick="submitAuth()" id="auth-btn">Sign In</button>
  </div>
</div>

<!-- APP -->
<div id="app-screen">
  <div class="sidebar">
    <div class="sidebar-logo">Va<span>u</span>lt</div>
    <nav class="nav">
      <div class="nav-item active" onclick="showPage('dashboard')">
        <span class="nav-icon">◈</span> Dashboard
      </div>
      <div class="nav-item" onclick="showPage('transactions')">
        <span class="nav-icon">≡</span> Transactions
      </div>
      <div class="nav-item" onclick="showPage('add')">
        <span class="nav-icon">+</span> Add Entry
      </div>
    </nav>
    <div class="sidebar-user">
      <div class="user-avatar" id="user-avatar">–</div>
      <span class="user-email" id="user-email-display">–</span>
      <button class="logout-btn" onclick="logout()" title="Logout">⏻</button>
    </div>
  </div>

  <main class="main">
    <!-- DASHBOARD -->
    <div class="page active" id="page-dashboard">
      <div class="page-title">Overview</div>
      <div class="page-subtitle">Your financial snapshot</div>
      <div class="month-row">
        <button class="month-nav" onclick="changeMonth(-1)">←</button>
        <div class="month-label" id="month-label"></div>
        <button class="month-nav" onclick="changeMonth(1)">→</button>
      </div>
      <div class="cards">
        <div class="card income">
          <div class="card-icon">↑</div>
          <div class="card-label">Total Income</div>
          <div class="card-amount" id="dash-income">£0.00</div>
        </div>
        <div class="card expense">
          <div class="card-icon">↓</div>
          <div class="card-label">Total Expenses</div>
          <div class="card-amount" id="dash-expense">£0.00</div>
        </div>
        <div class="card balance">
          <div class="card-icon">◈</div>
          <div class="card-label">Net Balance</div>
          <div class="card-amount" id="dash-balance">£0.00</div>
        </div>
      </div>
      <div class="dashboard-grid">
        <div class="widget">
          <div class="widget-title">Spending by Category</div>
          <div class="chart-wrap">
            <canvas id="pie-chart" width="200" height="200" style="max-width:200px;max-height:200px;"></canvas>
            <div class="no-data" id="pie-no-data" style="display:none;">No expense data yet</div>
          </div>
        </div>
        <div class="widget">
          <div class="widget-title">Recent Activity</div>
          <div id="recent-list"><div class="no-data">No transactions yet</div></div>
        </div>
      </div>
    </div>

    <!-- TRANSACTIONS -->
    <div class="page" id="page-transactions">
      <div class="page-title">Transactions</div>
      <div class="page-subtitle">All your entries</div>
      <div class="tx-controls">
        <div class="month-row" style="margin-bottom:0;">
          <button class="month-nav" onclick="changeMonth(-1)">←</button>
          <div class="month-label" id="month-label-2"></div>
          <button class="month-nav" onclick="changeMonth(1)">→</button>
        </div>
        <div class="tx-filter-btns">
          <button class="filter-btn active" onclick="setFilter('all', this)">All</button>
          <button class="filter-btn" onclick="setFilter('income', this)">Income</button>
          <button class="filter-btn" onclick="setFilter('expense', this)">Expenses</button>
        </div>
      </div>
      <div class="tx-list" id="tx-list"></div>
    </div>

    <!-- ADD -->
    <div class="page" id="page-add">
      <div class="page-title">Add Entry</div>
      <div class="page-subtitle">Record income or expense</div>
      <div class="add-form">
        <div class="type-toggle">
          <button class="type-btn active income" id="btn-income" onclick="setType('income')">⬆ Income</button>
          <button class="type-btn expense" id="btn-expense" onclick="setType('expense')">⬇ Expense</button>
        </div>
        <div class="field">
          <label>Amount</label>
          <div class="amount-field">
            <span class="amount-prefix">£</span>
            <input type="number" id="add-amount" placeholder="0.00" min="0.01" step="0.01"/>
          </div>
        </div>
        <div id="cat-section" style="display:none;">
          <div class="field">
            <label>Category</label>
            <div class="cat-pills" id="cat-pills"></div>
          </div>
        </div>
        <div class="field">
          <label>Date</label>
          <input type="date" id="add-date"/>
        </div>
        <div class="field">
          <label>Note <span style="color:var(--muted);font-size:0.7rem;">(optional)</span></label>
          <input type="text" id="add-note" placeholder="e.g. Monthly salary, Lunch at Pret..."/>
        </div>
        <button class="btn-primary" onclick="submitTransaction()">Add Entry</button>
        <div class="auth-error" id="add-error" style="margin-top:14px;"></div>
      </div>
    </div>
  </main>
</div>

<div class="success-toast" id="toast">✓ Entry added successfully</div>

<script>
const CATEGORIES = {
  expense: ['🍔 Food','🏠 Rent','🚗 Transport','🛍 Shopping','💊 Health','🎬 Entertainment','📱 Bills','✈️ Travel','📚 Education','🎁 Gifts','💼 Work','📦 Other'],
  income: ['💰 Salary','🔧 Freelance','💵 Investment','🎁 Gift','💳 Refund','📦 Other']
};

let currentType = 'income';
let selectedCategory = '';
let currentMonth = new Date().toISOString().slice(0,7);
let allTx = [];
let txFilter = 'all';
let pieChart = null;

// ── Auth ──────────────────────────────────────────────────────────
let authMode = 'login';
function switchTab(mode) {
  authMode = mode;
  document.querySelectorAll('.auth-tab').forEach((t,i) => t.classList.toggle('active', (mode==='login'&&i===0)||(mode==='signup'&&i===1)));
  document.getElementById('auth-btn').textContent = mode==='login' ? 'Sign In' : 'Create Account';
  document.getElementById('auth-error').style.display='none';
}

async function submitAuth() {
  const email = document.getElementById('auth-email').value.trim();
  const password = document.getElementById('auth-password').value;
  const err = document.getElementById('auth-error');
  err.style.display='none';
  const endpoint = authMode==='login' ? '/api/login' : '/api/signup';
  const res = await fetch(endpoint, {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email,password})});
  const data = await res.json();
  if (!res.ok) { err.textContent=data.error; err.style.display='block'; return; }
  showApp(email);
}

document.addEventListener('keydown', e => {
  if(e.key==='Enter' && document.getElementById('auth-screen').style.display!=='none') submitAuth();
});

async function logout() {
  await fetch('/api/logout',{method:'POST'});
  document.getElementById('app-screen').style.display='none';
  document.getElementById('auth-screen').style.display='flex';
}

function showApp(email) {
  document.getElementById('auth-screen').style.display='none';
  document.getElementById('app-screen').style.display='block';
  document.getElementById('user-email-display').textContent=email;
  document.getElementById('user-avatar').textContent=email[0].toUpperCase();
  updateMonthLabels();
  loadDashboard();
  // Default today date
  document.getElementById('add-date').valueAsDate=new Date();
  setupCategoryPills();
}

// ── Navigation ────────────────────────────────────────────────────
function showPage(name) {
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
  document.getElementById('page-'+name).classList.add('active');
  const items = document.querySelectorAll('.nav-item');
  const map = {dashboard:0,transactions:1,add:2};
  items[map[name]].classList.add('active');
  if(name==='dashboard') loadDashboard();
  if(name==='transactions') loadTransactions();
}

// ── Month ─────────────────────────────────────────────────────────
function changeMonth(dir) {
  const [y,m] = currentMonth.split('-').map(Number);
  const d = new Date(y,m-1+dir,1);
  currentMonth = d.toISOString().slice(0,7);
  updateMonthLabels();
  const active = document.querySelector('.page.active');
  if(active.id==='page-dashboard') loadDashboard();
  else if(active.id==='page-transactions') loadTransactions();
}
function updateMonthLabels() {
  const [y,m] = currentMonth.split('-');
  const label = new Date(y,m-1,1).toLocaleDateString('en-GB',{month:'long',year:'numeric'});
  document.getElementById('month-label').textContent=label;
  document.getElementById('month-label-2').textContent=label;
}

// ── Dashboard ─────────────────────────────────────────────────────
async function loadDashboard() {
  const [sumRes, txRes] = await Promise.all([
    fetch(`/api/summary?month=${currentMonth}`),
    fetch(`/api/transactions?month=${currentMonth}`)
  ]);
  const sum = await sumRes.json();
  const txs = await txRes.json();
  document.getElementById('dash-income').textContent=fmt(sum.income);
  document.getElementById('dash-expense').textContent=fmt(sum.expenses);
  const bal = document.getElementById('dash-balance');
  bal.textContent=fmt(sum.balance);
  bal.style.color = sum.balance>=0 ? 'var(--gold)' : 'var(--red)';

  // Pie chart
  const canvas = document.getElementById('pie-chart');
  const noData = document.getElementById('pie-no-data');
  const cats = sum.categories;
  if(pieChart){pieChart.destroy();pieChart=null;}
  if(Object.keys(cats).length===0){canvas.style.display='none';noData.style.display='block';}
  else {
    canvas.style.display='block';noData.style.display='none';
    const colors=['#c9a84c','#cf6679','#4caf82','#7b6cff','#e8a845','#6bb5cf','#b07cc6','#7ab87a'];
    pieChart=new Chart(canvas,{
      type:'doughnut',
      data:{labels:Object.keys(cats),datasets:[{data:Object.values(cats),backgroundColor:colors,borderWidth:0,hoverOffset:4}]},
      options:{responsive:true,plugins:{legend:{display:false},tooltip:{callbacks:{label:ctx=>`£${ctx.parsed.toFixed(2)}`}}},cutout:'60%'}
    });
  }

  // Recent
  const recent = txs.slice(0,6);
  const list = document.getElementById('recent-list');
  if(recent.length===0){list.innerHTML='<div class="no-data">No transactions yet</div>';return;}
  list.innerHTML=recent.map(t=>`
    <div class="tx-mini">
      <div class="tx-mini-left">
        <div class="tx-mini-cat">${t.category||'—'}</div>
        ${t.note?`<div class="tx-mini-note">${t.note}</div>`:''}
      </div>
      <div class="tx-mini-amount ${t.type}">${t.type==='income'?'+':'-'}${fmt(t.amount)}</div>
    </div>`).join('');
}

// ── Transactions ──────────────────────────────────────────────────
function setFilter(f,el) {
  txFilter=f;
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  el.classList.add('active');
  renderTransactions();
}
async function loadTransactions() {
  const res=await fetch(`/api/transactions?month=${currentMonth}`);
  allTx=await res.json();
  renderTransactions();
}
function renderTransactions() {
  const filtered=txFilter==='all'?allTx:allTx.filter(t=>t.type===txFilter);
  const list=document.getElementById('tx-list');
  if(filtered.length===0){list.innerHTML='<div class="empty-state"><div class="empty-icon">◈</div><div class="empty-text">No transactions found</div></div>';return;}
  list.innerHTML=filtered.map(t=>`
    <div class="tx-row" id="tx-${t.id}">
      <div class="tx-type-dot ${t.type}"></div>
      <div class="tx-info">
        <div class="tx-cat">${t.category||'—'}</div>
        ${t.note?`<div class="tx-note">${t.note}</div>`:''}
      </div>
      <div class="tx-date">${t.date}</div>
      <div class="tx-amount ${t.type}">${t.type==='income'?'+':'-'}${fmt(t.amount)}</div>
      <button class="tx-del" onclick="deleteTransaction(${t.id})" title="Delete">✕</button>
    </div>`).join('');
}
async function deleteTransaction(id) {
  if(!confirm('Delete this transaction?'))return;
  await fetch(`/api/transactions/${id}`,{method:'DELETE'});
  allTx=allTx.filter(t=>t.id!==id);
  renderTransactions();
  loadDashboard();
}

// ── Add Entry ─────────────────────────────────────────────────────
function setType(type) {
  currentType=type;
  document.getElementById('btn-income').className=`type-btn income${type==='income'?' active':''}`;
  document.getElementById('btn-expense').className=`type-btn expense${type==='expense'?' active':''}`;
  document.getElementById('cat-section').style.display=type==='expense'?'block':'none';
  selectedCategory='';
  setupCategoryPills();
}

function setupCategoryPills() {
  const cats=CATEGORIES[currentType]||[];
  const container=document.getElementById('cat-pills');
  if(!container)return;
  container.innerHTML=cats.map(c=>`<div class="cat-pill${c===selectedCategory?' active':''}" onclick="selectCat(this,'${c}')">${c}</div>`).join('');
}

function selectCat(el,cat) {
  selectedCategory=cat;
  document.querySelectorAll('.cat-pill').forEach(p=>p.classList.remove('active'));
  el.classList.add('active');
}

async function submitTransaction() {
  const amount=document.getElementById('add-amount').value;
  const date=document.getElementById('add-date').value;
  const note=document.getElementById('add-note').value.trim();
  const err=document.getElementById('add-error');
  err.style.display='none';

  const category=currentType==='expense'?selectedCategory||'Other':'Income';

  const res=await fetch('/api/transactions',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({type:currentType,amount:parseFloat(amount),category,note,date})
  });
  const data=await res.json();
  if(!res.ok){err.textContent=data.error;err.style.display='block';return;}

  // Reset
  document.getElementById('add-amount').value='';
  document.getElementById('add-note').value='';
  document.getElementById('add-date').valueAsDate=new Date();
  selectedCategory='';
  setupCategoryPills();

  const toast=document.getElementById('toast');
  toast.style.display='block';
  setTimeout(()=>toast.style.display='none',2500);
}

function fmt(n){ return '£'+Math.abs(n).toFixed(2); }

// ── Init ──────────────────────────────────────────────────────────
(async()=>{
  const res=await fetch('/api/me');
  const data=await res.json();
  if(data.logged_in){ showApp(data.email); }
})();
</script>
</body>
</html>"""

if __name__ == "__main__":
    init_db()
    print("\n💰 Vault — Money Manager")
    print("═" * 40)
    print("  Open: http://localhost:5000")
    print("  Stop: Ctrl+C")
    print("═" * 40 + "\n")
    app.run(debug=True, port=5000)