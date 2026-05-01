"""
SecureBank API — Intentionally Vulnerable Flask Application
Part of the Automated IR Pipeline project.

WARNING: This application contains intentional vulnerabilities
for security testing and detection rule validation.
DO NOT deploy this in any production environment.

Vulnerabilities included:
- Weak JWT secret (token forgery)
- No rate limiting on login (brute force)
- SQL injection on transfer endpoint
- Debug mode enabled (info disclosure)
- No input validation on admin config (command injection)
- Sensitive data in API responses
- Runs as root in container (privilege escalation)
"""

import os
import sqlite3
import subprocess
import datetime
import logging
import uuid
import json

from flask import Flask, request, jsonify, g
from functools import wraps
import jwt


# ============================================================
# App Configuration
# ============================================================

app = Flask(__name__)

# VULNERABILITY: Weak JWT secret — easily brute-forced
app.config["SECRET_KEY"] = "super-secret-key-123"

# VULNERABILITY: Debug mode enabled — exposes stack traces
app.config["DEBUG"] = True

# ============================================================
# Paths Configuration
# ============================================================

LOG_DIR = os.environ.get("LOG_DIR", "logs")
DATA_DIR = os.environ.get("DATA_DIR", "data")
DATABASE = os.environ.get("DATABASE_PATH", os.path.join(DATA_DIR, "securebank.db"))

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

# ============================================================
# Logging Configuration
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(LOG_DIR, "securebank.log")),
    ],
)
logger = logging.getLogger("securebank")

# ============================================================
# Database Setup
# ============================================================


def get_db():
    """Get database connection for current request."""
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    """Close database connection at end of request."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Initialize database with tables and seed data."""
    os.makedirs(os.path.dirname(DATABASE), exist_ok=True)

    db = sqlite3.connect(DATABASE)
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS accounts (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            balance REAL DEFAULT 1000.00,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS transactions (
            id TEXT PRIMARY KEY,
            from_account TEXT NOT NULL,
            to_account TEXT NOT NULL,
            amount REAL NOT NULL,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (from_account) REFERENCES accounts(id),
            FOREIGN KEY (to_account) REFERENCES accounts(id)
        )
    """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS app_config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """
    )

    # Seed admin user if not exists
    existing = db.execute(
        "SELECT id FROM users WHERE username = 'admin'"
    ).fetchone()
    if not existing:
        admin_id = str(uuid.uuid4())
        admin_account_id = str(uuid.uuid4())
        # VULNERABILITY: Password stored in plain text
        db.execute(
            "INSERT INTO users (id, username, password, role) VALUES (?, ?, ?, ?)",
            (admin_id, "admin", "admin123", "admin"),
        )
        db.execute(
            "INSERT INTO accounts (id, user_id, balance) VALUES (?, ?, ?)",
            (admin_account_id, admin_id, 50000.00),
        )

    db.commit()
    db.close()


# ============================================================
# Authentication Helpers
# ============================================================


def generate_token(user_id, username, role):
    """Generate JWT token for authenticated user."""
    payload = {
        "user_id": user_id,
        "username": username,
        "role": role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24),
        "iat": datetime.datetime.utcnow(),
    }
    # VULNERABILITY: Using weak secret for signing
    token = jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")
    return token


def token_required(f):
    """Decorator to require valid JWT token."""

    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get("Authorization")

        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]

        if not token:
            logger.warning(
                "ACCESS_DENIED: No token provided — IP: %s, Path: %s",
                request.remote_addr,
                request.path,
            )
            return jsonify({"error": "Token is missing"}), 401

        try:
            data = jwt.decode(
                token, app.config["SECRET_KEY"], algorithms=["HS256"]
            )
            g.current_user = data
        except jwt.ExpiredSignatureError:
            logger.warning(
                "ACCESS_DENIED: Expired token — IP: %s", request.remote_addr
            )
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            logger.warning(
                "ACCESS_DENIED: Invalid token — IP: %s, Path: %s",
                request.remote_addr,
                request.path,
            )
            return jsonify({"error": "Token is invalid"}), 401

        return f(*args, **kwargs)

    return decorated


def admin_required(f):
    """Decorator to require admin role."""

    @wraps(f)
    def decorated(*args, **kwargs):
        if g.current_user.get("role") != "admin":
            logger.warning(
                "PRIVILEGE_ESCALATION_ATTEMPT: User '%s' tried to access admin endpoint — IP: %s, Path: %s",
                g.current_user.get("username"),
                request.remote_addr,
                request.path,
            )
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)

    return decorated


# ============================================================
# API Endpoints
# ============================================================


@app.route("/api/health", methods=["GET"])
def health_check():
    """Health check endpoint."""
    return jsonify({"status": "healthy", "service": "SecureBank API"})


# --- Authentication ---


@app.route("/api/auth/register", methods=["POST"])
def register():
    """Register a new user."""
    data = request.get_json()

    if not data or not data.get("username") or not data.get("password"):
        return jsonify({"error": "Username and password required"}), 400

    username = data["username"]
    password = data["password"]

    db = get_db()

    existing = db.execute(
        "SELECT id FROM users WHERE username = ?", (username,)
    ).fetchone()
    if existing:
        logger.info(
            "REGISTER_FAILED: Duplicate username '%s' — IP: %s",
            username,
            request.remote_addr,
        )
        return jsonify({"error": "Username already exists"}), 409

    user_id = str(uuid.uuid4())
    account_id = str(uuid.uuid4())

    # VULNERABILITY: Password stored in plain text — no hashing
    db.execute(
        "INSERT INTO users (id, username, password, role) VALUES (?, ?, ?, ?)",
        (user_id, username, password, "user"),
    )
    db.execute(
        "INSERT INTO accounts (id, user_id, balance) VALUES (?, ?, ?)",
        (account_id, user_id, 1000.00),
    )
    db.commit()

    logger.info(
        "REGISTER_SUCCESS: User '%s' created — IP: %s",
        username,
        request.remote_addr,
    )

    token = generate_token(user_id, username, "user")

    # VULNERABILITY: Returning internal IDs in response
    return (
        jsonify(
            {
                "message": "User registered successfully",
                "user_id": user_id,
                "account_id": account_id,
                "token": token,
            }
        ),
        201,
    )


@app.route("/api/auth/login", methods=["POST"])
def login():
    """Authenticate user and return JWT token."""
    data = request.get_json()

    if not data or not data.get("username") or not data.get("password"):
        return jsonify({"error": "Username and password required"}), 400

    username = data["username"]
    password = data["password"]

    db = get_db()

    user = db.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (username, password),
    ).fetchone()

    if not user:
        # VULNERABILITY: No rate limiting — allows brute force
        logger.warning(
            "LOGIN_FAILED: Invalid credentials for '%s' — IP: %s, User-Agent: %s",
            username,
            request.remote_addr,
            request.headers.get("User-Agent", "unknown"),
        )
        return jsonify({"error": "Invalid credentials"}), 401

    token = generate_token(user["id"], user["username"], user["role"])

    logger.info(
        "LOGIN_SUCCESS: User '%s' authenticated — IP: %s",
        username,
        request.remote_addr,
    )

    # VULNERABILITY: Returning password hash and role in response
    return jsonify(
        {
            "message": "Login successful",
            "token": token,
            "user_id": user["id"],
            "username": user["username"],
            "role": user["role"],
        }
    )


# --- Account Operations ---


@app.route("/api/account/balance", methods=["GET"])
@token_required
def get_balance():
    """Get account balance for authenticated user."""
    db = get_db()
    user_id = g.current_user["user_id"]

    account = db.execute(
        "SELECT * FROM accounts WHERE user_id = ?", (user_id,)
    ).fetchone()

    if not account:
        return jsonify({"error": "Account not found"}), 404

    logger.info(
        "BALANCE_CHECK: User '%s' checked balance — IP: %s",
        g.current_user["username"],
        request.remote_addr,
    )

    return jsonify(
        {
            "account_id": account["id"],
            "balance": account["balance"],
            "user_id": account["user_id"],
        }
    )


@app.route("/api/account/transfer", methods=["POST"])
@token_required
def transfer():
    """Transfer funds between accounts."""
    data = request.get_json()

    if not data or not data.get("to_account") or not data.get("amount"):
        return jsonify({"error": "to_account and amount required"}), 400

    to_account = data["to_account"]
    amount = data["amount"]

    db = get_db()
    user_id = g.current_user["user_id"]

    from_account = db.execute(
        "SELECT * FROM accounts WHERE user_id = ?", (user_id,)
    ).fetchone()

    if not from_account:
        return jsonify({"error": "Source account not found"}), 404

    if from_account["balance"] < float(amount):
        return jsonify({"error": "Insufficient funds"}), 400

    # VULNERABILITY: SQL injection — amount is concatenated directly
    try:
        db.execute(
            "UPDATE accounts SET balance = balance - "
            + str(amount)
            + " WHERE id = '"
            + from_account["id"]
            + "'"
        )
        db.execute(
            "UPDATE accounts SET balance = balance + "
            + str(amount)
            + " WHERE id = '"
            + to_account
            + "'"
        )

        transaction_id = str(uuid.uuid4())
        db.execute(
            "INSERT INTO transactions (id, from_account, to_account, amount) VALUES (?, ?, ?, ?)",
            (transaction_id, from_account["id"], to_account, float(amount)),
        )
        db.commit()

        logger.info(
            "TRANSFER_SUCCESS: User '%s' transferred %s to account '%s' — IP: %s",
            g.current_user["username"],
            amount,
            to_account,
            request.remote_addr,
        )

        return jsonify(
            {
                "message": "Transfer successful",
                "transaction_id": transaction_id,
                "amount": float(amount),
                "from_account": from_account["id"],
                "to_account": to_account,
                "new_balance": from_account["balance"] - float(amount),
            }
        )

    except Exception as e:
        # VULNERABILITY: Debug mode leaks full stack trace
        logger.error(
            "TRANSFER_ERROR: %s — User: '%s', IP: %s",
            str(e),
            g.current_user["username"],
            request.remote_addr,
        )
        return jsonify({"error": str(e)}), 500


@app.route("/api/account/history", methods=["GET"])
@token_required
def transaction_history():
    """Get transaction history for authenticated user."""
    db = get_db()
    user_id = g.current_user["user_id"]

    account = db.execute(
        "SELECT id FROM accounts WHERE user_id = ?", (user_id,)
    ).fetchone()

    if not account:
        return jsonify({"error": "Account not found"}), 404

    transactions = db.execute(
        "SELECT * FROM transactions WHERE from_account = ? OR to_account = ? ORDER BY timestamp DESC",
        (account["id"], account["id"]),
    ).fetchall()

    logger.info(
        "HISTORY_CHECK: User '%s' viewed transaction history — IP: %s",
        g.current_user["username"],
        request.remote_addr,
    )

    return jsonify(
        {
            "account_id": account["id"],
            "transactions": [
                {
                    "id": t["id"],
                    "from_account": t["from_account"],
                    "to_account": t["to_account"],
                    "amount": t["amount"],
                    "timestamp": t["timestamp"],
                }
                for t in transactions
            ],
        }
    )


# --- Admin Operations ---


@app.route("/api/admin/users", methods=["GET"])
@token_required
@admin_required
def list_users():
    """List all users — admin only."""
    db = get_db()

    users = db.execute("SELECT * FROM users").fetchall()

    logger.info(
        "ADMIN_ACCESS: User '%s' listed all users — IP: %s",
        g.current_user["username"],
        request.remote_addr,
    )

    # VULNERABILITY: Returning passwords in response
    return jsonify(
        {
            "users": [
                {
                    "id": u["id"],
                    "username": u["username"],
                    "password": u["password"],
                    "role": u["role"],
                    "created_at": u["created_at"],
                }
                for u in users
            ]
        }
    )


@app.route("/api/admin/config", methods=["POST"])
@token_required
@admin_required
def update_config():
    """Update application config — admin only."""
    data = request.get_json()

    if not data or not data.get("key") or not data.get("value"):
        return jsonify({"error": "key and value required"}), 400

    key = data["key"]
    value = data["value"]

    # VULNERABILITY: Command injection — value passed to subprocess
    if key == "backup_path":
        try:
            result = subprocess.run(
                f"ls {value}",
                shell=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            logger.warning(
                "ADMIN_CONFIG: User '%s' set backup_path to '%s' — IP: %s, Command output: %s",
                g.current_user["username"],
                value,
                request.remote_addr,
                result.stdout[:200],
            )
        except subprocess.TimeoutExpired:
            logger.error(
                "ADMIN_CONFIG_TIMEOUT: Command timed out — User: '%s', Value: '%s', IP: %s",
                g.current_user["username"],
                value,
                request.remote_addr,
            )
            return jsonify({"error": "Command timed out"}), 500
        except Exception as e:
            logger.error(
                "ADMIN_CONFIG_ERROR: %s — User: '%s', IP: %s",
                str(e),
                g.current_user["username"],
                request.remote_addr,
            )

    db = get_db()
    db.execute(
        "INSERT OR REPLACE INTO app_config (key, value) VALUES (?, ?)",
        (key, value),
    )
    db.commit()

    logger.info(
        "CONFIG_UPDATE: User '%s' updated config '%s' — IP: %s",
        g.current_user["username"],
        key,
        request.remote_addr,
    )

    return jsonify({"message": f"Config '{key}' updated", "key": key, "value": value})


# ============================================================
# Error Handlers
# ============================================================


@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404


@app.errorhandler(500)
def internal_error(error):
    # VULNERABILITY: Debug mode exposes internal error details
    logger.error("INTERNAL_ERROR: %s — IP: %s", str(error), request.remote_addr)
    return jsonify({"error": str(error)}), 500


# ============================================================
# Application Startup
# ============================================================

if __name__ == "__main__":
    init_db()
    logger.info("DATABASE_INIT: Database initialized successfully")

    # VULNERABILITY: Binding to all interfaces + debug mode
    app.run(host="0.0.0.0", port=5000, debug=True)
