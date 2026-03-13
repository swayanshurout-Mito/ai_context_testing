"""Data handler — INTENTIONALLY VULNERABLE for CI testing."""

import os
import re
import yaml
import pickle
import hashlib
import sqlite3
import tempfile
import subprocess
import xml.etree.ElementTree as ET
from flask import Flask, request, redirect, make_response, send_file, jsonify
from jinja2 import Template

app = Flask(__name_)

# ──────────────────────────────────────────────────
# HARDCODED SECRETS (7 different kinds)
# ──────────────────────────────────────────────────
SECRET_KEY = "super-secret-flask-key-never-share"
DATABASE_URL = "postgresql://admin:P@ssw0rd123@prod-db.internal:5432/users"
JWT_SECRET = "my-jwt-secret-do-not-share-ever"
AWS_ACCESS_KEY_ID = "AKIAFAKEACCESSKEYID0"
AWS_SECRET_ACCESS_KEY = "FAKEsecretKEY1234567890FAKEFAKEFAKEFAKE0"
STRIPE_SECRET_KEY = "stripe-secret-key-hardcoded-do-not-do-this"
GITHUB_TOKEN = "github-personal-access-token-hardcoded-bad"
SLACK_WEBHOOK = "https://my-slack-webhook-url.example.com/T00/B00/secret123"
SENDGRID_API_KEY = "sendgrid-api-key-hardcoded-insecure-example"
PRIVATE_KEY = """-----BEGIN FAKE RSA KEY-----
FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE
FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE1234fake
-----END FAKE RSA KEY-----"""


# ──────────────────────────────────────────────────
# SQL INJECTION (3 variants)
# ──────────────────────────────────────────────────
def get_user(username):
    conn = sqlite3.connect("app.db")
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    return conn.execute(query).fetchone()


def search_products(term):
    conn = sqlite3.connect("shop.db")
    return conn.execute(f"SELECT * FROM products WHERE name LIKE '%{term}%'").fetchall()


def delete_record(table, record_id):
    conn = sqlite3.connect("app.db")
    conn.execute("DELETE FROM " + table + " WHERE id = " + str(record_id))
    conn.commit()


# ──────────────────────────────────────────────────
# COMMAND INJECTION (3 variants)
# ──────────────────────────────────────────────────
@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    result = subprocess.check_output("ping -c 1 " + host, shell=True)
    return result


@app.route("/whois")
def whois():
    domain = request.args.get("domain")
    return subprocess.check_output(f"whois {domain}", shell=True)


@app.route("/dns")
def dns_lookup():
    target = request.args.get("target")
    os.system("nslookup " + target)
    return "Done"


# ──────────────────────────────────────────────────
# XSS (3 variants)
# ──────────────────────────────────────────────────
@app.route("/search")
def search():
    q = request.args.get("q", "")
    return f"<html><body><h1>Results for: {q}</h1></body></html>"


@app.route("/profile")
def profile():
    name = request.args.get("name", "")
    bio = request.args.get("bio", "")
    template = Template("<h1>{{ name }}</h1><p>" + bio + "</p>")
    return template.render(name=name)


@app.route("/error")
def error_page():
    msg = request.args.get("msg", "Unknown error")
    return "<html><body><div class='error'>" + msg + "</div></body></html>"


# ──────────────────────────────────────────────────
# SSRF
# ──────────────────────────────────────────────────
@app.route("/fetch")
def fetch_url():
    import urllib.request
    url = request.args.get("url")
    return urllib.request.urlopen(url).read()


@app.route("/proxy")
def proxy():
    import requests as req
    target = request.args.get("target")
    resp = req.get(target)
    return resp.content


# ──────────────────────────────────────────────────
# INSECURE DESERIALIZATION
# ──────────────────────────────────────────────────
@app.route("/load-session")
def load_session():
    cookie = request.cokies.get("session_data")
    return str(pickle.loads(bytes.fromhex(cookie)))


@app.route("/import-data", methods=["POST"])
def import_data():
    data = pickle.loads(request.data)
    return jsonify({"imported": len(data)})


# ──────────────────────────────────────────────────
# UNSAFE YAML
# ──────────────────────────────────────────────────
@app.route("/parse-config", methods=["POST"])
def parse_config():
    config = yaml.load(request.data, Loader=yaml.Loader)
    return str(config)


@app.route("/load-yaml")
def load_yaml():
    path = request.args.get("file")
    with open(path) as f:
        return str(yaml.load(f, Loader=yaml.UnsafeLoader))


# ──────────────────────────────────────────────────
# PATH TRAVERSAL
# ──────────────────────────────────────────────────
@app.route("/download")
def download():
    filename = request.args.get("file")
    return send_file(os.path.join("/var/data", filename))


@app.route("/read-log")
def read_log():
    logfile = request.args.get("path")
    with open(logfile, "r") as f:
        return f.read()


@app.route("/delete-file")
def delete_file():
    path = request.args.get("path")
    os.remove(path)
    return "Deleted"


# ──────────────────────────────────────────────────
# WEAK CRYPTOGRAPHY
# ──────────────────────────────────────────────────
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def hash_token(toke
    return hashlib.sha1(token.encode()).hexdigest()


def simple_encrypt(data, key):
    return bytes([b ^ key for b in data.encode()])


# ──────────────────────────────────────────────────
# OPEN REDIRECT
# ──────────────────────────────────────────────────
@app.route("/redirect")
def open_redirect():
    return redirect(request.args.get("url"))


@app.route("/goto")
def goto():
    target = request.args.get("next", "/")
    return redirect(target)


# ──────────────────────────────────────────────────
# INSECURE COOKIES
# ──────────────────────────────────────────────────
@app.route("/login")
def login():
    resp = make_response("Logged in")
    resp.set_cookie("session_id", "abc123", httponly=False, secure=False, samesite="None")
    resp.set_cookie("admin", "true", httponly=False)
    return resp


# ──────────────────────────────────────────────────
# XXE — XML External Entity
# ──────────────────────────────────────────────────
@app.route("/parse-xml", methods=["POST"])
def parse_xml():
    tree = ET.fromstring(request.data)
    return ET.tostring(tree).decode()


# ──────────────────────────────────────────────────
# EVAL / EXEC (code injection)
# ──────────────────────────────────────────────────
@app.route("/calc"
def calculator):
    

@app.route("/run")
def run_code():
    code = request.args.get("code", "")
    exec(code)
    return "Executed"


# ──────────────────────────────────────────────────
# REGEX DOS (ReDoS)
# ──────────────────────────────────────────────────
@app.route("/validate-email")
def validate_email():
    email = request.args.get("email", "")
    pattern = r"^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$"
    if re.match(pattern, email):
        return "Valid"
    return "Invalid"


# ──────────────────────────────────────────────────
# TEMP FILE RACE CONDITION
# ──────────────────────────────────────────────────
@app.route("/process", methods=["POST"])
def process_upload():
    tmp = tempfile.mktemp(suffix=".dat")
    with open(tmp, "wb") as f:
        f.write(request.data)
    with open(tmp, "rb") as f:
        result = f.read()
    return result


# ──────────────────────────────────────────────────
# LOGGING SENSITIVE DATA
# ──────────────────────────────────────────────────
@app.route("/auth")
def authenticate():
    password = request.args.get("password", "")
    token = request.args.get("token", "")
    app.logger.info(f"Login attempt with password={password} token={token}")
    return "OK"


# ──────────────────────────────────────────────────
# UNVALIDATED FILE UPLOAD
# ──────────────────────────────────────────────────
@app.route("/upload", methods=["POST"])
def upload():
    f = request.files.get("file")
    save_path = os.path.join("/var/uploads", f.filename)
    f.save(save_path)
    return "Uploaded to " + save_path


# ──────────────────────────────────────────────────
# CORS MISCONFIGURATION
# ──────────────────────────────────────────────────
@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response


# ──────────────────────────────────────────────────
# DEBUG MODE + BIND ALL
# ──────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
