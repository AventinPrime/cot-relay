"""
Web panel on top of the relay core.

RelayManager keeps config.yaml as the single source of truth, rebuilds and
restarts the Relay entirely on any server or route change (the same
principle as rebuild_multisender() in vision-agent - stop the old one,
rebuild, start the new one), and saves changes back to disk so they
survive a process restart.

Authentication here is opt-in - see the README, "Authentication" section.
"""

from __future__ import annotations

import os
import threading
import uuid
from functools import wraps
from typing import Optional

import yaml
from flask import Flask, Response, jsonify, render_template, request
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from certs import EnrollmentError, enroll_certificate, get_cert_identity
from relay import Relay

CONFIG_PATH = "config.yaml"
CERTS_DIR = "certs"

_ALLOWED_CERT_EXTS = {".p12", ".pfx", ".pem", ".crt", ".cer", ".key"}


def _save_uploaded_cert(file_storage, server_dir: str, canonical_stem: str) -> str:
    """
    Saves an uploaded cert/truststore file under a fixed name
    (client.<ext> / truststore.<ext>) so two uploads never collide and the
    path never needs to be shown to or typed by the user.
    """
    ext = os.path.splitext(secure_filename(file_storage.filename or ""))[1].lower()
    if ext not in _ALLOWED_CERT_EXTS:
        ext = ".p12"
    os.makedirs(server_dir, exist_ok=True)
    path = os.path.join(server_dir, canonical_stem + ext)
    file_storage.save(path)
    return path


class RelayManager:
    def __init__(self, config_path: str) -> None:
        self.config_path = config_path
        self.lock = threading.Lock()
        self.config = self._load()
        self.relay: Relay | None = None
        self._build_and_start()

    # -- persistence ---------------------------------------------------

    def _load(self) -> dict:
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                cfg = yaml.safe_load(f)
        except FileNotFoundError:
            cfg = None
        return cfg or {"servers": [], "routes": [], "filter": {}, "state": {}}

    def _save(self) -> None:
        with open(self.config_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(self.config, f, sort_keys=False, allow_unicode=True)

    # -- lifecycle -------------------------------------------------------

    def _build_and_start(self) -> None:
        active_cfg = dict(self.config)
        active_cfg["servers"] = [s for s in self.config.get("servers", []) if s.get("enabled", True)]
        self.relay = Relay(active_cfg)
        self.relay.start()

    def reload(self) -> None:
        with self.lock:
            old_relay = self.relay
            self._build_and_start()
            if old_relay is not None:
                old_relay.stop()
            self._save()

    def status(self) -> dict:
        statuses = {}
        for s in self.config.get("servers", []):
            name = s["name"]
            enabled = s.get("enabled", True)
            conn = self.relay.connections.get(name) if (enabled and self.relay) else None
            statuses[name] = {
                "name": name,
                "host": s["host"],
                "port": s["port"],
                "direction": s.get("direction", "both"),
                "trust_uid": s.get("trust_uid", True),
                "enabled": enabled,
                "connected": bool(conn and conn.connected.is_set()),
                "cert": s.get("cert", ""),
                "key": s.get("key", ""),
                "ca": s.get("ca", ""),
                "verify_ca": s.get("verify_ca", True),
                "enroll_username": s.get("enroll_username", ""),
                # the CN in the certificate itself - this is the identity
                # the TAK server actually sees this connection as, which
                # may differ from enroll_username and is the only reliable
                # answer when the same physical server has several
                # server-entries here under different logins/certs
                "identity_cn": (
                    get_cert_identity(s["cert"], s.get("cert_password"))
                    if s.get("cert") and os.path.exists(s["cert"]) else None
                ),
            }
        return statuses

    def items(self) -> list[dict]:
        """Live snapshot of the State Store: what the relay is actually
        pulling from the servers right now (after merge and namespacing -
        this shows everything tracked, not only what got pushed).
        routed_to - where this was LAST actually routed to under the
        current Routes; an empty list means no rule matched (a common
        reason for "clients can't see each other")."""
        if not self.relay:
            return []
        items = self.relay.state.snapshot()
        for it in items:
            it["routed_to"] = self.relay.get_last_routed(it["namespaced_uid"])
        return items

    def chat_messages(self) -> list[dict]:
        """Rolling log of GeoChat messages seen across all connections."""
        if not self.relay:
            return []
        return self.relay.chat.snapshot()

    # -- mutations (each releases the lock before calling reload()) ------

    def add_server(self, server: dict) -> None:
        with self.lock:
            if any(s["name"] == server["name"] for s in self.config.get("servers", [])):
                raise ValueError(f"server {server['name']!r} already exists")
            self.config.setdefault("servers", []).append(server)
        self.reload()

    def update_server(self, name: str, updates: dict) -> None:
        with self.lock:
            target = None
            for s in self.config.get("servers", []):
                if s["name"] == name:
                    target = s
                    break
            if target is None:
                raise KeyError(name)

            new_name = updates.get("name", name)
            if new_name != name:
                if any(s["name"] == new_name for s in self.config.get("servers", []) if s is not target):
                    raise ValueError(f"server {new_name!r} already exists")
                # cascade the rename through every routing rule instead of
                # just blocking it - otherwise a server's name becomes
                # permanent for the whole life of the config
                for r in self.config.get("routes", []):
                    if r.get("from") == name:
                        r["from"] = new_name
                    r["to"] = [new_name if t == name else t for t in r.get("to", [])]

            target.update(updates)
        self.reload()

    def delete_server(self, name: str) -> None:
        with self.lock:
            self.config["servers"] = [s for s in self.config.get("servers", []) if s["name"] != name]
            self.config["routes"] = [
                r for r in self.config.get("routes", [])
                if r["from"] != name and name not in r.get("to", [])
            ]
        self.reload()

    def toggle_server(self, name: str) -> None:
        with self.lock:
            for s in self.config.get("servers", []):
                if s["name"] == name:
                    s["enabled"] = not s.get("enabled", True)
                    break
            else:
                raise KeyError(name)
        self.reload()

    def list_routes(self) -> list[dict]:
        return self.config.get("routes", [])

    def add_route(self, route: dict) -> str:
        route = dict(route)
        route["id"] = uuid.uuid4().hex[:8]
        with self.lock:
            self.config.setdefault("routes", []).append(route)
        self.reload()
        return route["id"]

    def update_route(self, route_id: str, updates: dict) -> None:
        with self.lock:
            for r in self.config.get("routes", []):
                if r.get("id") == route_id:
                    r.update({k: v for k, v in updates.items() if k != "id"})
                    break
            else:
                raise KeyError(route_id)
        self.reload()

    def delete_route(self, route_id: str) -> None:
        with self.lock:
            self.config["routes"] = [r for r in self.config.get("routes", []) if r.get("id") != route_id]
        self.reload()

    # -- panel access (does NOT touch the Relay - no rebuild needed) -----

    def get_web_auth(self) -> Optional[dict]:
        return self.config.get("web_auth")

    def set_web_auth(self, username: str, password: str) -> None:
        with self.lock:
            self.config["web_auth"] = {
                "username": username,
                "password_hash": generate_password_hash(password),
            }
            self._save()


app = Flask(__name__, template_folder=".")
manager = RelayManager(CONFIG_PATH)

# Panel access control. Two mechanisms, checked in this order:
#  1. Credentials set via the panel itself ("Panel access" in the UI) -
#     stored in config.yaml as a salted hash (werkzeug's
#     generate_password_hash), never in plain text. This is the
#     recommended way to set/change the panel's login - no need to type a
#     password into a terminal or restart the process.
#  2. RELAY_WEB_USER/RELAY_WEB_PASS environment variables - kept as a
#     bootstrap/automation option, only used if nothing has been
#     configured via the UI yet.
# Neither set -> the panel stays open (MVP mode, for localhost/a trusted
# network).
WEB_USER = os.environ.get("RELAY_WEB_USER")
WEB_PASS = os.environ.get("RELAY_WEB_PASS")


def _current_auth():
    """Returns (username, secret, mode) - mode is 'hash' or 'plain'. (None, None, None) if nothing is configured."""
    stored = manager.get_web_auth()
    if stored:
        return stored["username"], stored["password_hash"], "hash"
    if WEB_USER and WEB_PASS:
        return WEB_USER, WEB_PASS, "plain"
    return None, None, None


def _check_credentials(username: str, password: str) -> bool:
    cur_user, secret, mode = _current_auth()
    if cur_user is None or username != cur_user:
        return False
    if mode == "hash":
        return check_password_hash(secret, password)
    return password == secret


def _auth_ok(auth) -> bool:
    return bool(auth) and _check_credentials(auth.username, auth.password)


@app.before_request
def _require_auth():
    cur_user, _secret, _mode = _current_auth()
    if cur_user is None:
        return None
    if not _auth_ok(request.authorization):
        return Response(
            "Authentication required", 401,
            {"WWW-Authenticate": 'Basic realm="CoT Relay Panel"'},
        )
    return None


@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/servers", methods=["GET"])
def api_list_servers():
    return jsonify(list(manager.status().values()))


@app.route("/api/servers", methods=["POST"])
def api_add_server():
    name = request.form.get("name", "").strip()
    host = request.form.get("host", "").strip()
    port_raw = request.form.get("port", "")
    if not name or not host or not port_raw:
        return jsonify({"error": "name, host and port are required"}), 400
    try:
        port = int(port_raw)
    except ValueError:
        return jsonify({"error": "port must be a number"}), 400

    cert_file = request.files.get("cert_file")
    if not cert_file or not cert_file.filename:
        return jsonify({"error": "a client certificate file is required"}), 400

    server_dir = os.path.join(CERTS_DIR, name)
    cert_path = _save_uploaded_cert(cert_file, server_dir, "client")
    ca_file = request.files.get("ca_file")
    ca_path = _save_uploaded_cert(ca_file, server_dir, "truststore") if (ca_file and ca_file.filename) else None

    data = {
        "name": name,
        "host": host,
        "port": port,
        "cert": cert_path,
        "key": None,  # not used: p12 carries its own key, plain PEM may embed the key in the same file
        "ca": ca_path,
        "cert_password": request.form.get("cert_password") or None,
        "ca_password": request.form.get("ca_password") or None,
        "verify_ca": request.form.get("verify_ca") == "true",
        "direction": request.form.get("direction", "both"),
        "trust_uid": request.form.get("trust_uid", "true") == "true",
        "enabled": True,
    }
    try:
        manager.add_server(data)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"ok": True})


@app.route("/api/servers/enroll", methods=["POST"])
def api_enroll_server():
    """Auto-enroll: domain + login/password -> the relay obtains cert/key/ca
    itself and adds the server with ready-made PEM paths (or, if a server
    with that name already exists, updates it - i.e. re-enroll/refresh the
    certificate after the fact)."""
    data = request.get_json(force=True) or {}
    required = {"name", "host", "port", "username", "password"}
    if not required.issubset(data):
        return jsonify({"error": f"missing fields: {required - data.keys()}"}), 400

    name = data["name"]
    enroll_port = int(data.get("enroll_port", 8446))
    server_dir = os.path.join(CERTS_DIR, name)
    os.makedirs(server_dir, exist_ok=True)
    cert_path = os.path.join(server_dir, "client.pem")
    key_path = os.path.join(server_dir, "client.key")
    ca_path = os.path.join(server_dir, "ca.pem")

    try:
        enroll_certificate(
            host=data["host"], enroll_port=enroll_port,
            username=data["username"], password=data["password"],
            client_uid=name,
            out_cert_path=cert_path, out_key_path=key_path, out_ca_path=ca_path,
        )
    except EnrollmentError as exc:
        return jsonify({"error": f"enrollment failed: {exc}"}), 400

    server_cfg = {
        "name": name,
        "host": data["host"],
        "port": int(data["port"]),
        "cert": cert_path,
        "key": key_path,
        "ca": ca_path if os.path.exists(ca_path) else None,
        "cert_password": None,
        "ca_password": None,
        "verify_ca": data.get("verify_ca", True),
        "direction": data.get("direction", "both"),
        "trust_uid": data.get("trust_uid", True),
        "enabled": True,
        # the username is not a secret - saved for convenience so it's
        # pre-filled next time you re-enroll (refresh the certificate).
        # The password is NEVER saved anywhere, by design - it's used once
        # for this request only.
        "enroll_username": data["username"],
    }

    existing_names = {s["name"] for s in manager.config.get("servers", [])}
    try:
        if name in existing_names:
            manager.update_server(name, server_cfg)
        else:
            manager.add_server(server_cfg)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"ok": True})


@app.route("/api/servers/<name>", methods=["PUT"])
def api_edit_server(name):
    new_name = request.form.get("name", "").strip() or name
    updates = {
        "name": new_name,
        "host": request.form.get("host", "").strip(),
        "cert_password": request.form.get("cert_password") or None,
        "ca_password": request.form.get("ca_password") or None,
        "verify_ca": request.form.get("verify_ca") == "true",
        "direction": request.form.get("direction", "both"),
        "trust_uid": request.form.get("trust_uid", "true") == "true",
    }
    port_raw = request.form.get("port", "")
    if port_raw:
        try:
            updates["port"] = int(port_raw)
        except ValueError:
            return jsonify({"error": "port must be a number"}), 400

    # a new file replaces the certificate; no file -> keep whatever is
    # already configured (nothing about it is shown or re-typed)
    server_dir = os.path.join(CERTS_DIR, new_name)
    cert_file = request.files.get("cert_file")
    if cert_file and cert_file.filename:
        updates["cert"] = _save_uploaded_cert(cert_file, server_dir, "client")
    ca_file = request.files.get("ca_file")
    if ca_file and ca_file.filename:
        updates["ca"] = _save_uploaded_cert(ca_file, server_dir, "truststore")

    try:
        manager.update_server(name, updates)
    except KeyError:
        return jsonify({"error": "not found"}), 404
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"ok": True})


@app.route("/api/servers/<name>", methods=["DELETE"])
def api_delete_server(name):
    manager.delete_server(name)
    return jsonify({"ok": True})


@app.route("/api/servers/<name>/toggle", methods=["POST"])
def api_toggle_server(name):
    try:
        manager.toggle_server(name)
    except KeyError:
        return jsonify({"error": "not found"}), 404
    return jsonify({"ok": True})


@app.route("/api/routes", methods=["GET"])
def api_list_routes():
    return jsonify(manager.list_routes())


@app.route("/api/routes", methods=["POST"])
def api_add_route():
    data = request.get_json(force=True) or {}
    if "from" not in data or "to" not in data:
        return jsonify({"error": "missing 'from' or 'to'"}), 400
    route_id = manager.add_route(data)
    return jsonify({"ok": True, "id": route_id})


@app.route("/api/routes/<route_id>", methods=["PUT"])
def api_edit_route(route_id):
    data = request.get_json(force=True) or {}
    if "from" not in data or "to" not in data:
        return jsonify({"error": "missing 'from' or 'to'"}), 400
    try:
        manager.update_route(route_id, data)
    except KeyError:
        return jsonify({"error": "not found"}), 404
    return jsonify({"ok": True})


@app.route("/api/routes/<route_id>", methods=["DELETE"])
def api_delete_route(route_id):
    manager.delete_route(route_id)
    return jsonify({"ok": True})


@app.route("/api/items", methods=["GET"])
def api_list_items():
    return jsonify(manager.items())


@app.route("/api/chat", methods=["GET"])
def api_list_chat():
    return jsonify(manager.chat_messages())


@app.route("/api/auth", methods=["GET"])
def api_auth_status():
    username, _secret, _mode = _current_auth()
    return jsonify({"configured": username is not None, "username": username or ""})


@app.route("/api/auth", methods=["POST"])
def api_auth_change():
    data = request.get_json(force=True) or {}
    new_username = (data.get("new_username") or "").strip()
    new_password = data.get("new_password") or ""
    if not new_username or not new_password:
        return jsonify({"error": "new username and password are required"}), 400

    cur_user, _secret, _mode = _current_auth()
    if cur_user is not None:
        # already configured - must prove the CURRENT credentials to change them
        cur_username_input = data.get("current_username", "")
        cur_password_input = data.get("current_password", "")
        if not _check_credentials(cur_username_input, cur_password_input):
            return jsonify({"error": "current username/password is incorrect"}), 403

    manager.set_web_auth(new_username, new_password)
    return jsonify({"ok": True})


if __name__ == "__main__":
    port = int(os.environ.get("RELAY_WEB_PORT", 5077))
    if manager.get_web_auth() is None and not (WEB_USER and WEB_PASS):
        print("[web_dashboard] WARNING: no panel login configured - the panel is reachable "
              "WITHOUT a password by anyone who can hit the port. Set one up from the "
              "'Panel access' control in the UI, or via RELAY_WEB_USER/RELAY_WEB_PASS.")

    use_tls = os.environ.get("RELAY_WEB_TLS", "").lower() in ("1", "true", "yes")
    if use_tls:
        # ad-hoc self-signed cert, generated on the fly by Flask/pyOpenSSL -
        # not for a trusted-cert experience (browsers will warn), just so
        # enroll credentials and everything else aren't sent in the clear
        # over the network between the browser and this panel.
        try:
            app.run(host="0.0.0.0", port=port, debug=False, ssl_context="adhoc")
        except ImportError:
            print("[web_dashboard] RELAY_WEB_TLS is set but pyOpenSSL isn't installed. "
                  "Run: pip install pyopenssl - falling back to plain HTTP for now.")
            app.run(host="0.0.0.0", port=port, debug=False)
    else:
        app.run(host="0.0.0.0", port=port, debug=False)
