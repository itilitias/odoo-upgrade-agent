"""HTTP-endepunkter for oppgraderingspanelet.

Alle kall krever:
* at tilgangen er åpnet (tidsvindu satt av en administrator),
* riktig nøkkel i ``Authorization: Bearer …``,
* at avsenderens IP er i lista, hvis lista er fylt ut.

Backupen lages av en frakoblet prosess (pg_dump + zip), slik at den ikke stoppes av
``limit_time_real``. Panelet henter filen i biter.
"""

import hmac
import ipaddress
import json
import logging
import os
import shutil
import subprocess
import sys
import time

import odoo
from odoo import SUPERUSER_ID, api, http, release
from odoo.http import request
from odoo.tools import config

from ..models.agent import get_param, hash_token, open_until, set_param

_logger = logging.getLogger(__name__)
MAX_FAILS = 10
CHUNK_MAX = 64 * 1024 * 1024

BACKUP_SCRIPT = r"""
import json, os, subprocess, sys, zipfile
work, dbname, filestore, pg_dump = sys.argv[1:5]
status = os.path.join(work, "status.json")
def write(**kw):
    tmp = status + ".tmp"
    with open(tmp, "w") as f:
        json.dump(kw, f)
    os.replace(tmp, status)
try:
    write(state="running", step="dump")
    dump = os.path.join(work, "dump.sql")
    with open(os.path.join(work, "pg_dump.log"), "w") as log:
        rc = subprocess.run([pg_dump, "--no-owner", "--format=p", "-f", dump, dbname], stderr=log).returncode
    if rc != 0:
        raise RuntimeError("pg_dump failed with code %s: %s" % (rc, open(os.path.join(work, "pg_dump.log")).read()[-500:]))
    write(state="running", step="zip")
    part = os.path.join(work, "backup.zip.part")
    with zipfile.ZipFile(part, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
        zf.write(dump, "dump.sql")
        zf.write(os.path.join(work, "manifest.json"), "manifest.json")
        if os.path.isdir(filestore):
            for root, _dirs, files in os.walk(filestore):
                for name in files:
                    path = os.path.join(root, name)
                    zf.write(path, os.path.join("filestore", os.path.relpath(path, filestore)))
    os.remove(dump)
    final = os.path.join(work, "backup.zip")
    os.replace(part, final)
    write(state="done", size=os.path.getsize(final))
except Exception as exc:
    write(state="failed", error=str(exc))
"""


def _pg_tools():
    try:
        from odoo.tools.misc import exec_pg_environ, find_pg_tool

        return exec_pg_environ(), find_pg_tool("pg_dump")
    except Exception:
        env = os.environ.copy()
        for key, opt in (("PGHOST", "db_host"), ("PGPORT", "db_port"), ("PGUSER", "db_user"), ("PGPASSWORD", "db_password")):
            if config.get(opt):
                env[key] = str(config[opt])
        return env, shutil.which("pg_dump") or "pg_dump"


def work_dir(dbname):
    return os.path.join(config["data_dir"], "upgrade_panel_agent", dbname)


def delete_backup_files(dbname):
    shutil.rmtree(work_dir(dbname), ignore_errors=True)


def _pick_db():
    try:
        dbs = odoo.service.db.list_dbs(True)
    except Exception:
        return None
    host = request.httprequest.environ.get("HTTP_HOST", "")
    try:
        dbs = odoo.http.db_filter(dbs, host=host)
    except TypeError:
        dbs = odoo.http.db_filter(dbs)
    wanted = request.httprequest.args.get("db") or request.httprequest.headers.get("X-Odoo-Database")
    if wanted:
        return wanted if wanted in dbs else None
    return dbs[0] if len(dbs) == 1 else None


def _json(data, status=200):
    return request.make_response(json.dumps(data), headers=[("Content-Type", "application/json"), ("Cache-Control", "no-store")], status=status)


def _ip_allowed(ip, allowed):
    if not allowed.strip():
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for part in allowed.replace(";", ",").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if addr in ipaddress.ip_network(part, strict=False):
                return True
        except ValueError:
            continue
    return False


class UpgradePanelAgent(http.Controller):

    def _run(self, action, handler):
        """Felles: velg database, kontroller tilgang, logg kallet, kjør handler(env, dbname)."""
        ip = request.httprequest.remote_addr or ""
        dbname = _pick_db()
        if not dbname:
            return _json({"error": "Unknown database. Pass ?db=<name>."}, 404)
        try:
            registry = odoo.modules.registry.Registry(dbname)
        except Exception:
            return _json({"error": "Unknown database."}, 404)
        with registry.cursor() as cr:
            env = api.Environment(cr, SUPERUSER_ID, {})
            if "upgrade.agent.log" not in env:
                return _json({"error": "The agent module is not installed in this database."}, 404)
            log = env["upgrade.agent.log"]
            auth = request.httprequest.headers.get("Authorization") or ""
            token = auth[7:].strip() if auth.startswith("Bearer ") else ""
            expected = get_param(env, "token_hash")
            if not open_until(env):
                log.add(ip, action, False, "access is closed")
                return _json({"error": "Access is closed. Open it in Settings > Upgrade panel agent."}, 403)
            if not _ip_allowed(ip, get_param(env, "allowed_ips")):
                log.add(ip, action, False, "IP not allowed")
                return _json({"error": f"IP address {ip} is not allowed."}, 403)
            if not expected or not token or not hmac.compare_digest(hash_token(token), expected):
                fails = int(get_param(env, "fail_count", "0") or 0) + 1
                set_param(env, "fail_count", str(fails))
                if fails >= MAX_FAILS:
                    set_param(env, "open_until", "")
                    log.add(ip, action, False, "wrong key; access closed after repeated failures")
                else:
                    log.add(ip, action, False, "wrong key")
                time.sleep(1)
                return _json({"error": "Wrong key."}, 401)
            try:
                return handler(env, dbname, log, ip)
            except Exception as exc:
                _logger.exception("upgrade_panel_agent %s failed", action)
                log.add(ip, action, False, str(exc))
                return _json({"error": str(exc)}, 500)

    @http.route("/upgrade_panel_agent/info", type="http", auth="none", methods=["GET"], csrf=False, save_session=False)
    def info(self, **kw):
        def handler(env, dbname, log, ip):
            cr = env.cr
            mods = env["ir.module.module"].search_read(
                [("state", "in", ["installed", "to upgrade", "to remove"])],
                ["name", "state", "latest_version", "license", "author", "website", "shortdesc"],
            )
            cr.execute("SELECT pg_database_size(current_database())")
            db_size = cr.fetchone()[0]
            cr.execute("SHOW server_version")
            pg_version = cr.fetchone()[0]
            names = {m["name"] for m in mods}
            log.add(ip, "info", True)
            return _json({
                "db": dbname,
                "version": release.version,
                "major_version": release.major_version,
                "edition": "enterprise" if "web_enterprise" in names else "community",
                "pg_version": pg_version,
                "db_size": db_size,
                "modules": mods,
                "open_until": open_until(env).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "agent_version": env["ir.module.module"].search([("name", "=", "upgrade_panel_agent")]).installed_version,
            })

        return self._run("info", handler)

    @http.route("/upgrade_panel_agent/backup", type="http", auth="none", methods=["POST"], csrf=False, save_session=False)
    def backup_start(self, **kw):
        def handler(env, dbname, log, ip):
            work = work_dir(dbname)
            status = _read_status(work)
            started = os.path.getmtime(os.path.join(work, "status.json")) if status else 0
            if status.get("state") == "running" and time.time() - started < 4 * 3600:
                return _json(status)
            delete_backup_files(dbname)
            os.makedirs(work, exist_ok=True)
            cr = env.cr
            cr.execute("SELECT name, latest_version FROM ir_module_module WHERE state = 'installed'")
            modules = dict(cr.fetchall())
            cr.execute("SHOW server_version")
            pg_version = cr.fetchone()[0]
            manifest = {
                "odoo_dump": "1",
                "db_name": dbname,
                "version": release.version,
                "version_info": list(release.version_info),
                "major_version": release.major_version,
                "pg_version": pg_version,
                "modules": modules,
            }
            with open(os.path.join(work, "manifest.json"), "w") as f:
                json.dump(manifest, f, indent=4)
            with open(os.path.join(work, "status.json"), "w") as f:
                json.dump({"state": "running", "step": "starting"}, f)
            pg_env, pg_dump = _pg_tools()
            subprocess.Popen(
                [sys.executable, "-c", BACKUP_SCRIPT, work, dbname, config.filestore(dbname), pg_dump],
                env=pg_env, start_new_session=True, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True,
            )
            log.add(ip, "backup started", True)
            return _json({"state": "running", "step": "starting"})

        return self._run("backup", handler)

    @http.route("/upgrade_panel_agent/backup/status", type="http", auth="none", methods=["GET"], csrf=False, save_session=False)
    def backup_status(self, **kw):
        return self._run("status", lambda env, dbname, log, ip: _json(_read_status(work_dir(dbname)) or {"state": "none"}))

    @http.route("/upgrade_panel_agent/backup/download", type="http", auth="none", methods=["GET"], csrf=False, save_session=False)
    def backup_download(self, offset=0, length=CHUNK_MAX, **kw):
        def handler(env, dbname, log, ip):
            path = os.path.join(work_dir(dbname), "backup.zip")
            if not os.path.isfile(path):
                return _json({"error": "No finished backup. Start one first."}, 404)
            start, size = int(offset), os.path.getsize(path)
            n = max(0, min(int(length), CHUNK_MAX, size - start))
            with open(path, "rb") as f:
                f.seek(start)
                data = f.read(n)
            if start == 0:
                log.add(ip, "download", True, f"{size} bytes")
            return request.make_response(data, headers=[
                ("Content-Type", "application/octet-stream"),
                ("X-Total-Size", str(size)),
                ("Cache-Control", "no-store"),
            ])

        return self._run("download", handler)

    @http.route("/upgrade_panel_agent/backup/delete", type="http", auth="none", methods=["POST"], csrf=False, save_session=False)
    def backup_delete(self, **kw):
        def handler(env, dbname, log, ip):
            delete_backup_files(dbname)
            log.add(ip, "backup deleted", True)
            return _json({"state": "deleted"})

        return self._run("delete", handler)


def _read_status(work):
    try:
        with open(os.path.join(work, "status.json")) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}
