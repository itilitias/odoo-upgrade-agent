"""HTTP-endepunkter for oppgraderingspanelet.

Alle kall krever:
* at tilgangen er åpnet (tidsvindu satt av en administrator),
* riktig nøkkel i ``Authorization: Bearer …``,
* at avsenderens IP er i lista, hvis lista er fylt ut.

Backupen lages av en frakoblet prosess (pg_dump + zip), slik at den ikke stoppes av
``limit_time_real``. Panelet henter filen i biter.

Erstatte (bare staging/test, av som standard): når en administrator har slått på «Allow replace»
i denne databasen, kan panelet sende en oppgradert kopi i små biter (ingen grense i proxyen foran
Odoo). En frakoblet prosess gjenoppretter den som ny database, nøytraliserer den, tar med agentens
innstillinger, og bytter navn: den gamle databasen beholdes som <db>_forrige_<tid>.
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

import hashlib

from ..models.agent import get_param, hash_token, open_until, receive_allowed, set_param

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


RECEIVE_SCRIPT = r"""
import json, os, shutil, subprocess, sys, time, zipfile
work, dbname, data_dir, psql = sys.argv[1:5]
status = os.path.join(work, "status.json")
def write(**kw):
    tmp = status + ".tmp"
    with open(tmp, "w") as f:
        json.dump(kw, f)
    os.replace(tmp, status)
def q(name):
    return '"' + name.replace('"', '""') + '"'
def lit(value):
    return "'" + str(value).replace("'", "''") + "'"
def sql(db, *stmts, check=True):
    args = [psql, "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1", "-d", db]
    for st in stmts:
        args += ["-c", st]
    p = subprocess.run(args, capture_output=True, text=True)
    if check and p.returncode != 0:
        raise RuntimeError("psql: " + p.stderr.strip()[-400:])
    return p.stdout.strip()
stamp = time.strftime("%Y%m%d%H%M%S")
new = (dbname + "_upn_" + stamp)[:63]
bak = (dbname + "_forrige_" + stamp)[:63]
fs = os.path.join(data_dir, "filestore")
swapped = False
NEUTRALIZE = [
    "UPDATE ir_cron SET active = false",
    "UPDATE ir_mail_server SET active = false",
    "UPDATE fetchmail_server SET active = false",
    "UPDATE payment_provider SET state = 'disabled' WHERE state <> 'disabled'",
    "UPDATE ir_config_parameter SET value = gen_random_uuid()::text WHERE key = 'database.uuid'",
]
try:
    write(state="running", step="unpack")
    path = os.path.join(work, "incoming.zip")
    target_fs = os.path.join(fs, new)
    with zipfile.ZipFile(path) as zf:
        for n in zf.namelist():
            if n.startswith("/") or ".." in n.split("/"):
                raise RuntimeError("invalid path in backup: " + n)
        zf.extract("dump.sql", work)
        for info in zf.infolist():
            if info.filename.startswith("filestore/") and not info.is_dir():
                dest = os.path.join(target_fs, info.filename[len("filestore/"):])
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with zf.open(info) as src, open(dest, "wb") as out:
                    shutil.copyfileobj(src, out, 1024 * 1024)
    os.makedirs(target_fs, exist_ok=True)
    os.remove(path)
    write(state="running", step="restore")
    sql("postgres", "CREATE DATABASE %s TEMPLATE template0 ENCODING 'UTF8'" % q(new))
    p = subprocess.run([psql, "-X", "-q", "-o", os.devnull, "-d", new, "-f", os.path.join(work, "dump.sql")],
                       capture_output=True, text=True)
    os.remove(os.path.join(work, "dump.sql"))
    if sql(new, "SELECT count(*) FROM information_schema.tables WHERE table_name = 'ir_module_module'") != "1":
        raise RuntimeError("restore failed: " + p.stderr.strip()[-400:])
    if sql(new, "SELECT state FROM ir_module_module WHERE name = 'upgrade_panel_agent'") != "installed":
        raise RuntimeError("the copy does not have upgrade_panel_agent installed; nothing was replaced")
    write(state="running", step="neutralize")
    for st in NEUTRALIZE:
        sql(new, st, check=False)
    # Agentens innstillinger (nøkkel, tilgang, IP-liste, erstatte) følger med, så panelet kan fortsette
    rows = sql(dbname, "SELECT key || chr(9) || coalesce(value, '') FROM ir_config_parameter WHERE key LIKE 'upgrade\\_panel\\_agent.%'")
    stmts = ["DELETE FROM ir_config_parameter WHERE key LIKE 'upgrade\\_panel\\_agent.%'"]
    for line in rows.splitlines():
        key, _, value = line.partition("\t")
        stmts.append("INSERT INTO ir_config_parameter (key, value) VALUES (%s, %s)" % (lit(key), lit(value)))
    sql(new, *stmts)
    write(state="running", step="swap")
    sql("postgres",
        "ALTER DATABASE %s ALLOW_CONNECTIONS false" % q(dbname),
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname IN (%s, %s) AND pid <> pg_backend_pid()" % (lit(dbname), lit(new)),
        "ALTER DATABASE %s RENAME TO %s" % (q(dbname), q(bak)))
    try:
        sql("postgres", "ALTER DATABASE %s RENAME TO %s" % (q(new), q(dbname)))
    except Exception:
        sql("postgres", "ALTER DATABASE %s RENAME TO %s" % (q(bak), q(dbname)),
            "ALTER DATABASE %s ALLOW_CONNECTIONS true" % q(dbname), check=False)
        raise
    swapped = True
    sql("postgres", "ALTER DATABASE %s ALLOW_CONNECTIONS true" % q(bak), check=False)
    if os.path.isdir(os.path.join(fs, dbname)):
        os.rename(os.path.join(fs, dbname), os.path.join(fs, bak))
    os.rename(target_fs, os.path.join(fs, dbname))
    # Be Odoo-prosessene laste databasen på nytt
    sql(dbname, "SELECT nextval(c.oid::regclass) FROM pg_class c WHERE c.relkind = 'S' AND c.relname LIKE 'base\\_%signaling%'", check=False)
    sql(dbname, "INSERT INTO orm_signaling_registry DEFAULT VALUES", check=False)  # Odoo 20
    write(state="done", backup=bak)
except Exception as exc:
    if not swapped:
        sql("postgres", "DROP DATABASE IF EXISTS %s" % q(new), check=False)
        shutil.rmtree(os.path.join(fs, new), ignore_errors=True)
    write(state="failed", error=str(exc)[-600:], swapped=swapped)
finally:
    for n in ("incoming.zip", "dump.sql"):
        try:
            os.remove(os.path.join(work, n))
        except OSError:
            pass
"""
RECEIVE_CHUNK_MAX = 32 * 1024 * 1024


def recv_dir(dbname):
    return os.path.join(config["data_dir"], "upgrade_panel_agent", "receive-" + dbname)


def _find_tool(name):
    try:
        from odoo.tools.misc import find_pg_tool

        return find_pg_tool(name)
    except Exception:
        return shutil.which(name) or name


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
        dbs = _list_dbs()
    except Exception:
        _logger.exception("upgrade_panel_agent: could not list databases")
        return None
    host = request.httprequest.environ.get("HTTP_HOST", "")
    db_filter = getattr(odoo.http, "db_filter", None)
    if db_filter is None:
        try:
            from odoo.http.router import db_filter  # Odoo 20
        except ImportError:
            db_filter = None
    if db_filter:
        try:
            dbs = db_filter(dbs, host=host)
        except TypeError:
            dbs = db_filter(dbs)
    wanted = request.httprequest.args.get("db") or request.httprequest.headers.get("X-Odoo-Database")
    if wanted:
        return wanted if wanted in dbs else None
    return dbs[0] if len(dbs) == 1 else None


def _list_dbs():
    try:
        from odoo.service.db import list_dbs  # Odoo 16–19

        return list_dbs(True)
    except ImportError:
        from odoo.modules.db import list_dbs  # Odoo 20

        return list_dbs(force=True)


def _registry(dbname):
    try:
        from odoo.modules.registry import Registry
    except ImportError:  # Odoo 19+: odoo.orm.registry
        from odoo.orm.registry import Registry
    return Registry(dbname)


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
            registry = _registry(dbname)
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


class UpgradePanelAgentReceive(UpgradePanelAgent):
    """Ta imot en oppgradert kopi og erstatt denne databasen. Bare når «Allow replace» er slått på."""

    def _guard(self, env):
        if not receive_allowed(env):
            return _json({"error": "Replace is not allowed in this database. Allow it in Settings > Upgrade panel agent "
                                   "(staging/test only)."}, 403)
        return None

    @http.route("/upgrade_panel_agent/receive/start", type="http", auth="none", methods=["POST"], csrf=False, save_session=False)
    def receive_start(self, size=0, sha256="", **kw):
        def handler(env, dbname, log, ip):
            denied = self._guard(env)
            if denied:
                log.add(ip, "receive start", False, "replace not allowed")
                return denied
            rdir = recv_dir(dbname)
            st = _read_status(rdir)
            if st.get("state") == "running":
                return _json({"error": "A replace is already running."}, 409)
            total = int(size or 0)
            free = shutil.disk_usage(config["data_dir"]).free
            if total <= 0 or not sha256:
                return _json({"error": "size and sha256 are required."}, 400)
            if free < total * 4:
                return _json({"error": f"Not enough disk space: {free // 1048576} MB free, need about {total * 4 // 1048576} MB."}, 507)
            shutil.rmtree(rdir, ignore_errors=True)
            os.makedirs(rdir)
            with open(os.path.join(rdir, "meta.json"), "w") as f:
                json.dump({"size": total, "sha256": sha256.lower()}, f)
            open(os.path.join(rdir, "incoming.zip"), "wb").close()
            with open(os.path.join(rdir, "status.json"), "w") as f:
                json.dump({"state": "receiving", "received": 0, "size": total}, f)
            log.add(ip, "receive start", True, f"{total} bytes")
            return _json({"state": "receiving", "chunk_max": RECEIVE_CHUNK_MAX})

        return self._run("receive start", handler)

    @http.route("/upgrade_panel_agent/receive/chunk", type="http", auth="none", methods=["POST"], csrf=False, save_session=False)
    def receive_chunk(self, offset=0, **kw):
        def handler(env, dbname, log, ip):
            denied = self._guard(env)
            if denied:
                return denied
            path = os.path.join(recv_dir(dbname), "incoming.zip")
            if not os.path.isfile(path):
                return _json({"error": "No upload in progress. Start again."}, 409)
            have = os.path.getsize(path)
            if int(offset) != have:
                return _json({"error": "Wrong offset.", "received": have}, 409)
            data = request.httprequest.get_data(cache=False)
            if len(data) > RECEIVE_CHUNK_MAX:
                return _json({"error": "Chunk too large.", "received": have}, 413)
            with open(path, "ab") as f:
                f.write(data)
            return _json({"received": have + len(data)})

        return self._run("receive chunk", handler)

    @http.route("/upgrade_panel_agent/receive/finish", type="http", auth="none", methods=["POST"], csrf=False, save_session=False)
    def receive_finish(self, **kw):
        def handler(env, dbname, log, ip):
            denied = self._guard(env)
            if denied:
                return denied
            rdir = recv_dir(dbname)
            path = os.path.join(rdir, "incoming.zip")
            try:
                with open(os.path.join(rdir, "meta.json")) as f:
                    meta = json.load(f)
            except (OSError, ValueError):
                return _json({"error": "No upload in progress. Start again."}, 409)
            if not os.path.isfile(path) or os.path.getsize(path) != meta["size"]:
                return _json({"error": "The upload is incomplete."}, 409)
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(chunk)
            if h.hexdigest() != meta["sha256"]:
                os.remove(path)
                return _json({"error": "Checksum mismatch. The upload was discarded."}, 422)
            import zipfile

            try:
                with zipfile.ZipFile(path) as zf:
                    if "dump.sql" not in zf.namelist():
                        return _json({"error": "The backup has no dump.sql."}, 422)
            except zipfile.BadZipFile:
                return _json({"error": "The upload is not a zip file."}, 422)
            with open(os.path.join(rdir, "status.json"), "w") as f:
                json.dump({"state": "running", "step": "starting"}, f)
            pg_env, _pg_dump = _pg_tools()
            subprocess.Popen(
                [sys.executable, "-c", RECEIVE_SCRIPT, rdir, dbname, config["data_dir"], _find_tool("psql")],
                env=pg_env, start_new_session=True, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True,
            )
            log.add(ip, "replace started", True, f"{meta['size']} bytes")
            return _json({"state": "running", "step": "starting"})

        return self._run("receive finish", handler)

    @http.route("/upgrade_panel_agent/receive/status", type="http", auth="none", methods=["GET"], csrf=False, save_session=False)
    def receive_status(self, **kw):
        return self._run("receive status", lambda env, dbname, log, ip: _json(_read_status(recv_dir(dbname)) or {"state": "none"}))


def health_report(env):
    """Hva som er i orden i denne databasen, sett fra serveren: kode for installerte moduler, versjoner,
    moduler som har stoppet midt i noe, nøytralisering og feil i loggen. Bare lesing."""
    from odoo.modules import module as M

    available = {}
    for name in M.get_modules():
        try:
            man = M.get_manifest(name) or {}
        except Exception:
            man = {}
        if man:
            try:
                version = M.adapt_version(man.get("version") or "1.0")
            except Exception:
                version = man.get("version") or ""
            available[name] = {"version": version, "installable": man.get("installable", True)}
    cr = env.cr
    cr.execute("SELECT name, state, latest_version FROM ir_module_module WHERE state IN "
               "('installed', 'to upgrade', 'to install', 'to remove')")
    installed = cr.fetchall()
    missing, not_installable, outdated, stuck = [], [], [], []
    for name, state, db_version in installed:
        code = available.get(name)
        if state != "installed":
            stuck.append({"module": name, "state": state})
        if not code:
            if state != "to install":
                missing.append(name)
        elif not code["installable"]:
            not_installable.append(name)
        elif db_version and code["version"] and db_version != code["version"]:
            outdated.append({"module": name, "db": db_version, "code": code["version"]})

    def count(sql):
        try:
            cr.execute("SAVEPOINT upa_health")
            cr.execute(sql)
            n = cr.fetchone()[0]
            cr.execute("RELEASE SAVEPOINT upa_health")
            return n
        except Exception:
            cr.execute("ROLLBACK TO SAVEPOINT upa_health")
            return None

    errors = []
    logfile = config.get("logfile")
    if logfile and os.path.isfile(logfile):
        try:
            with open(logfile, "rb") as f:
                f.seek(max(0, os.path.getsize(logfile) - 2_000_000))
                lines = f.read().decode("utf-8", errors="replace").splitlines()
            cutoff = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(time.time() - 3600))
            for line in lines:
                if (" ERROR " in line or " CRITICAL " in line) and line[:19] >= cutoff and f" {cr.dbname} " in line:
                    errors.append(line[:400])
        except OSError:
            pass
    return {
        "db": cr.dbname,
        "version": release.version,
        "available": sorted(available),
        "installed": len(installed),
        "missing": sorted(missing),
        "not_installable": sorted(not_installable),
        "outdated": outdated,
        "stuck": stuck,
        "active_crons": count("SELECT count(*) FROM ir_cron WHERE active"),
        "active_mail_servers": count("SELECT count(*) FROM ir_mail_server WHERE active"),
        "neutralized": bool(count("SELECT count(*) FROM ir_config_parameter WHERE key = 'database.is_neutralized' AND value ILIKE 'true'")),
        "log_errors": errors[-30:],
        "logfile": bool(logfile),
    }


class UpgradePanelAgentHealth(UpgradePanelAgentReceive):

    @http.route("/upgrade_panel_agent/health", type="http", auth="none", methods=["GET"], csrf=False, save_session=False)
    def health(self, **kw):
        def handler(env, dbname, log, ip):
            res = health_report(env)
            log.add(ip, "health", True, f"{len(res['missing'])} missing, {len(res['outdated'])} outdated")
            return _json(res)

        return self._run("health", handler)


def _read_status(work):
    try:
        with open(os.path.join(work, "status.json")) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}
