import hashlib
import html
import secrets
from datetime import datetime, timedelta

from odoo import api, fields, models

PARAM = "upgrade_panel_agent."


def get_param(env, key, default=""):
    # Rett fra databasen, ikke fra Odoos hurtigbuffer: stenger en administrator tilgangen
    # i én Odoo-prosess, skal alle prosesser se det med en gang.
    env.cr.execute("SELECT value FROM ir_config_parameter WHERE key = %s", (PARAM + key,))
    row = env.cr.fetchone()
    return (row[0] if row else None) or default


def set_param(env, key, value):
    icp = env["ir.config_parameter"].sudo()
    if hasattr(icp, "set_param"):
        icp.set_param(PARAM + key, value or "")
    else:  # Odoo 20: set_str
        icp.set_str(PARAM + key, value or "")


def system_param(env, key, default=""):
    icp = env["ir.config_parameter"].sudo()
    return (icp.get_param(key, default) if hasattr(icp, "get_param") else icp.get_str(key, default)) or default


def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def receive_allowed(env):
    return get_param(env, "receive") == "1"


def open_until(env):
    value = get_param(env, "open_until")
    if not value:
        return None
    try:
        until = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    return until if until > datetime.utcnow() else None


# Tilgang for administratorer. Odoo 20 erstattet ir.model.access med ir.access, så tilgangen lages
# fra koden (data/access.xml kaller _ensure_access ved installasjon og oppgradering) i stedet for en
# CSV-fil som bare virker på én av dem.
ACCESS_MODELS = ("upgrade.agent.log", "upgrade.agent.wizard")


def ensure_access(env):
    group = env.ref("base.group_system")
    for model in ACCESS_MODELS:
        mid = env["ir.model"]._get_id(model)
        name = "upgrade_panel_agent: " + model
        if "ir.access" in env:
            access = env["ir.access"].sudo().with_context(active_test=False)
            if not access.search([("name", "=", name)], limit=1):
                access.create({"name": name, "model_id": mid, "group_id": group.id, "operation": "crud"})
        else:
            access = env["ir.model.access"].sudo().with_context(active_test=False)
            if not access.search([("name", "=", name)], limit=1):
                access.create({"name": name, "model_id": mid, "group_id": group.id, "perm_read": True,
                               "perm_write": True, "perm_create": True, "perm_unlink": True})


class UpgradeAgentLog(models.Model):
    _name = "upgrade.agent.log"
    _description = "Upgrade panel agent log"
    _order = "id desc"

    ip = fields.Char(readonly=True)
    action = fields.Char(readonly=True)
    ok = fields.Boolean(readonly=True)
    detail = fields.Char(readonly=True)

    @api.model
    def _ensure_access(self):
        ensure_access(self.env)

    @api.model
    def add(self, ip, action, ok, detail=""):
        self.sudo().create({"ip": ip, "action": action, "ok": ok, "detail": (detail or "")[:500]})
        # Hold loggen kort
        old = self.sudo().search([], offset=500)
        if old:
            old.unlink()


class UpgradeAgentWizard(models.TransientModel):
    _name = "upgrade.agent.wizard"
    _description = "Upgrade panel agent"
    _rec_name = "name"

    name = fields.Char(default="Upgrade panel agent", readonly=True)
    hours = fields.Integer(string="Open for (hours)", default=4)
    allowed_ips = fields.Char(
        string="Allowed IP addresses",
        help="Comma separated IP addresses or networks (e.g. 203.0.113.10, 10.0.0.0/8). Empty: any address.",
    )
    new_token = fields.Char(string="New key", readonly=True)
    receive_ack = fields.Boolean(
        string="This database is a staging/test copy",
        help="Tick to confirm that this database is NOT production before allowing the panel to replace it.",
    )
    status_html = fields.Html(compute="_compute_status", sanitize=False)
    log_html = fields.Html(compute="_compute_status", sanitize=False)

    @api.model
    def default_get(self, fields_list):
        res = super().default_get(fields_list)
        res["allowed_ips"] = get_param(self.env, "allowed_ips")
        return res

    def _compute_status(self):
        base = system_param(self.env, "web.base.url")
        for rec in self:
            until = open_until(self.env)
            has_key = bool(get_param(self.env, "token_hash"))
            rows = [
                ("Status", f"<b style='color:#1e7f52'>Open until {until:%Y-%m-%d %H:%M} UTC</b>" if until
                 else "<b style='color:#b8322b'>Closed</b>"),
                ("Key", "Set" if has_key else "Not created yet"),
                ("Replace from panel", "<b style='color:#b8322b'>Allowed: the panel may replace this database</b>"
                 if receive_allowed(self.env) else "Not allowed (read only)"),
                ("Agent address", f"<code>{html.escape(base)}</code>"),
                ("Database", f"<code>{html.escape(self.env.cr.dbname)}</code>"),
            ]
            rec.status_html = "<table class='table table-sm'>" + "".join(
                f"<tr><th style='width:30%'>{k}</th><td>{v}</td></tr>" for k, v in rows) + "</table>"
            logs = self.env["upgrade.agent.log"].sudo().search([], limit=30)
            rec.log_html = "<table class='table table-sm'><tr><th>Time (UTC)</th><th>IP</th><th>Action</th><th>Result</th></tr>" + "".join(
                f"<tr><td>{l.create_date:%Y-%m-%d %H:%M:%S}</td><td>{html.escape(l.ip or '')}</td>"
                f"<td>{html.escape(l.action or '')}</td><td>{'OK' if l.ok else 'Denied'} {html.escape(l.detail or '')}</td></tr>"
                for l in logs) + "</table>" if logs else "<p>No calls yet.</p>"

    def _reopen(self):
        return {
            "type": "ir.actions.act_window",
            "res_model": self._name,
            "res_id": self.id,
            "view_mode": "form",
            "target": "current",
        }

    def action_new_key(self):
        token = secrets.token_urlsafe(32)
        set_param(self.env, "token_hash", hash_token(token))
        self.env["upgrade.agent.log"].add("-", "new key", True, f"by {self.env.user.login}")
        self.new_token = token
        return self._reopen()

    def action_open(self):
        hours = max(1, min(self.hours or 4, 72))
        until = datetime.utcnow() + timedelta(hours=hours)
        set_param(self.env, "open_until", until.strftime("%Y-%m-%d %H:%M:%S"))
        set_param(self.env, "allowed_ips", (self.allowed_ips or "").strip())
        set_param(self.env, "fail_count", "0")
        self.env["upgrade.agent.log"].add("-", "opened", True, f"{hours} h by {self.env.user.login}")
        return self._reopen()

    def action_close(self):
        from ..controllers.main import delete_backup_files

        set_param(self.env, "open_until", "")
        delete_backup_files(self.env.cr.dbname)
        self.env["upgrade.agent.log"].add("-", "closed", True, f"by {self.env.user.login}")
        return self._reopen()

    def action_revoke_key(self):
        set_param(self.env, "token_hash", "")
        set_param(self.env, "open_until", "")
        self.env["upgrade.agent.log"].add("-", "key revoked", True, f"by {self.env.user.login}")
        return self._reopen()

    def action_allow_receive(self):
        if not self.receive_ack:
            from odoo.exceptions import UserError

            raise UserError("Tick «This database is a staging/test copy» first. Never allow this in production.")
        set_param(self.env, "receive", "1")
        self.env["upgrade.agent.log"].add("-", "replace allowed", True, f"by {self.env.user.login}")
        return self._reopen()

    def action_block_receive(self):
        set_param(self.env, "receive", "")
        self.env["upgrade.agent.log"].add("-", "replace blocked", True, f"by {self.env.user.login}")
        return self._reopen()
