{
    "name": "Upgrade Panel Agent",
    "summary": "Kobler Odoo til oppgraderingspanelet: hent backup, og (bare i staging) legg inn en oppgradert kopi, uten database manager",
    "description": """
Gives an Odoo upgrade panel read-only access to a backup of *this* database (SQL dump,
manifest and filestore), so ``list_db`` can stay ``False`` and the master password is
never shared.

* Off by default. An administrator opens access for a limited number of hours.
* A dedicated key, shown once and stored only as a hash.
* Optional IP allowlist.
* Reads by default: no drop, restore, create or rename.
* Optional, per database and off by default: let the panel replace a staging/test database
  with an upgraded copy. Uploaded in small chunks (no proxy size limits), restored as a new
  database (new database ID, neutralized), then swapped in. The old database is kept as a backup.
* Health check (read only): installed modules without code on the server, outdated
  modules, modules stuck in an operation, neutralization and recent errors in the log.
* Every call is logged.
""",
    "version": "1.3.0",
    "category": "Administration",
    "author": "ITILITI AS",
    "website": "https://itiliti.no",
    "images": ["static/description/banner.png"],
    "license": "LGPL-3",
    "depends": ["base"],
    "data": [
        "data/access.xml",
        "views/agent_views.xml",
    ],
    "installable": True,
    "application": False,
}
