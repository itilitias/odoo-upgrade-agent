{
    "name": "Upgrade Panel Agent",
    "summary": "Lets an upgrade panel fetch a backup of this database, and (staging only) replace it, without the database manager",
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
* Every call is logged.
""",
    "version": "1.1.0",
    "category": "Administration",
    "author": "ITILITI AS",
    "license": "LGPL-3",
    "depends": ["base"],
    "data": [
        "security/ir.model.access.csv",
        "views/agent_views.xml",
    ],
    "installable": True,
    "application": False,
}
