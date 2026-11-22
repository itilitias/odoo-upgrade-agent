# Odoo Upgrade Agent

Two small tools that let the Odoo upgrade panel work with any hosting provider without enabling Odoo's database manager (`list_db`) or sharing the master password.

## `upgrade_panel_agent/` – Odoo module (fetch backups)

Install it like any other custom module (CloudPepper: *Details → Addons → add this repository*; Skysize/Odoo.sh: add to your deploy repository; own server: copy into `addons_path`). Depends only on `base`; written for Odoo 16–19, tested on 19.

In Odoo: *Settings → Upgrade panel agent*

1. **Create new key** – shown once, stored only as a hash.
2. Optionally restrict to the panel's IP, then **Open access** (default 4 hours, max 72).
3. Paste the address and key into the panel ("New job → Via agent").

The agent can only read a backup of its own database. It cannot drop, restore, create or rename databases. Every call is logged; access closes automatically after 10 wrong keys.

## `ssh/odoo-upgrade-receive` – receiver script (upload results)

Lets the panel restore an upgraded database over SSH with a key that can run nothing else:

```
sudo curl -fsSL -o /usr/local/bin/odoo-upgrade-receive https://raw.githubusercontent.com/itilitias/odoo-upgrade-agent/main/ssh/odoo-upgrade-receive
sudo chmod 755 /usr/local/bin/odoo-upgrade-receive
```

Then add the line shown in the panel (*Settings → SSH*) to `~/.ssh/authorized_keys` of the user Odoo runs as:

```
command="/usr/local/bin/odoo-upgrade-receive",restrict,from="<panel ip>" ssh-ed25519 AAAA… odoo-upgrade-panel
```

Optional `/etc/odoo-upgrade-receive.conf`:

```
[receive]
odoo_conf = /etc/odoo/odoo.conf
allow_overwrite = false
after_restore =
```

Source of truth: `agent/` in the upgrade panel repository.
