#!/usr/bin/env python3
"""
Génère SA_BUILD/local/savedsearches.conf et SA_BUILD/metadata/local.meta
à partir des règles pseudo-Sigma de Detection/**/*.yml.

Conventions imposées (Guide BUILD p.5 / p.13-14) :
  - nom "[BUILD] [SEVERITY] <title>"
  - action webhook vers n8n
  - alerte partagée dans l'application SA_BUILD

Usage :
  python3 Automatisation/sigma2savedsearch.py            # génère
  python3 Automatisation/sigma2savedsearch.py --check    # valide seulement
  python3 Automatisation/sigma2savedsearch.py --disabled # génère avec disabled = 1
Déploiement :
  scp SA_BUILD/local/savedsearches.conf user@<SOC>:/tmp/
  sudo cp /tmp/savedsearches.conf /opt/splunk/etc/apps/SA_BUILD/local/
  sudo /opt/splunk/bin/splunk restart   (ou | rest /services/saved/searches/_reload)
"""
import argparse
import pathlib
import sys
import urllib.parse

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
DETECTION = ROOT / "Detection"
OUT_CONF = ROOT / "SA_BUILD" / "local" / "savedsearches.conf"
OUT_META = ROOT / "SA_BUILD" / "metadata" / "local.meta"

WEBHOOK_URL = "http://soc_n8n:5678/webhook/alert"
SEVERITY = {  # level Sigma -> (libellé, alert.severity Splunk)
    "informational": ("INFO", 1), "info": ("INFO", 1),
    "low": ("LOW", 2), "medium": ("MEDIUM", 3),
    "high": ("HIGH", 4), "critical": ("CRITICAL", 5),
}
REQUIRED = ["title", "id", "description", "level", "logsource", "detection", "x_splunk"]


def load_rules():
    rules, errors = [], []
    for path in sorted(DETECTION.rglob("*.yml")):
        if path.name.startswith("_"):
            continue
        try:
            rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            errors.append(f"{path}: YAML invalide ({exc})")
            continue
        missing = [k for k in REQUIRED if k not in rule]
        if missing:
            errors.append(f"{path}: champs manquants {missing}")
            continue
        if rule["level"] not in SEVERITY:
            errors.append(f"{path}: level inconnu '{rule['level']}'")
            continue
        if not rule["x_splunk"].get("search", "").strip():
            errors.append(f"{path}: x_splunk.search vide")
            continue
        rule["_path"] = path.relative_to(ROOT)
        rules.append(rule)
    ids = [r["id"] for r in rules]
    for dup in {i for i in ids if ids.count(i) > 1}:
        errors.append(f"id dupliqué : {dup}")
    return rules, errors


def conf_multiline(text):
    """Les valeurs multi-lignes d'un .conf Splunk se terminent par ' \\'."""
    lines = [l.rstrip() for l in text.strip().splitlines()]
    return " \\\n".join(lines)


def stanza_name(rule):
    return f"[BUILD] [{SEVERITY[rule['level']][0]}] {rule['title']}"


def build_stanza(rule, disabled):
    s = rule["x_splunk"]
    name = stanza_name(rule)
    desc = " ".join(rule["description"].split())
    desc += f" | Règle: {rule['_path']} (id {rule['id']})"
    lines = [
        f"[{name}]",
        f"description = {desc}",
        f"search = {conf_multiline(s['search'])}",
        "enableSched = 1",
        f"disabled = {1 if disabled else 0}",
        f"cron_schedule = {s.get('cron', '*/15 * * * *')}",
        f"dispatch.earliest_time = {s.get('earliest', '-20m@m')}",
        f"dispatch.latest_time = {s.get('latest', '-5m@m')}",
        "schedule_window = auto",
        "counttype = number of events",
        "relation = greater than",
        "quantity = 0",
        f"alert.digest_mode = {0 if s.get('trigger', 'once') == 'each' else 1}",
        f"alert.severity = {SEVERITY[rule['level']][1]}",
        "alert.track = 1",
        "alert.expires = 24h",
        "action.webhook = 1",
        f"action.webhook.param.url = {WEBHOOK_URL}",
        "request.ui_dispatch_app = SA_BUILD",
        "request.ui_dispatch_view = search",
    ]
    thr = s.get("throttle")
    if thr:
        lines += [
            "alert.suppress = 1",
            f"alert.suppress.period = {thr.get('period', '1h')}",
        ]
        if thr.get("fields"):
            lines.append(f"alert.suppress.fields = {thr['fields']}")
    else:
        lines.append("alert.suppress = 0")
    return "\n".join(lines)


def build_meta(rules):
    out = []
    for r in rules:
        key = urllib.parse.quote(stanza_name(r), safe="")
        out += [
            f"[savedsearches/{key}]",
            "access = read : [ * ], write : [ admin, power ]",
            "export = none",           # partagé dans l'app (Shared in App)
            "owner = admin",
            "",
        ]
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="valider sans générer")
    ap.add_argument("--disabled", action="store_true", help="générer les alertes désactivées")
    args = ap.parse_args()

    rules, errors = load_rules()
    for e in errors:
        print(f"[ERREUR] {e}", file=sys.stderr)
    print(f"{len(rules)} règle(s) valide(s).")
    for r in rules:
        flag = "OK " if r.get("x_collecte", {}).get("valide_sur_lab") else "..."
        print(f"  [{flag}] {stanza_name(r)}")
    if errors:
        sys.exit(1)
    if args.check:
        return

    header = ("# FICHIER GÉNÉRÉ par Automatisation/sigma2savedsearch.py – ne pas éditer à la main.\n"
              "# Modifier les YAML dans Detection/ puis régénérer.\n\n")
    OUT_CONF.parent.mkdir(parents=True, exist_ok=True)
    OUT_CONF.write_text(header + "\n\n".join(build_stanza(r, args.disabled) for r in rules) + "\n",
                        encoding="utf-8")
    OUT_META.parent.mkdir(parents=True, exist_ok=True)
    OUT_META.write_text(header + build_meta(rules), encoding="utf-8")
    print(f"→ {OUT_CONF.relative_to(ROOT)}\n→ {OUT_META.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
