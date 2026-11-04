# SOC - Detection Engineering

Mini SOC **AEGIS CyberProtect** – périmètre client **Dunder Mifflin**.
Phase de BUILD : conception, test et documentation d'un jeu de règles de détection (Splunk → n8n → DFIR-IRIS).

## Arborescence

| Dossier | Contenu |
|---|---|
| `Detection/` | Règles de détection au format **pseudo-Sigma** (1 fichier YAML = 1 règle) + conventions |
| `Investigation/` | Librairie de pivots SPL pour la qualification et l'investigation |
| `Automatisation/` | Générateur `savedsearches.conf`, workflows n8n exportés, templates (notification client, rapport) |
| `Documentation/` | Architecture et écarts de collecte, processus (workflow, SLA, MCO/MCD), matrices, fiches réflexes, plan du rapport |
| `SA_BUILD/` | Copie versionnée de l'app Splunk (`local/savedsearches.conf`, `metadata/local.meta`, dashboards) |

## Chaîne de détection

```
Endpoints (Security / System / Sysmon / Kunai / Suricata)
   └─ Splunk Universal Forwarder ──► Splunk (index=main, app SA-BUILD)
         └─ Alerte planifiée "[BUILD] [SEVERITY] ..." ──► webhook n8n (http://soc_n8n:5678/webhook/alert)
               └─ n8n : normalisation / enrichissement ──► alerte DFIR-IRIS
```

## Workflow de contribution

1. Écrire / modifier la règle dans `Detection/<domaine>/<regle>.yml` (partir de `Detection/_template.yml`).
2. Tester le SPL dans Splunk (Search & Reporting) en rejouant l'attaque depuis Kali.
3. Passer `x_collecte.valide_sur_lab: true` et renseigner `x_test.resultat`.
4. Régénérer la conf : `python3 Automatisation/sigma2savedsearch.py`
5. Déployer `SA_BUILD/local/savedsearches.conf` sur le SOC, puis vérifier l'alerte dans IRIS.
6. Commit : `git commit -m "detection: <regle> – <changement>"`.

## Livrables (VABF – 06/11/2026 23h)

- [ ] Dépôt Git (ce projet)
- [ ] Export de l'app Splunk SA_BUILD
- [ ] Rapport de BUILD (PDF) – plan dans `Documentation/rapport_build_plan.md`

## Démarrage rapide

```bash
pip install pyyaml
python3 Automatisation/sigma2savedsearch.py --check
```
Voir `TODO_lab.md` pour les étapes à réaliser sur le lab.
