# Automatisation

## Contenu

| Fichier | Rôle |
|---|---|
| `sigma2savedsearch.py` | YAML pseudo-Sigma → `SA_BUILD/local/savedsearches.conf` + `metadata/local.meta` (nommage `[BUILD] [SEVERITY]`, webhook n8n, partage dans l'app) |
| `templates/notification_client.md` | Notification client (variables `{{...}}`) |
| `templates/rapport_investigation.md` | Rapport d'investigation v1 / final |
| `n8n/` | Exports JSON des workflows n8n (à versionner après chaque modification) |

## Chaîne Splunk → n8n → IRIS

Le webhook Splunk envoie un JSON de la forme `{ "search_name", "results_link", "sid", "result": {…premier résultat…} }`.

Workflow n8n cible. La base sera le nouveau workflow fourni par les profs ([mail « Update »]) :

1. **Webhook** `POST /webhook/alert`.
2. **Code (Python/JS) – normalisation** :
   - sévérité extraite du nom `[BUILD] [HIGH] …` et convertie en `alert_severity_id` IRIS ;
   - champs clés (`ComputerName`, `src_ip`, `compte`, `User`) extraits vers `alert_source_content` et les IOCs.
3. **Enrichissement** (bonus barème « Automatisation des pivots ») :
   - IP privée → résolution de l'hôte (lookup de l'inventaire) ; IP publique → réputation (AbuseIPDB / OTX) ;
   - requête Splunk `Create a search job` avec le pivot associé à la règle (ex. `P-AUTH-01` sur le compte) et ajout du résultat en note.
4. **DFIR-IRIS HTTP Request** `POST /alerts/add`.
5. **Notification client automatique** (barème) : pour HIGH/CRITICAL, génération d'un brouillon de notification à partir du template, poussé en note dans IRIS, à relire avant envoi.

## Déploiement de la conf Splunk

```bash
python3 Automatisation/sigma2savedsearch.py --check      # validation
python3 Automatisation/sigma2savedsearch.py              # génération
scp SA_BUILD/local/savedsearches.conf SA_BUILD/metadata/local.meta user@<SOC>:/tmp/
ssh user@<SOC> 'sudo cp /opt/splunk/etc/apps/SA_BUILD/local/savedsearches.conf{,.bak} 2>/dev/null; \
  sudo cp /tmp/savedsearches.conf /opt/splunk/etc/apps/SA_BUILD/local/ && \
  sudo cp /tmp/local.meta /opt/splunk/etc/apps/SA_BUILD/metadata/ && \
  sudo chown -R splunk:splunk /opt/splunk/etc/apps/SA_BUILD && sudo /opt/splunk/bin/splunk restart'
```
⚠ Ce fichier **écrase** les alertes créées à la main via l'interface dans SA_BUILD (dont les TestAlert des profs). Récupérer d'abord la conf existante du SOC et fusionner les stanzas `TestAlert`.
