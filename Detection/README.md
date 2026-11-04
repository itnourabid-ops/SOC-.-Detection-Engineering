# Règles de détection – conventions

## Format pseudo-Sigma

Chaque règle est un fichier YAML qui reprend les champs **Sigma standards** (`title`, `id`, `status`, `description`, `references`, `tags`, `logsource`, `detection`, `falsepositives`, `level`), complétés par des **extensions `x_*`** propres au Groupe 3 :

| Champ | Rôle |
|---|---|
| `x_collecte` | Événements requis, prérequis de journalisation, statut de validation sur le lab |
| `x_splunk` | SPL réellement déployé, planification, throttling |
| `x_exclusions` | Mécanismes d'exclusion (faux positifs connus, comptes et hôtes de service) |
| `x_triage` | Questions à se poser pour qualifier l'alerte (vrai ou faux positif) |
| `x_reponse` | Mesures d'endiguement et de remédiation |
| `x_test` | Comment rejouer l'attaque sur le lab, et résultat obtenu |

Le bloc `detection` reste en syntaxe Sigma pour la lisibilité et la portabilité. **Le SPL de `x_splunk.search` fait foi** : c'est lui qui est adapté à notre collecte (index, source, noms de champs).

> Ne jamais coller ces règles dans un convertisseur en ligne (uncoder.io…). Pour convertir, utiliser `sigma-cli` en local.

## Nommage des alertes

`[BUILD] [SEVERITY] <Nom>`, où SEVERITY ∈ `INFO | LOW | MEDIUM | HIGH | CRITICAL`. Le nom est généré automatiquement à partir de `level` et `title`.

## Sévérité

| Level | Critère | Exemples |
|---|---|---|
| `critical` | Compromission avérée ou imminente de l'AD / des identifiants à privilèges | DCSync, dump LSASS |
| `high` | Technique offensive caractérisée, faible taux de faux positifs | WMIExec, Kerberoasting, Shadow Credentials, password looting |
| `medium` | Comportement suspect qui demande une qualification | Tâche planifiée ou service suspect, clé Run, password spraying |
| `low` | Signal faible, utile en corrélation | Énumération Linux, scan interne |

## Logique d'exécution

Les fenêtres sont **décalées de 5 minutes** (`latest = -5m@m`) pour absorber la latence d'indexation du Universal Forwarder. La largeur de la fenêtre est **égale à la période cron**, ce qui évite à la fois les trous et les doublons.
Exemple : cron `*/15 * * * *`, fenêtre `-20m@m → -5m@m`.

## Inventaire

| Domaine | Règle | Fichier | Level | Validée lab |
|---|---|---|---|---|
| AD | Kerberoasting | `ad/kerberoasting.yml` | high | ☐ |
| AD | AS-REPRoasting | `ad/asreproasting.yml` | high | ☐ |
| AD | Shadow Credentials | `ad/shadow_credentials.yml` | high | ☐ |
| AD | Password Spraying | `ad/password_spraying.yml` | medium | ☐ |
| AD | DCSync | `ad/dcsync.yml` | critical | ☐ |
| Windows | Tâche planifiée suspecte | `windows/tache_planifiee_suspecte.yml` | medium | ☐ |
| Windows | Service suspect | `windows/service_suspect.yml` | medium | ☐ |
| Windows | Clé Run | `windows/cle_run.yml` | medium | ☐ |
| Windows | Dump LSASS | `windows/dump_lsass.yml` | critical | ☐ |
| Windows | Impacket WMIExec | `windows/impacket_wmiexec.yml` | high | ☐ |
| Windows | Exécution WMI distante (silentcommand) | `windows/wmi_execution_distante.yml` | medium | ☐ |
| Linux | Énumération | `linux/enumeration.yml` | low | ☐ |
| Linux | Password looting | `linux/password_looting.yml` | high | ☐ |
| Réseau | Scan de ports | `reseau/scan_ports.yml` | medium | ☐ |
| Réseau | Beaconing C2 | `reseau/beaconing.yml` | high | ☐ |
| Bonus | *(1 par étudiant)* | | | ☐ |
