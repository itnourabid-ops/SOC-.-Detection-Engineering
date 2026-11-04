# Architecture supervisée et sources de données

Sources : Présentation projet (infra Dunder Mifflin, politiques d'audit), Guide BUILD (lab), mail « Update: lab detection engineering ».

## 1. Périmètre de production – Dunder Mifflin (RUN)

| Hôte | IP | Rôle | Collecte | Criticité |
|---|---|---|---|---|
| WINSERV-DC | 192.168.10.10 | Contrôleur de domaine AD + AD CS (PKI) | Security (audit DC), System, Sysmon | **Critique** |
| WINSERV-APP | 192.168.10.20 | Web IIS, base MSSQL, partage de fichiers | Security (audit serveurs), System, Sysmon | Haute |
| LINSERV-DEV | 192.168.10.30 | Dépôt de code, partage de fichiers | Kunai | Haute |
| LINSERV-BAST | 192.168.10.90 | Bastion SSH (point d'entrée Tailscale), rebond RDP | Kunai | **Critique** (accès à tout le LAN) |
| DESKTOP-DEV / ADMIN / VIP / AD-ADMIN | 192.168.10.100-120 | Postes de travail | Security, System, Sysmon | Moyenne (VIP / AD-ADMIN : haute) |
| FW + Suricata | – | Pare-feu, sonde NIDS | Suricata eve.json | Haute |
| Collecteur | 192.168.20.0/24 | Relais des journaux vers le Mini SOC | – | – |

Accès distant : uniquement via Tailscale vers le bastion. Aucun service du LAN IT n'est exposé sur Internet.

**Groupes AD sensibles** (pour la priorisation) : VIPs (M. Scott, D. Schrute), AD-Admins (J. Halpert, R. Howard), Servers-Admins (A. Martin, K. Kapoor, A. Bernard), Desktop-Admins / Dev-DevOps (P. Beesly, P. Vance, O. Martinez, S. Hudson).

## 2. Environnement de test (BUILD) – Groupe 3

| Composant | Adresse | Accès |
|---|---|---|
| Lab Groupe 3 (NAT) | 192.168.10.131 | 443 IRIS, 8000 Splunk, 5678 n8n, SSH, RDP |
| SOC (Ubuntu 22.04) | 192.168.10.11 (interne) | Splunk, DFIR-IRIS, n8n |
| DC.test.local | 192.168.10.100 | RDP 3389 |
| SRV.test.local | 192.168.10.101 | RDP 3390 |
| Kali | 192.168.10.200 | SSH 2222 / VNC 5900 |
| Linux Suricata + Kunai | *à déployer* | – |

## 3. Sources de données dans Splunk

| Source | `source` / `sourcetype` | Événements clés utilisés |
|---|---|---|
| Windows Security | `WinEventLog:Security` | 4624/4625, 4662, 4697, 4698, 4768/4769/4771/4776, 5136, 5140/5145 |
| Windows System | `WinEventLog:System` | 7045 |
| Sysmon | `WinEventLog:Microsoft-Windows-Sysmon/Operational` | 1, 3, 10, 11, 12/13, 22 |
| Kunai | `sourcetype=kunai` (JSON) | execve, connect, read… |
| Suricata | `sourcetype=suricata` (eve.json) | flow, alert, dns, tls, http |

Index unique : `main` (lab). **À vérifier en prod** : nom de l'index client (les slides montrent `index="connectix"`).

## 4. Écarts de journalisation identifiés (impact sur la détection)

Cette analyse croise les politiques d'audit (annexes) avec les besoins des règles. Elle est utile pour le rapport et la soutenance.

| Constat | Impact | Contournement |
|---|---|---|
| DC : *Audit Other Object Access Events* = **No Auditing** | Pas de 4698 (création de tâche) sur le DC | Règle tâche planifiée basée sur Sysmon 1 et 11 |
| DC et serveurs : *RPC Events* = No Auditing | Pas de trace RPC directe (DCSync, WMI) | DCSync via 4662 ; WMI via Sysmon 1 |
| Serveurs : *Kerberos* = No Auditing | Normal : seuls les DC journalisent Kerberos | Toutes les règles Kerberos ciblent le DC |
| 5136 / 4662 nécessitent des **SACL** AD | Shadow Credentials / DCSync silencieux si la SACL est absente | Vérifier sur le lab ; pivot de secours 4768 PKINIT |
| DC : *Detailed File Share* = Failure seulement | 5145 en succès absent sur le DC | 5140 (File Share) utilisable |
| *Audit SAM* = No Auditing | Pas de 4661 (énumération SAM) | Non couvert |
| PowerShell/Operational : collecte non confirmée | Pas de 4104 dans Splunk ? | À vérifier (`stats values(source)`) |
| Suricata : visibilité limitée au trafic qui traverse la sonde | Scans / beaconing intra-LAN invisibles | Documenter l'emplacement de la sonde |
