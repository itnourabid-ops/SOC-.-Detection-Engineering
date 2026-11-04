# Fiches réflexes – endiguement et remédiation

Chaque règle a ses mesures spécifiques dans son YAML (`x_reponse`). Ce fichier regroupe les **fiches par scénario**, pour l'appel client et la cellule de crise.

---

## FR-01 – Compromission d'identifiants AD
*Règles : Kerberoasting, AS-REPRoasting, Password Spraying, Shadow Credentials*

| Étape | Action | Qui |
|---|---|---|
| Endiguer | Réinitialiser le mot de passe des comptes visés ou compromis ; désactiver le compte attaquant | IT client |
| Endiguer | Bloquer l'IP source (FW) ; révoquer le nœud Tailscale si l'IP est en 100.x | IT client |
| Vérifier | Authentifications réussies des comptes visés depuis l'alerte (P-AUTH-01/04) | SOC |
| Remédier | gMSA, mots de passe longs, AES only, pré-auth obligatoire, MFA sur l'accès distant | IT client |
| À ne pas faire | Réinitialiser sans vérifier si l'attaquant a déjà utilisé le compte (perte de traçabilité de sa progression) | – |

## FR-02 – Compromission totale du domaine
*Règles : DCSync, Dump LSASS sur le DC*

| Étape | Action |
|---|---|
| Alerter | Appel au RSSI ≤ 2h ; proposer l'ouverture d'une **cellule de crise** |
| Endiguer | Isoler les hôtes sources ; désactiver les comptes utilisés ; couper Tailscale si l'accès initial est distant |
| Endiguer | Réinitialiser **deux fois** krbtgt (intervalle ≥ 10h) puis tous les comptes à privilèges |
| Remédier | Rotation de tous les mots de passe ; audit des ACL de réplication ; recherche de persistance (GPO, comptes, services, tâches) |
| À ne pas faire | Éteindre le DC ; réinitialiser krbtgt une seule fois ; communiquer sur la messagerie interne potentiellement compromise |

## FR-03 – Mouvement latéral
*Règles : Impacket WMIExec, WMI silentcommand, Service suspect*

| Étape | Action |
|---|---|
| Endiguer | Isoler l'hôte source **et** l'hôte cible (isolement réseau, sans extinction) |
| Endiguer | Désactiver le compte utilisé ; bloquer 135/445/5985 depuis la source |
| Investiguer | Commandes exécutées (règle WMIExec), autres cibles du même compte (P-AUTH-01) |
| Remédier | Tiering admin, LAPS, restriction SMB/WMI aux postes d'administration |

## FR-04 – Persistance Windows
*Règles : tâche planifiée, service, clé Run*

| Étape | Action |
|---|---|
| Collecter | Exporter la tâche (XML), la clé ou le binaire du service **avant** de supprimer |
| Endiguer | Désactiver puis supprimer la persistance ; mettre le binaire en quarantaine |
| Investiguer | Hash du binaire sur le parc (P-PROC-02) ; processus créateur (P-PROC-01) |

## FR-05 – Compromission d'un serveur Linux
*Règles : énumération, password looting*

| Étape | Action |
|---|---|
| Endiguer | Couper la session (`pkill -KILL -u <user>`), bloquer l'IP source ; si bastion : couper Tailscale |
| Endiguer | Rotation des secrets lus (clés SSH, tokens, mots de passe applicatifs) |
| Investiguer | Accès initial (auth.log, Kunai) ; ancêtre web → webshell |

## FR-06 – Activité réseau malveillante
*Règles : scan de ports, beaconing C2*

| Étape | Action |
|---|---|
| Endiguer | Bloquer la destination C2 (FW + DNS) ; isoler l'hôte source |
| Investiguer | Processus à l'origine (Sysmon 3 / Kunai connect) ; autres hôtes contactant la même destination |
