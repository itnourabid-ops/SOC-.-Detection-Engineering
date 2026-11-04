# Matrices de priorisation, de triage et de communication

## 1. Matrice de priorisation

**Priorité = sévérité de la règle × criticité de l'actif / du compte touché.**

| Sévérité ↓ / Actif → | Standard (poste utilisateur) | Sensible (serveur APP/DEV, poste admin) | Critique (DC, bastion, compte Domain/AD-Admin, VIP) |
|---|---|---|---|
| CRITICAL | P1 | P1 | P1 |
| HIGH | P2 | P1 | P1 |
| MEDIUM | P3 | P2 | P2 |
| LOW | P4 | P3 | P3 |

| Priorité | Prise en charge | Exemple |
|---|---|---|
| P1 | Immédiate, tout le monde s'y met | DCSync, dump LSASS sur le DC, WMIExec vers le DC |
| P2 | < 30 min | Kerberoasting, service suspect sur WINSERV-APP |
| P3 | < 2h | Clé Run sur un poste, scan horizontal |
| P4 | Dans la journée | Énumération Linux isolée |

**Facteurs d'escalade** (on monte d'un cran) : plusieurs alertes corrélées sur la même IP, le même compte ou le même hôte en moins de 24h ; une authentification réussie après une attaque d'identifiants ; une activité hors des heures habituelles.

## 2. Grille de triage rapide (5 questions)

1. **Qui ?** Le compte est-il connu, privilégié, cohérent avec son rôle (groupes AD) ?
2. **D'où ?** L'IP source est-elle connue (bastion .90, poste attitré, plage Tailscale) ?
3. **Quoi ?** L'action est-elle de l'administration plausible ou un outil offensif (motif Impacket, Mimikatz) ?
4. **Quand ?** Heure ouvrée ? Changement planifié connu ?
5. **Et ensuite ?** Y a-t-il d'autres alertes ou événements dans les ±2h ? (pivot `P-ALL-01`)

Verdict : **vrai positif** (incident), **vrai positif bénin** (légitime, on documente), ou **faux positif** (on corrige la règle).

## 3. Matrice de communication

| Situation | Destinataire client | Canal | Délai | Contenu |
|---|---|---|---|---|
| Incident CRITICAL / HIGH avéré | RSSI / responsable IT (+ direction si critique) | **Téléphone** puis écrit (Teams) | ≤ 2h | Synthèse, périmètre, mesures d'endiguement urgentes |
| Incident CRITICAL / HIGH qualifié | RSSI / responsable IT | Teams : rapport v1 | ≤ 4h | Qualification argumentée, chronologie, recommandations |
| Incident MEDIUM | Responsable IT | Teams : rapport v1 | ≤ 8h | Qualification + recommandations |
| Incident LOW | Responsable IT | Teams : rapport v1 | ≤ 12h | Qualification |
| Demande d'information (doute sur légitimité) | Responsable IT | Teams | Dès que nécessaire | Question fermée et précise (« X a-t-il lancé Y le … à … ? ») |
| Mise à jour d'investigation | RSSI | Teams : rapport final | ≤ 72h | Compléments, IOCs, état de l'endiguement |
| Faux positif / bénin | – | Interne (IRIS) | – | Pas de sollicitation client |

**Règles de communication** :
- Se présenter (analyste SOC AEGIS CyberProtect), contextualiser (hôte, heure, ce qu'on sait), puis donner les décisions attendues.
- Distinguer **ce qu'on sait / ce qu'on suppose / ce qu'on ignore** (known unknowns).
- Dire ce qu'il **ne faut pas faire** : ne pas éteindre les machines (perte de la mémoire), ne pas prévenir l'utilisateur suspecté, ne pas réinitialiser krbtgt une seule fois.
