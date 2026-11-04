# Processus du Mini SOC

## 1. Workflow d'investigation (cycle de vie d'une alerte)

```
 Splunk (alerte [BUILD]) ──► n8n ──► DFIR-IRIS (alerte "New")
                                         │
              ┌──────────────────────────┘
              ▼
 1. TRIAGE (< 15 min)  ── matrice de triage ──► priorité P1..P4
              │  Faux positif ? ──► clôture "False positive" + demande d'exclusion (MCD)
              ▼
 2. QUALIFICATION  ── pivots Investigation/ ──► incident avéré / suspect / bénin
              │  Bénin ──► clôture "Not applicable" (commentaire obligatoire)
              ▼
 3. INCIDENT : alerte ──► "Case" IRIS (merge des alertes liées)
              │
              ├─► Notification client (HIGH/CRITICAL : < 2h)  [template]
              ├─► Rapport d'investigation v1 (< 4h HIGH/CRIT, 8h MED, 12h LOW)  [template]
              ▼
 4. INVESTIGATION APPROFONDIE ── chronologie, Kill Chain, IOCs dans IRIS
              │
              ├─► Rapport final / complément (< 72h HIGH/CRIT)
              ▼
 5. CLÔTURE ── retour d'expérience ──► nouvelle règle / ajustement (MCD)
```

## 2. Engagements de service (SLA)

| Sévérité | Notification | Qualification (rapport v1) | Investigations complémentaires |
|---|---|---|---|
| LOW | – | 12h | – |
| MEDIUM | – | 8h | – |
| HIGH | 2h | 4h | 72h |
| CRITICAL | 2h | 4h | 72h |

La notification, par mail ou par téléphone si c'est urgent, est obligatoire pour toute intrusion avérée sous 4h.
**Canal** : conversation Teams « sollicitations client » du groupe.
**Nomenclature** :
- `[5A-4AS] [Groupe-3] Incident n°X - notification client`
- `[5A-4AS] [Groupe-3] Incident n°X - rapport d'investigation_v1`
- `[5A-4AS] [Groupe-3] Incident n°X - rapport d'investigation_final`

## 3. Statuts IRIS

| Statut alerte | Usage |
|---|---|
| New | Non traitée |
| In progress | Analyste assigné (s'assigner **avant** de commencer) |
| Closed – False positive | Logique de règle prise en défaut → ticket MCD |
| Closed – Not applicable / benign | Comportement réel mais légitime (documenter qui a confirmé) |
| Escalated → Case | Incident avéré ou suspect |

## 4. Rôles (à adapter selon les membres)

| Rôle | Responsabilité RUN | Titulaire |
|---|---|---|
| Analyste N1 (triage) | Surveille IRIS, triage, premiers pivots | |
| Analyste N2 (investigation) | Qualification, rapport, IOCs | |
| Responsable communication | Notifications, appel client, respect des SLA | |
| Detection engineer | Exclusions, correctifs de règles (MCD), suivi Git | |

## 5. MCO – Maintien en condition opérationnelle

| Contrôle | Fréquence | Requête / action |
|---|---|---|
| Tous les hôtes remontent | Quotidien + avant le RUN | `index=main earliest=-1h \| stats latest(_time) as last by host \| eval retard_min=round((now()-last)/60)` |
| Les alertes s'exécutent sans erreur | Quotidien | `index=_internal sourcetype=scheduler savedsearch_name="[BUILD]*" \| stats count by savedsearch_name status` |
| Le webhook n8n répond | Quotidien | Historique d'exécution n8n ; test RDP `TestAlert` (Guide BUILD p.6) |
| Forwarder Windows OK | Si un hôte est absent | `C:\Program Files\SplunkUniversalForwarder\var\log\splunk\splunkd.log` |

## 6. MCD – Maintien en condition de détection

1. Tout faux positif donne lieu à une exclusion **la plus ciblée possible** (combinaison compte + hôte + processus, jamais un hôte seul), ajoutée dans `x_exclusions` et dans le SPL.
2. Le YAML est modifié, puis on lance `python3 Automatisation/sigma2savedsearch.py`, on déploie et on commit `detection: <règle> – exclusion <motif>`.
3. Chaque modification est tracée dans `modified:` et dans le journal Git (preuve pour la note de prise de recul).
4. Après chaque incident, on se demande : une règle aurait-elle pu détecter plus tôt ? Si oui, on ouvre un use case.
