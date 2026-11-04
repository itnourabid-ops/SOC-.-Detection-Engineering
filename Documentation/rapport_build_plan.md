# Plan du rapport de BUILD (PDF – livraison 06/11/2026 23h)

Construit pour suivre le barème « Rendu BUILD » de la présentation projet. Cible : 15 à 25 pages.

1. **Introduction**
   - Contexte AEGIS CyberProtect / Dunder Mifflin, objectifs du Mini SOC (faible coût, passage à l'échelle)
   - Organisation de l'équipe (rôles), outils (Git, Teams)
2. **Architecture et sources de données** → `Documentation/architecture.md`
   - Schéma prod + lab ; tableau des sources ; **écarts de journalisation identifiés** (point fort)
   - Validation du lab : captures auditpol, Observateur d'événements, `stats values(source) by host`, alerte TestAlert dans IRIS
3. **Stratégie de détection** *(5 pts)*
   - Méthode : Sigma de référence → compréhension → adaptation SPL → test → durcissement (cas WMIExec détaillé : partage, PowerShell, silentcommand)
   - Tableau des 15+ règles : MITRE, sources, sévérité et justification, exclusions
   - Logique d'exécution (fenêtres décalées de 5 min, throttling)
   - Mesures d'endiguement : renvoi vers les fiches réflexes
4. **Outillage et automatisation** *(6 pts)*
   - Détection-as-code : YAML → générateur → savedsearches.conf versionné
   - Workflow n8n (capture), enrichissement, brouillon de notification automatique
   - Résultats des tests sur le lab (tableau règle / commande / détecté ? / capture)
5. **Procédures et documentation** *(6 pts)*
   - Workflow d'investigation, SLA, statuts IRIS, MCO / MCD
   - Librairie de pivots (extrait), matrices de priorisation et de communication
6. **Limites et axes d'amélioration**
   - Règles non validées sur le lab et pourquoi ; dépendances de collecte (SACL, PowerShell) ; règles bonus envisagées
7. **Annexes** : liste des fichiers du dépôt, export SA_BUILD
