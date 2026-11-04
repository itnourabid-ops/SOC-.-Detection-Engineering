# Checklist – dès que l'accès au lab est disponible

## A. Accès et sécurité (Mail « Update », Guide BUILD p.2)
- [ ] Tester 192.168.10.131 : 8000 (Splunk), 443 (IRIS), 5678 (n8n), SSH, RDP 3389/3390, Kali
- [ ] Confirmer l'accès dans le canal PROF
- [ ] Changer les mots de passe par défaut (SOC, Splunk, IRIS, n8n, DC, Kali), stockés dans un KeePass partagé (hors Git)
- [ ] Créer les comptes profs et les transmettre en privé

## B. Validation du lab (Guide BUILD p.3-6), avec captures pour le rapport
- [ ] `auditpol /get /category:*` sur DC et SRV, comparé à l'annexe
- [ ] `index=main | stats values(source) by host` → DC + SRV, Sysmon + Security + System
- [ ] PowerShell/Operational collecté ? (sinon le noter dans architecture.md)
- [ ] Test RDP `TestAlert` → alerte dans IRIS (~5 min)
- [ ] **Récupérer la conf existante** : `/opt/splunk/etc/apps/SA_BUILD/local/savedsearches.conf` → la mettre dans Git avant toute modification

## C. Vérifier les noms de champs (le plus important, 15 min)
Lancer ces requêtes et corriger les SPL si un champ diffère :
- [ ] `index=main EventCode=4624 | head 1` → `Logon_ID` multivalué ? `Source_Network_Address` ?
- [ ] `index=main EventCode=4769 | head 1` → `Ticket_Encryption_Type`, `Failure_Code` ou `Status` ?
- [ ] `index=main EventCode=4662 | head 1` (après un secretsdump) → `Properties` ?
- [ ] `index=main EventCode=5136 | head 1` → `LDAP_Display_Name`, `Operation_Type` ?
- [ ] `index=main sourcetype=*sysmon* EventCode=10 TargetImage=*lsass* | head 1` → accès lsass journalisé ?
- [ ] `index=main sourcetype=kunai | head 1` → structure JSON (`info.event.name`, `data.command_line` ?)

## D. Tests d'attaque depuis Kali (commandes dans `x_test` de chaque YAML)
Ordre conseillé : WMIExec (modèle) → service (psexec/smbexec) → tâche (atexec) → clé Run → LSASS → password spraying → Kerberoasting / AS-REP (créer les comptes vulnérables) → DCSync → Shadow Credentials.
Pour chaque test : capture, `valide_sur_lab: true`, `x_test.resultat`, commit.

## E. Linux Suricata + Kunai (Mail « Update »)
- [ ] Demander aux profs où héberger la VM
- [ ] Installation Suricata + Kunai + UF, puis tests énumération / looting / nmap
