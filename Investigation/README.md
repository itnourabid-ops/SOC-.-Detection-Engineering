# Librairie de pivots d'investigation

Requêtes SPL réutilisables pendant la qualification et l'investigation.
Remplacer les `<VARIABLES>`. Par défaut, la plage de temps est de 24 h autour de l'alerte.

> Convention : chaque pivot répond à **une question**. Dans le rapport d'investigation, citer le pivot utilisé (ex. `P-AUTH-02`), puis l'observation et la conclusion.

---

## 1. Identité et authentification

### P-AUTH-01 – D'où vient ce compte ? (connexions réussies)
```spl
index=main source="WinEventLog:Security" EventCode=4624 Account_Name="<COMPTE>"
| eval compte=mvindex(Account_Name,-1), LogonId=mvindex(Logon_ID,-1)
| stats min(_time) as premiere max(_time) as derniere count by compte Logon_Type Source_Network_Address Workstation_Name ComputerName Authentication_Package
| convert ctime(premiere) ctime(derniere)
```
Logon_Type : 2 = interactif, 3 = réseau (SMB/WMI), 10 = RDP, 4/5 = tâche planifiée / service.
`Authentication_Package=NTLM` depuis un poste hors domaine → suspicion de pass-the-hash.

### P-AUTH-02 – Échecs d'authentification d'une source
```spl
index=main source="WinEventLog:Security" (EventCode=4625 OR EventCode=4771 OR EventCode=4776)
  (Source_Network_Address="<IP>" OR Client_Address="*<IP>")
| eval cible=mvindex(Account_Name,-1)
| stats count values(Sub_Status) as sub_status values(Failure_Code) as kerb_code by cible ComputerName
```
Sub_Status 0xC0000064 = utilisateur inexistant ; 0xC000006A = mauvais mot de passe ; 0xC0000234 = compte verrouillé.

### P-AUTH-03 – Tout ce qu'a fait une session (LogonId)
```spl
index=main ComputerName="<HOTE>" (Logon_ID="<LOGONID>" OR LogonId="<LOGONID>")
| table _time source EventCode Image CommandLine TargetFilename TargetObject Service_Name
| sort _time
```

### P-AUTH-04 – Tickets Kerberos d'un compte
```spl
index=main source="WinEventLog:Security" EventCode IN (4768,4769,4770) Account_Name="<COMPTE>*"
| table _time EventCode Client_Address Service_Name Ticket_Encryption_Type Ticket_Options Certificate_Issuer_Name
```
Un 4769 sans 4768 préalable pour le même compte peut signaler un Golden Ticket. Un `Certificate_Issuer_Name` renseigné signale une authentification PKINIT (Shadow Credentials, AD CS).

### P-AUTH-05 – Activité d'administration AD (comptes et groupes)
```spl
index=main source="WinEventLog:Security" EventCode IN (4720,4722,4724,4728,4732,4756,4738,5136)
| table _time ComputerName EventCode Account_Name Group_Name LDAP_Display_Name DN
```

---

## 2. Processus et exécution (Sysmon)

### P-PROC-01 – Arbre de processus d'un hôte
```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 ComputerName="<HOTE>"
| table _time User ParentImage ParentCommandLine Image CommandLine ProcessId ParentProcessId LogonId
| sort _time
```

### P-PROC-02 – Où ce binaire a-t-il été vu ? (hash)
```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Hashes="*<SHA256>*"
| stats min(_time) as premiere count values(Image) as chemins values(User) as users by ComputerName
```

### P-PROC-03 – Enfants de WmiPrvSE / services / tâches (mouvement latéral)
```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  ParentImage IN ("*\\wmiprvse.exe","*\\services.exe","*\\taskeng.exe","*\\svchost.exe") ComputerName="<HOTE>"
  NOT Image IN ("*\\svchost.exe","*\\WmiPrvSE.exe","*\\conhost.exe")
| table _time ParentImage Image CommandLine User LogonId
```

### P-PROC-04 – Commandes PowerShell (script block)
```spl
index=main source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104 ComputerName="<HOTE>"
| table _time ScriptBlockText
```
À vérifier : le journal PowerShell/Operational est-il collecté ? ([Guide BUILD] p.4 ne montre que Sysmon, Security et System.)

---

## 3. Fichiers, registre, persistance

### P-PERS-01 – Persistances créées sur un hôte
```spl
index=main ComputerName="<HOTE>" (
   (source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 TargetObject="*\\Run*")
OR (source="WinEventLog:System" EventCode=7045)
OR (source="WinEventLog:Security" EventCode IN (4697,4698,4702))
OR (source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 TargetFilename="C:\\Windows\\System32\\Tasks\\*") )
| table _time EventCode TargetObject Details Service_Name Service_File_Name Task_Name TargetFilename
```

### P-FILE-01 – Fichiers créés par un processus / dans un dossier
```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 ComputerName="<HOTE>"
  (Image="*<PROCESSUS>*" OR TargetFilename="<DOSSIER>*")
| table _time Image TargetFilename
```

### P-FILE-02 – Accès aux partages SMB (dépôt d'outils, exfiltration)
```spl
index=main source="WinEventLog:Security" EventCode IN (5140,5145) Source_Address="<IP>"
| stats count values(Relative_Target_Name) as fichiers by ComputerName Share_Name Account_Name
```

---

## 4. Réseau

### P-NET-01 – Connexions d'un hôte (Suricata)
```spl
index=main sourcetype=suricata (src_ip="<IP>" OR dest_ip="<IP>") event_type IN (flow,alert,dns,tls,http)
| stats count sum(bytes_toserver) as out sum(bytes_toclient) as in values(dest_port) as ports values(alert.signature) as alertes by src_ip dest_ip
```

### P-NET-02 – Connexions réseau d'un processus (Sysmon 3)
```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 ComputerName="<HOTE>"
| stats count values(DestinationPort) as ports by Image DestinationIp DestinationHostname
```

### P-NET-03 – Résolutions DNS (Sysmon 22)
```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=22 QueryName="*<DOMAINE>*"
| stats count values(Image) as processus by ComputerName QueryName QueryResults
```

---

## 5. Linux (Kunai)

### P-LIN-01 – Commandes exécutées sur un serveur
```spl
index=main sourcetype=kunai "info.event.name"=execve "info.host.name"="<HOTE>"
| table _time info.task.uid data.ancestors data.command_line
```

### P-LIN-02 – Connexions réseau d'un serveur
```spl
index=main sourcetype=kunai "info.event.name"=connect "info.host.name"="<HOTE>"
| stats count by data.exe.path data.dst.ip data.dst.port
```
Les noms de champs Kunai sont à confirmer sur le lab.

---

## 6. Vue d'ensemble

### P-ALL-01 – Chronologie complète d'une IP sur toutes les sources
```spl
index=main "<IP>"
| eval resume=coalesce(CommandLine, Service_Name, TargetObject, 'alert.signature', Message)
| table _time host source EventCode resume
| sort _time
```

### P-ALL-02 – Alertes déjà levées sur un hôte (historique Splunk)
```spl
index=_audit action=alert_fired ss_name="[BUILD]*"
| table _time ss_name trigger_time result_count
```
