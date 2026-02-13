Log-urile din GAIA pe Check Point Firewall arată scanările de rețea prin intrări multiple de tip "drop" pentru conexiuni SYN pe porturi diferite de la aceeași sursă IP, în special în fișierele /var/log/messages sau fw.log. Acestea indică trafic suspect blocat de policy, fără un eveniment dedicat "port scan" în logurile standard, dar detectabil prin agregare în SmartEvent sau SmartLog. [dkcheckpoint.blogspot](http://dkcheckpoint.blogspot.com/2016/07/)

#### Tipuri de Loguri Relevante

- **Fw.log și syslog**: Intrări precum "drop <src_ip> proto: tcp service: <port> s_port: <ephem_port>" repetate pentru porturi secvențiale (ex: 22, 23, 80, 443) indică scan SYN stealth. [ossec](https://www.ossec.net/docs/log_samples/firewalls/checkpoint.html)
- **Audit logs**: /var/log/audit sau messages pentru modificări config, nu direct pentru trafic. [docs.nextgensoftware](https://docs.nextgensoftware.eu/220/site/Data%20Sources/Guides/How%20to%20configure%20Firewall%20CheckPoint%20to%20send%20logs%20to%20CQ%20Server%20IP%20Address%20on%20port%205140%20UDP/)

#### Exemplu Log Scan Porturi
```
Sep 3 15:12:20 192.168.99.1 Checkpoint: drop 192.168.11.7 proto: tcp; service: 22; s_port: 1352
Sep 3 15:12:21 192.168.99.1 Checkpoint: drop 192.168.11.7 proto: tcp; service: 23; s_port: 1353
Sep 3 15:12:22 192.168.99.1 Checkpoint: drop 192.168.11.7 proto: tcp; service: 80; s_port: 1354
```
Acest pattern arată scan de la un singur IP pe porturi comune; vizualizat cu `fw log` sau `tail -f /var/log/messages | grep drop`.  [ossec](https://www.ossec.net/docs/log_samples/firewalls/checkpoint.html)

#### Configurare
- Comenzi GAIA: `show syslog all`, `fw log -n` pentru live logs, `fw log | grep drop`.  [docs.nextgensoftware](https://docs.nextgensoftware.eu/220/site/Data%20Sources/Guides/How%20to%20configure%20Firewall%20CheckPoint%20to%20send%20logs%20to%20CQ%20Server%20IP%20Address%20on%20port%205140%20UDP/)
- Activează logging în policy rules pe "Drop" cu track "Log". Scanurile apar ca trafic respins pe interfața externă. [sc1.checkpoint](https://sc1.checkpoint.com/documents/R80.40/WebAdminGuides/EN/CP_R80.40_LoggingAndMonitoring_AdminGuide/Topics-LMG/Log_Actions.htm)

