# 404SECURITY

Suite de cyber-défense modulaire pour serveurs Linux.
Mainteneur : 404sec — https://github.com/uncensored404/404security

## Modules
- **404-SENTINEL** : HIDS — intégrité de fichiers, processus suspects
- **404-LOGFIRE** : mini-SIEM — ingestion et corrélation d'événements
- **404-NETWATCH** : IDS réseau — SYN flood, scans de ports
- **404-HONEYPOT** : leurres SSH et HTTP
- **404-SHIELD** : audit de durcissement type CIS + remèdes
- **404-VULNSCAN** : inventaire des services exposés, correspondance CVE
- **404-RESPONDER** : SOAR — scoring d'IP, blocage nftables, notifications
- **404-DASHBOARD** : console web temps réel (FastAPI + WebSocket)

## Installation
    git clone https://github.com/uncensored404/404security.git
    cd 404security
    python3 -m venv .venv && . .venv/bin/activate
    pip install -r requirements.txt
    sudo python3 main.py

Premier lancement : Sentinel construit sa baseline d'intégrité.
Alertes dans `data/events.db`, console sur https://<ip>:8443.
Certificat auto-signé à régénérer localement :
    openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
      -keyout certs/server.pem -out certs/server.pem -subj "/CN=404security"

## Tests
    python -m pytest tests/ -v

## Licence
GPL-3.0
