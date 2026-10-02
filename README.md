# Linux Hardener 0.6

Petit projet DevSecOps de hardening et de compliance Linux. Il est volontairement écrit avec des fonctions simples pour rester lisible quand on débute en Python.

## Ce que contient cette version

### V3 - Security engine
- 28 contrôles intégrés : SSH, filesystem, kernel/sysctl, firewall, services, logging, MAC, network, packages, comptes et sudo.
- policies YAML (`server.yml`, `workstation.yml`).
- score de conformité.
- audit en terminal, JSON, HTML et SARIF.
- baseline et détection de drift.

### V4 - CI/CD et laboratoire
- GitHub Actions pour les tests et le security gate.
- image Docker de laboratoire volontairement faible pour tester la détection.
- script de démonstration.

### V5 - API et agent
- API FastAPI.
- SQLite pour l'historique des scans.
- dashboard HTML minimal.
- agent périodique qui peut poster les rapports vers l'API.

### V6 - plugins
- dossier `hardener/plugins/` avec un exemple Docker.
- architecture simple basée sur `register()`.

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

## Premier lancement

```bash
python -m hardener doctor
python -m hardener audit
```

### Rapports

```bash
python -m hardener audit --json report.json --html report.html --sarif report.sarif
```

### Security gate

```bash
python -m hardener audit --fail-on high
```

Le code de sortie est 2 si un contrôle `FAIL` atteint le niveau demandé.

### Baseline / drift

```bash
python -m hardener baseline --output baseline.json
python -m hardener drift baseline.json
```

### Remédiation

Toujours commencer par :

```bash
sudo python -m hardener remediate --dry-run
```

Puis sur une VM de test :

```bash
sudo python -m hardener remediate
sudo python -m hardener audit
```

Les contrôles SSH et sysctl sont remédiables. Le firewall et les mises à jour de paquets sont volontairement en audit uniquement pour éviter les changements surprise.

### Rollback

```bash
sudo python -m hardener list-runs
sudo python -m hardener rollback <RUN_ID>
```

### API / dashboard

```bash
linux-hardener-api
```

Puis ouvrir `http://127.0.0.1:8000`.

### Agent

Un scan unique :

```bash
linux-hardener-agent --once
```

Avec envoi vers l'API :

```bash
linux-hardener-agent --once --server http://127.0.0.1:8000/api/scans
```

En boucle, toutes les 15 minutes :

```bash
linux-hardener-agent --interval 900 --server http://127.0.0.1:8000/api/scans
```

## Docker lab

Le Dockerfile crée une image Debian avec une configuration SSH volontairement faible. C'est un laboratoire de démonstration, pas une image à déployer.

```bash
docker build -t linux-hardener-lab docker-lab
docker run --rm linux-hardener-lab
```

Pour un test de remédiation complet, utiliser une VM Linux de test plutôt qu'un conteneur : systemd, SSH et sysctl sont différents dans un conteneur.

## Tests

```bash
pytest
```

## Structure

```text
hardener/
├── api.py
├── agent.py
├── baseline.py
├── cli.py
├── db.py
├── engine.py
├── models.py
├── policy.py
├── registry.py
├── remediation.py
├── reporters.py
├── checks/
├── plugins/
└── static/
```

## Idées pour la suite

- authentification API et RBAC ;
- PostgreSQL pour plusieurs hôtes ;
- file d'agents ;
- signature des rapports ;
- CVE mapping avec une source externe ;
- vrai service systemd pour l'agent ;
- meilleur dashboard avec historique par machine ;
- tests d'intégration sur VMs Debian/Ubuntu.
