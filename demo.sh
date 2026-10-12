#!/usr/bin/env bash

# Couleurs
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

log_section() {
    echo -e "\n${BLUE}=== $1 ===${NC}\n"
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_err() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Charger l'environnement virtuel si présent
if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
fi

# Nettoyage à la fin du script
API_PID=""
cleanup() {
    if [ -n "$API_PID" ]; then
        log_info "Arrêt du serveur API (PID: $API_PID)..."
        kill "$API_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

log_section "1. Diagnostic du système"
python3 -m hardener doctor

log_section "2. Audit complet"
python3 -m hardener audit --json report.json --html report.html --sarif report.sarif
log_info "Rapports générés : report.json, report.html, report.sarif"

log_section "3. Security Gate (Test d'échec)"
python3 -m hardener audit --fail-on high || log_warn "Security Gate : failles détectées (code retour $?)."

log_section "4. Baseline et Drift"
python3 -m hardener baseline --output baseline.json
log_info "Baseline sauvegardée dans baseline.json"
python3 -m hardener drift baseline.json

log_section "5. Simulation de remédiation (Dry-run)"
python3 -m hardener remediate --dry-run || log_warn "Remédiation exécutée en mode dry-run."

log_section "6. Lancement de l'API et de l'Agent"
python3 -m hardener api > api.log 2>&1 &
API_PID=$!
log_info "API démarrée (PID: $API_PID) sur http://127.0.0.1:8000"
sleep 2

python3 -m hardener agent --once --server http://127.0.0.1:8000/api/scans
log_info "Agent exécuté et rapport envoyé à l'API."

log_section "7. Tests unitaires & Qualité code"
pytest -q

log_section "8. Audit avec politique spécifique"
python3 -m hardener audit --policy .policies/server.yml

log_section "9. Test du laboratoire Docker (Optionnel)"
if command -v docker &> /dev/null; then
    docker build -t linux-hardener-lab docker-lab -q
    log_info "Image Docker lab construite avec succès."
fi

log_section "Démonstration terminée"
