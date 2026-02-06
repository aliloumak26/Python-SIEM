# 🛡️ SIEM Professionnel

**Security Information and Event Management** - Système de détection et d'analyse d'attaques en temps réel avec Machine Learning et Honeypots intégrés.

## ✨ Fonctionnalités

### 🤖 Machine Learning
- Détection d'anomalies avec **Isolation Forest**
- Feature extraction sophistiquée (entropie, patterns, caractères spéciaux)
- Scoring de confiance pour chaque alerte

### 🍯 Honeypots Intégrés
- **SSH Honeypot** (port 2222) - Capture les tentatives de connexion
- **HTTP Honeypot** (port 8888) - Simule des endpoints vulnérables
- Logging automatique dans la base de données

### 🖥️ Interface GUI (PySide6) - **RECOMMANDÉ**
- **Dashboard temps réel** avec thème sombre premium
- **Scroll complet** de la page pour une vue d'ensemble
- **Cartes statistiques** dynamiques (SQLi, XSS, ML Anomaly, etc.)
- **Auto-scroll** intelligent des logs et alertes
- **Filtrage interactif** immédiat

### 🔍 Détecteurs
- **SQL Injection** - 50+ patterns
- **XSS** - Détection de scripts malveillants
- **Brute Force** - Analyse de fréquence
- **ML Anomaly** - Détection comportementale

### 💾 Persistance
- Base de données **SQLite**
- Géolocalisation IP automatique
- Statistiques agrégées
- Export CSV/JSON

## 📦 Installation

```bash
# Cloner le projet
cd SIEM

# Installer les dépendances
pip install -r requirements.txt

# Entraîner le modèle ML (première fois)
python ml/train.py
```

## 🚀 Lancement

### Version Desktop (PySide6) - Recommandé
```bash
python dashboard_gui.py
```

### Version Web (Legacy)
```bash
python main.py
```
Le système démarrera alors le dashboard web (http://localhost:8000).

## 🧪 Test

### Générer des attaques simulées
```bash
# Terminal séparé
python attacks_generator.py
```

### Tester le honeypot SSH
```bash
ssh root@localhost -p 2222
```

### Tester le honeypot HTTP
```bash
curl http://localhost:8888
```

## 📊 Endpoints API

- `GET /` - Dashboard web
- `GET /api/stats` - Statistiques globales
- `GET /api/alerts?limit=100` - Alertes récentes
- `GET /api/honeypot` - Logs honeypot
- `GET /api/export/alerts?format=json` - Export
- `WS /ws` - WebSocket temps réel

## 🗂️ Structure du Projet

```
SIEM/
├── api/                    # API FastAPI
│   └── main.py
├── core/                   # Moteur central
│   ├── database.py         # SQLite
│   ├── engine.py           # Orchestration
│   └── alert_manager.py    # Gestion alertes
├── detectors/              # Détecteurs d'attaques
│   ├── sqli.py
│   ├── xss.py
│   └── bruteforce.py
├── ml/                     # Machine Learning
│   ├── anomaly_detector.py
│   └── train.py
├── honeypot/              # Honeypots
│   └── ssh_honeypot.py
├── web/                   # Interface web
│   ├── index.html
│   └── assets/
│       ├── css/style.css
│       └── js/app.js
├── utils/                 # Utilitaires
│   ├── geoip.py
│   └── normalize.py
├── config/
│   └── settings.py
├── dashboard_gui.py       # Interface principale PySide6
├── main.py                # Lanceur version Web (Legacy)
└── requirements.txt
```

## 🎯 Améliorations Futures

- [ ] Classification ML multi-classe
- [ ] Notifications email/webhook
- [ ] Règles personnalisées (YAML)
- [ ] Export PDF avec graphiques
- [ ] Authentification JWT
- [ ] Dashboard admin

## ⚠️ Avertissement

**Projet éducatif uniquement.**
- Ne pas utiliser sur des systèmes/réseaux sans autorisation
- Les honeypots doivent être déployés dans un environnement contrôlé
- Ne collecte que des métadonnées (IP, timestamp, patterns)



