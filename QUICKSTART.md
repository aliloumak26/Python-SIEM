# Guide de Démarrage Rapide - SIEM

## 🚀 Lancement du SIEM

### 1. Première Installation (une seule fois)
```powershell
# Installer les dépendances
pip install fastapi uvicorn websockets scikit-learn pandas numpy paramiko requests pyyaml

# Entraîner le modèle ML
python ml/train.py
```

### 2. Démarrer le Dashboard (GUI)
```powershell
# Lance l'interface principale PySide6
python dashboard_gui.py
```

L'interface s'ouvre dans une fenêtre dédiée avec tous les outils intégrés.

---

## ⚔️ Générer des Attaques pour Tester

### Dans un NOUVEAU terminal PowerShell :

```powershell
cd C:\Users\Pc\Documents\Python-SIEM
python attacks_generator.py
```

Ce script génère continuellement des logs d'attaques (SQL Injection, XSS) dans `logs/access.log`.

**Vous verrez dans le dashboard** :
- 🚨 Nouvelles alertes apparaître en temps réel
- 📊 Graphiques se mettre à jour
- 🗺️ Carte du monde avec géolocalisation des IPs
- 📈 Statistiques s'incrémenter

---

## 🧪 Autres Tests

### Tester le Honeypot SSH
```powershell
ssh root@localhost -p 2222
```

### Tester le Honeypot HTTP
```powershell
curl http://localhost:8888
```

Ou visitez http://localhost:8888 dans votre navigateur.

---

## ⚠️ Important : Le CSS ne s'affiche pas ?

**Problème** : Si vous ouvrez directement `web/index.html` dans votre navigateur (double-clic), le CSS ne chargera pas.

**Solution** : Vous DEVEZ lancer le serveur avec `python main.py` et accéder via :
- ✅ **http://localhost:8000** (correct)
- ❌ ~~file:///C:/Users/.../web/index.html~~ (incorrect)

Le serveur FastAPI sert les fichiers statiques correctement.

---

## 📊 Endpoints Disponibles

Une fois le serveur lancé :

- Dashboard : http://localhost:8000
- API Stats : http://localhost:8000/api/stats
- API Alertes : http://localhost:8000/api/alerts
- Export CSV : http://localhost:8000/api/export/alerts?format=csv

---

## 🛑 Arrêter le SIEM

Appuyez sur **Ctrl+C** dans le terminal où tourne `main.py`
