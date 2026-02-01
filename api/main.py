"""
API FastAPI pour le SIEM
Fournit des endpoints REST et WebSocket pour l'interface web
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import json
import asyncio
from typing import List
from datetime import datetime
import os
import sys

# Ajouter le répertoire parent au path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Database removed
from core.engine import SIEMEngine

app = FastAPI(title="SIEM API", version="1.0.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Engine pour l'accès aux données
engine = SIEMEngine()

# WebSocket clients connectés
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
    
    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
    
    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                pass

manager = ConnectionManager()

# Servir les fichiers statiques
web_dir = os.path.join(os.path.dirname(__file__), '..', 'web')
if os.path.exists(web_dir):
    app.mount("/assets", StaticFiles(directory=os.path.join(web_dir, 'assets')), name="assets")

# ==================== ROUTES ====================

@app.get("/")
async def root():
    """Sert la page principale"""
    html_path = os.path.join(web_dir, 'index.html')
    if os.path.exists(html_path):
        with open(html_path, 'r', encoding='utf-8') as f:
            return HTMLResponse(content=f.read())
    return {"message": "SIEM API Running"}

@app.get("/api/alerts")
async def get_alerts(limit: int = 100, type: str = None):
    """Récupère les alertes récentes"""
    alerts = engine.get_recent_alerts(limit=limit)
    # Filtrage par type si demandé (fait en mémoire ici car pas de SQL)
    if type:
        alerts = [a for a in alerts if a.get('attack_type') == type]
    return {"alerts": alerts, "count": len(alerts)}

@app.get("/api/stats")
async def get_stats():
    """Récupère les statistiques"""
    return engine.get_statistics() # Retourne déjà le format attendu

@app.get("/api/honeypot")
async def get_honeypot_logs(limit: int = 100, service: str = None):
    """Récupère les logs honeypot"""
    logs = engine.get_honeypot_logs(limit=limit)
    if service:
        logs = [l for l in logs if l.get('service') == service]
    return {"logs": logs, "count": len(logs)}

@app.get("/api/export/alerts")
async def export_alerts(format: str = "json"):
    """Exporte les alertes (JSON ou CSV)"""
    alerts = engine.get_recent_alerts(limit=1000)
    
    if format == "csv":
        import csv
        from io import StringIO
        
        output = StringIO()
        # Flat dictionary for CSV
        writer = csv.DictWriter(output, fieldnames=alerts[0].keys() if alerts else [])
        writer.writeheader()
        writer.writerows(alerts)
        
        from fastapi.responses import StreamingResponse
        output.seek(0)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=alerts.csv"}
        )
    
    return {"alerts": alerts}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket pour les mises à jour temps réel"""
    await manager.connect(websocket)
    
    try:
        while True:
            # Garder la connexion ouverte
            await websocket.receive_text()
    
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Fonction pour broadcaster les nouvelles alertes
async def broadcast_alert(alert: dict):
    """Diffuse une nouvelle alerte via WebSocket"""
    await manager.broadcast({
        "type": "new_alert",
        "data": alert
    })

async def broadcast_stats(stats: dict):
    """Diffuse des stats mises à jour via WebSocket"""
    await manager.broadcast({
        "type": "stats_update",
        "data": stats
    })

# ==================== LIFECYCLE ====================

@app.on_event("startup")
async def startup_event():
    """Démarrage de l'API"""
    print("[API] ✓ FastAPI démarrée (Mode Fichier)")

@app.on_event("shutdown")
async def shutdown_event():
    """Arrêt de l'API"""
    print("[API] ✓ FastAPI arrêtée")
