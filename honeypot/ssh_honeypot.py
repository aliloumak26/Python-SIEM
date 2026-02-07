"""
Honeypot SSH simulé
Capture les tentatives de connexion SSH et les commandes
"""

import socket
import threading
import time
from datetime import datetime
from core.database import Database
from utils.geoip import GeoIPLocator
from utils.chiffrer import chiffrer_donnees

class SSHHoneypot:
    """Honeypot SSH basique (simulation)"""
    
    def __init__(self, host: str = '0.0.0.0', port: int = 2222):
        self.host = host
        self.port = port
        self.running = False
        self.server_thread = None
        self.db = Database()
        self.geoip = GeoIPLocator()
    
    def start(self):
        """Démarre le honeypot"""
        if self.running:
            # print(f"[Honeypot SSH] Déjà en cours sur {self.host}:{self.port}")
            return
        
        self.running = True
        self.server_thread = threading.Thread(target=self._run_server, daemon=True)
        self.server_thread.start()
        # print(f"[Honeypot SSH] ✓ Démarré sur {self.host}:{self.port}")
    
    def stop(self):
        """Arrête le honeypot"""
        self.running = False
        # print("[Honeypot SSH] ✓ Arrêté")
    
    def _run_server(self):
        """Exécute le serveur honeypot"""
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.host, self.port))
            server.listen(5)
            server.settimeout(1.0)  # Timeout pour permettre l'arrêt
            
            while self.running:
                try:
                    client, addr = server.accept()
                    threading.Thread(
                        target=self._handle_client,
                        args=(client, addr),
                        daemon=True
                    ).start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        # print(f"[Honeypot SSH] Erreur accept: {e}")
        
        except Exception as e:
            # print(f"[Honeypot SSH] Erreur serveur: {e}")
        finally:
            try:
                server.close()
            except:
                pass
    
    def _handle_client(self, client: socket.socket, addr: tuple):
        """Gère une connexion client"""
        ip, port = addr
        
        try:
            # Envoyer un faux banner SSH
            banner = b"SSH-2.0-OpenSSH_7.4\r\n"
            client.send(banner)
            
            # Log de la tentative de connexion
            geo_data = self.geoip.locate(ip)
            
            self.db.insert_honeypot_log(
                service='SSH',
                source_ip=ip,
                source_port=port,
                geo_data=geo_data
            )
            
            # print(f"[Honeypot SSH] ⚠️ Connexion depuis {ip}:{port} ({geo_data.get('country', 'Unknown')})")
            
            # Log chiffré
            try:
                chiffrer_donnees(f"SSH Honeypot: Connection from {ip}:{port}")
            except: pass
            
            # Simuler une négociation puis fermer
            time.sleep(0.5)
            
            # Essayer de capturer des données (tentative de login)
            client.settimeout(2.0)
            try:
                data = client.recv(1024)
                if data:
                    # Logger les données (potentiellement username/password)
                    # print(f"[Honeypot SSH] Données reçues de {ip}: {len(data)} bytes")
            except socket.timeout:
                pass
        
        except Exception as e:
            # print(f"[Honeypot SSH] Erreur client {ip}: {e}")
        
        finally:
            client.close()


class HTTPHoneypot:
    """Honeypot HTTP avec faux endpoints vulnérables"""
    
    def __init__(self, host: str = '0.0.0.0', port: int = 8888):
        self.host = host
        self.port = port
        self.running = False
        self.server_thread = None
        self.db = Database()
        self.geoip = GeoIPLocator()
    
    def start(self):
        """Démarre le honeypot"""
        if self.running:
            # print(f"[Honeypot HTTP] Déjà en cours sur {self.host}:{self.port}")
            return
        
        self.running = True
        self.server_thread = threading.Thread(target=self._run_server, daemon=True)
        self.server_thread.start()
        # print(f"[Honeypot HTTP] ✓ Démarré sur {self.host}:{self.port}")
    
    def stop(self):
        """Arrête le honeypot"""
        self.running = False
        # print("[Honeypot HTTP] ✓ Arrêté")
    
    def _run_server(self):
        """Exécute le serveur HTTP basique"""
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.host, self.port))
            server.listen(5)
            server.settimeout(1.0)
            
            while self.running:
                try:
                    client, addr = server.accept()
                    threading.Thread(
                        target=self._handle_client,
                        args=(client, addr),
                        daemon=True
                    ).start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        # print(f"[Honeypot HTTP] Erreur accept: {e}")
        
        except Exception as e:
            # print(f"[Honeypot HTTP] Erreur serveur: {e}")
        finally:
            try:
                server.close()
            except:
                pass
    
    def _handle_client(self, client: socket.socket, addr: tuple):
        """Gère une requête HTTP"""
        ip, port = addr
        
        try:
            client.settimeout(5.0)
            request = client.recv(4096).decode('utf-8', errors='ignore')
            
            if not request:
                return
            
            # Parser la requête
            lines = request.split('\r\n')
            if len(lines) > 0:
                request_line = lines[0]
                
                # Log
                geo_data = self.geoip.locate(ip)
                
                self.db.insert_honeypot_log(
                    service='HTTP',
                    source_ip=ip,
                    source_port=port,
                    command=request_line,
                    geo_data=geo_data
                )
                
                # print(f"[Honeypot HTTP] ⚠️ {ip} - {request_line}")
                
                # Log chiffré
                try:
                    chiffrer_donnees(f"HTTP Honeypot: {ip} - {request_line}")
                except: pass
                
                # Réponse HTML basique (page de login piège)
                response = self._generate_response(request_line)
                client.send(response.encode())
        
        except Exception as e:
            # print(f"[Honeypot HTTP] Erreur client {ip}: {e}")
        
        finally:
            client.close()
    
    def _generate_response(self, request_line: str) -> str:
        """Génère une réponse HTTP"""
        html = """<!DOCTYPE html>
<html>
<head><title>Admin Login</title></head>
<body style="font-family: Arial; padding: 50px;">
<h2>🔐 Administrator Login</h2>
<form method="POST" action="/login">
<input type="text" name="username" placeholder="Username" style="padding: 10px; margin: 5px;"><br>
<input type="password" name="password" placeholder="Password" style="padding: 10px; margin: 5px;"><br>
<button type="submit" style="padding: 10px 20px; margin: 5px;">Login</button>
</form>
</body>
</html>"""
        
        response = f"""HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: {len(html)}
Connection: close

{html}"""
        
        return response
