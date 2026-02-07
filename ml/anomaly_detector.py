import os
import re
import pickle
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from typing import Tuple, List

class AnomalyDetector:
    """
    Détecteur d'anomalies basé sur Isolation Forest avec normalisation des caractéristiques
    Analyse les caractéristiques des requêtes HTTP pour détecter des comportements suspects
    """
    
    def __init__(self, model_path: str = None, scaler_path: str = None):
        if model_path is None:
            model_path = os.path.join(os.path.dirname(__file__), 'anomaly_model.pkl')
        if scaler_path is None:
            scaler_path = os.path.join(os.path.dirname(__file__), 'scaler.pkl')
        
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.model = None
        self.scaler = None
        self.is_trained = False
        
        # Charger le modèle et le scaler si ils existent
        if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
            self.load_model()
    
    def extract_features(self, log_line: str) -> np.ndarray:
        """
        Extrait les features d'une ligne de log
        Retourne un vecteur de caractéristiques
        """
        # Imports dynamiques pour éviter les dépendances circulaires
        from detectors import sqli, xss, os_injection, traversal, nosql
        
        features = []
        line_lower = log_line.lower()
        
        # 1. Longueur de la ligne
        features.append(len(log_line))
        
        # 2. Longueur de l'URL
        url_match = re.search(r'\s(?:GET|POST|PUT|DELETE|PATCH)\s+([^\s?]+)', log_line)
        url = url_match.group(1) if url_match else ""
        features.append(len(url))
        
        # 3. Nombre de paramètres (URL + Body)
        param_count = log_line.count('=') + log_line.count('&')
        features.append(param_count)
        
        # 4. Nombre de caractères spéciaux suspects (FILTRÉ pour le JSON normal)
        # On ignore {, }, ", :, , pour ne pas pénaliser le JSON normal
        special_chars = ['<', '>', "'", ';', '(', ')', '[', ']', '*', '|', '$', '`', '\\', '&', '!', '%']
        special_count = sum(log_line.count(char) for char in special_chars)
        features.append(special_count * 6) 
        
        # 5. Mots-clés SQL suspects (Index 4)
        sql_count = sum(1 for p in sqli.PATTERNS if re.search(p, line_lower))
        features.append(sql_count * 8)
        
        # 6. Mots-clés XSS / HTML (Index 5)
        xss_count = sum(1 for p in xss.PATTERNS if re.search(p, line_lower))
        features.append(xss_count * 8)
        
        # 7. Mots-clés Path Traversal / Sensitive Files (Index 6)
        traversal_count = sum(1 for p in traversal.PATTERNS if re.search(p, line_lower))
        features.append(traversal_count * 6)
        
        # 8. Mots-clés RCE / Shell (Index 7)
        shell_count = sum(1 for p in os_injection.PATTERNS if re.search(p, line_lower))
        features.append(shell_count * 12) 

        # 9. NoSQL Injection Patterns (MongoDB style) (Index 8)
        nosql_count = sum(1 for p in nosql.PATTERNS if re.search(p, line_lower))
        features.append(nosql_count * 8)
        
        # 10. Entropie (complexité de la chaîne) (Index 9)
        features.append(self._calculate_entropy(log_line) * 25)
        
        # 11. Ratio de caractères non-ASCII / Encoding (Index 10)
        non_ascii = sum(1 for c in log_line if ord(c) > 127)
        hex_encoding = len(re.findall(r'%[0-9a-fA-F]{2}', log_line))
        non_ascii_ratio = (non_ascii + (hex_encoding * 4)) / max(len(log_line), 1)
        features.append(non_ascii_ratio * 150) # Index 10 (v100 -> v150)
        
        # 12. Densité de chiffres (Index 11)
        digit_count = sum(c.isdigit() for c in log_line)
        digit_ratio = digit_count / max(len(log_line), 1)
        features.append(digit_ratio * 100)

        # 13. Caractères bizarres (Index 12)
        weird_chars = len(re.findall(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', log_line))
        features.append(weird_chars * 20) # v15 -> v20
        
        return np.array(features).reshape(1, -1)
    
    def _calculate_entropy(self, text: str) -> float:
        """Calcule l'entropie de Shannon d'une chaîne"""
        if not text:
            return 0.0
        
        from collections import Counter
        counts = Counter(text)
        total = len(text)
        
        entropy = 0.0
        for count in counts.values():
            p = count / total
            if p > 0:
                entropy -= p * np.log2(p)
        
        return entropy
    
    def train(self, normal_logs: list, contamination: float = 0.01):
        """
        Entraîne le modèle sur des logs normaux
        """
        # print("[ML] Préparation des données d'entraînement...")
        
        X = []
        for log in normal_logs:
            features = self.extract_features(log)
            X.append(features[0])
        
        X = np.array(X)
        
        # Initialiser et entraîner le scaler
        # print("[ML] Normalisation des caractéristiques...")
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        
        # Créer et entraîner le modèle
        # print("[ML] Entraînement de IsolationForest...")
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=300,
            max_samples='auto'
        )
        
        self.model.fit(X_scaled)
        self.is_trained = True
        
        # print(f"[ML] ✓ Modèle entraîné sur {len(X)} exemples")
    
    def predict(self, log_line: str) -> Tuple[bool, float]:
        """
        Prédit si une ligne de log est une anomalie
        Retourne: (is_anomaly, anomaly_score)
        """
        if not self.is_trained or self.model is None or self.scaler is None:
            return False, 0.0
        
        try:
            features = self.extract_features(log_line)
            features_scaled = self.scaler.transform(features)
            
            # Prediction (-1 = anomalie, 1 = normal)
            prediction = self.model.predict(features_scaled)[0]
            
            # decision_function: > 0 normal, < 0 anomalie
            decision_func = self.model.decision_function(features_scaled)[0]
            
            # Calibration ÉQUILIBRÉE pour le SIEM
            # decision_function: > 0 normal, < 0 anomalie
            # On utilise une sigmoïde centrée sur 0.0 (seuil naturel de Isolation Forest)
            # Une pente de 10 donne un score de ~0.3 pour DF=0.1 et ~0.7 pour DF=-0.1
            score = 1.0 / (1.0 + np.exp(decision_func * 10))
            
            # On vérifie si un pattern critique a été détecté (indices 4, 5, 6, 7, 8 dans extract_features)
            # 4: SQL, 5: XSS/HTML, 6: Traversal, 7: RCE, 8: NoSQL
            pattern_detected = any(features[0][i] > 0 for i in [4, 5, 6, 7, 8])
            
            if pattern_detected:
                # Si on détecte un pattern connu, on booste le score au dessus du seuil (0.6)
                score = max(score, 0.75)
                is_anomaly = True
            else:
                # Sinon on se fie au modèle Isolation Forest
                is_anomaly = prediction == -1 or score > 0.6
            
            return is_anomaly, score
        except Exception as e:
            # print(f"[ML] Erreur prédiction: {e}")
            return False, 0.0
    
    def save_model(self):
        """Sauvegarde le modèle et le scaler"""
        if self.model is None or self.scaler is None:
            # print("[ML] Aucun modèle/scaler à sauvegarder")
            return
        
        try:
            with open(self.model_path, 'wb') as f:
                pickle.dump(self.model, f)
            with open(self.scaler_path, 'wb') as f:
                pickle.dump(self.scaler, f)
            
            # print(f"[ML] + Modèle sauvegardé: {self.model_path}")
            # print(f"[ML] + Scaler sauvegardé: {self.scaler_path}")
        except Exception as e:
            # print(f"[ML] Erreur sauvegarde: {e}")
            pass

    def load_model(self):
        """Charge un modèle et un scaler existants"""
        try:
            if os.path.exists(self.model_path):
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
            
            if os.path.exists(self.scaler_path):
                with open(self.scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
            
            if self.model is not None and self.scaler is not None:
                self.is_trained = True
                # print(f"[ML] + Modèle et Scaler chargés")
            else:
                self.is_trained = False
        
        except Exception as e:
            # print(f"[ML] Erreur chargement: {e}")
            self.model = None
            self.scaler = None
            self.is_trained = False


def detect(line: str, detector: AnomalyDetector = None) -> Tuple[bool, str, str]:
    """
    Fonction de détection compatible avec le système SIEM
    """
    if detector is None:
        if not hasattr(detect, 'global_detector'):
            detect.global_detector = AnomalyDetector()
        detector = detect.global_detector
    
    if not detector.is_trained:
        return False, None, None
    
    is_anomaly, score = detector.predict(line)
    
    # On baisse légèrement le seuil de confiance car le score est mieux calibré
    if is_anomaly or score > 0.7:
        pattern = f"ml_conf_{score:.2f}"
        return True, pattern, "ML Anomaly"
    
    return False, None, None
