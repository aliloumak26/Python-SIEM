import os
import re
import pickle
import numpy as np
from sklearn.ensemble import IsolationForest
from typing import Tuple

class AnomalyDetector:
    """
    Détecteur d'anomalies basé sur Isolation Forest
    Analyse les caractéristiques des requêtes HTTP pour détecter des comportements suspects
    """
    
    def __init__(self, model_path: str = None):
        if model_path is None:
            model_path = os.path.join(os.path.dirname(__file__), 'anomaly_model.pkl')
        
        self.model_path = model_path
        self.model = None
        self.is_trained = False
        
        # Charger le modèle si il existe
        if os.path.exists(self.model_path):
            self.load_model()
    
    def extract_features(self, log_line: str) -> np.ndarray:
        """
        Extrait les features d'une ligne de log
        Retourne un vecteur de caractéristiques
        """
        features = []
        
        # 1. Longueur de la ligne
        features.append(len(log_line))
        
        # 2. Longueur de l'URL
        url_match = re.search(r'"(?:GET|POST|PUT|DELETE|PATCH)\s+([^\s]+)', log_line)
        url_length = len(url_match.group(1)) if url_match else 0
        features.append(url_length)
        
        # 3. Nombre de paramètres
        param_count = log_line.count('=')
        features.append(param_count)
        
        # 4. Nombre de caractères spéciaux suspects
        special_chars = ['<', '>', '"', "'", ';', '(', ')', '{', '}', '[', ']']
        special_count = sum(log_line.count(char) for char in special_chars)
        features.append(special_count)
        
        # 5. Nombre de mots-clés SQL
        sql_keywords = ['select', 'union', 'insert', 'delete', 'drop', 'update', 'exec']
        sql_count = sum(keyword in log_line.lower() for keyword in sql_keywords)
        features.append(sql_count)
        
        # 6. Nombre de balises HTML/JS
        html_tags = ['<script', '<img', '<iframe', '<svg', 'javascript:', 'onerror']
        html_count = sum(tag in log_line.lower() for tag in html_tags)
        features.append(html_count)
        
        # 7. Entropie (complexité de la chaîne)
        entropy = self._calculate_entropy(log_line)
        features.append(entropy)
        
        # 8. Ratio de caractères non-ASCII
        non_ascii = sum(1 for c in log_line if ord(c) > 127)
        non_ascii_ratio = non_ascii / max(len(log_line), 1)
        features.append(non_ascii_ratio)
        
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
    
    def train(self, normal_logs: list, contamination: float = 0.1):
        """
        Entraîne le modèle sur des logs normaux
        contamination: pourcentage estimé d'anomalies dans les données (0.1 = 10%)
        """
        print("[ML] Entraînement du modèle d'anomalie...")
        
        # Extraire les features
        X = []
        for log in normal_logs:
            features = self.extract_features(log)
            X.append(features[0])
        
        X = np.array(X)
        
        # Créer et entraîner le modèle
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100
        )
        
        self.model.fit(X)
        self.is_trained = True
        
        print(f"[ML] ✓ Modèle entraîné sur {len(X)} exemples")
    
    def predict(self, log_line: str) -> Tuple[bool, float]:
        """
        Prédit si une ligne de log est une anomalie
        Retourne: (is_anomaly, anomaly_score)
        """
        if not self.is_trained:
            return False, 0.0
        
        features = self.extract_features(log_line)
        
        # Prédiction (-1 = anomalie, 1 = normal)
        prediction = self.model.predict(features)[0]
        
        # Score d'anomalie (plus négatif = plus anormal)
        score = self.model.score_samples(features)[0]
        
        # Normaliser le score entre 0 et 1
        normalized_score = 1 / (1 + np.exp(score))  # Sigmoïde
        
        is_anomaly = prediction == -1
        
        return is_anomaly, normalized_score
    
    def save_model(self):
        """Sauvegarde le modèle entraîné"""
        if self.model is None:
            print("[ML] Aucun modèle à sauvegarder")
            return
        
        with open(self.model_path, 'wb') as f:
            pickle.dump(self.model, f)
        
        print(f"[ML] ✓ Modèle sauvegardé: {self.model_path}")
    
    def load_model(self):
        """Charge un modèle existant"""
        try:
            with open(self.model_path, 'rb') as f:
                self.model = pickle.load(f)
            
            self.is_trained = True
            print(f"[ML] ✓ Modèle chargé: {self.model_path}")
        
        except Exception as e:
            print(f"[ML] Erreur chargement modèle: {e}")
            self.model = None
            self.is_trained = False


def detect(line: str, detector: AnomalyDetector = None) -> Tuple[bool, str, str]:
    """
    Fonction de détection compatible avec le système SIEM
    """
    if detector is None:
        # Créer un détecteur global si nécessaire
        if not hasattr(detect, 'global_detector'):
            detect.global_detector = AnomalyDetector()
        detector = detect.global_detector
    
    if not detector.is_trained:
        return False, None, None
    
    is_anomaly, score = detector.predict(line)
    
    if is_anomaly and score > 0.6:  # Seuil de confiance
        pattern = f"ml_anomaly_score_{score:.2f}"
        return True, pattern, "ML Anomaly"
    
    return False, None, None
