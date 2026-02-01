import sqlite3
import sys
import os

# Chemin vers la base de données
DB_PATH = 'siem.db'

def run_query(query):
    if not os.path.exists(DB_PATH):
        print(f"Erreur: Le fichier '{DB_PATH}' est introuvable.")
        return

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(query)
        
        # Si c'est une requête qui lit des données (SELECT)
        if query.strip().upper().startswith("SELECT"):
            rows = cursor.fetchall()
            if cursor.description:
                headers = [description[0] for description in cursor.description]
                print("\n" + " | ".join(f"{h:<15}" for h in headers))
                print("-" * (18 * len(headers)))
                
                for row in rows:
                    # Convertir chaque élément en string pour l'affichage
                    print(" | ".join(f"{str(item):<15}" for item in row))
                print(f"\n({len(rows)} résultats)\n")
            else:
                print("Aucun résultat.")
        
        # Si c'est une requête qui modifie des données (INSERT, UPDATE, DELETE)
        else:
            conn.commit()
            print(f"✓ Commande exécutée avec succès. ({cursor.rowcount} lignes affectées)")
            
        conn.close()
    except Exception as e:
        print(f"❌ Erreur SQL : {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Mode argument : python db_tool.py "SELECT * FROM alerts"
        run_query(" ".join(sys.argv[1:]))
    else:
        # Mode interactif
        print(f"--- Console SQL pour '{DB_PATH}' ---")
        print("Tapez vos requêtes SQL (ex: SELECT * FROM alerts;)")
        print("Tapez 'tables' pour voir la liste des tables.")
        print("Tapez 'exit' pour quitter.\n")
        
        while True:
            try:
                q = input("SQL > ").strip()
                if not q: continue
                
                if q.lower() in ['exit', 'quit']:
                    break
                
                if q.lower() == 'tables':
                    q = "SELECT name FROM sqlite_master WHERE type='table'"
                
                run_query(q)
            except KeyboardInterrupt:
                print("\nAnnulé.")
                break
