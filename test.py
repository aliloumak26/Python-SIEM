import geoip2.database

reader = geoip2.database.Reader(r'data\GeoLite2-City.mmdb')

try:
    ip_test = "91.224.92.54"
    response = reader.city(ip_test)

    print(f"--- Résultat pour l'IP {ip_test} ---")

    # Pays
    print(f"Pays : {response.country.name}")
    print(f"Code ISO : {response.country.iso_code}")

    # Continent
    print(f"Continent : {response.continent.name}")

    # Ville
    print(f"Ville : {response.city.name}")

    # Région / Wilaya
    if response.subdivisions:
        print(f"Région : {response.subdivisions.most_specific.name}")

    # Coordonnées
    print(f"Latitude : {response.location.latitude}")
    print(f"Longitude : {response.location.longitude}")

    # Fuseau horaire
    print(f"Timezone : {response.location.time_zone}")

except Exception as e:
    print(f"Erreur : {e}")

finally:
    reader.close()
