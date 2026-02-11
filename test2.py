import requests

API_KEY = ""

url = "https://api.abuseipdb.com/api/v2/check"
params = {
    "ipAddress": "31.13.164.58",
    "maxAgeInDays": 90
}

headers = {
    "Key": API_KEY,
    "Accept": "application/json"
}

response = requests.get(url, headers=headers, params=params)
data = response.json()

print(data)
