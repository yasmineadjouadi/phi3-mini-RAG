"""
Lance ce script avec le serveur FastAPI démarré pour tester
les IOC qui ont échoué dans le dernier evaluate.
Usage: python debug_errors.py
"""
import requests
import json

API_URL = "http://127.0.0.1:8000"

# IOC qui ont échoué dans resultats_eval.json
FAILED_IOCS = [
    {"indicator": "11e749078065aa2c7c9ebbf35b8c59c9ad4e804bb1240f432c8e6f4c628894b7", "type": "hash"},
    {"indicator": "20513dd82fcb630c8a50dbd662bae6f76304a2a057346f95bb07713fcc34fba1", "type": "hash"},
    {"indicator": "track.blogmarketcom.fr", "type": "domain"},
]

def test_ioc(indicator, ioc_type):
    print(f"\n{'='*60}")
    print(f"Testing: {indicator} ({ioc_type})")
    try:
        resp = requests.post(
            f"{API_URL}/ioc/analyze",
            json={"indicator": indicator},
            params={"force_rag": "true"},
            timeout=30,
            headers={"Content-Type": "application/json"}
        )
        print(f"Status: {resp.status_code}")
        if resp.status_code != 200:
            print(f"Error body: {resp.text[:500]}")
        else:
            data = resp.json()
            print(f"Result: {json.dumps(data, indent=2)[:300]}")
    except Exception as e:
        print(f"Exception: {e}")

# Test aussi les endpoints individuels
def test_endpoint(path, indicator):
    print(f"\nTesting endpoint {path} with {indicator}")
    try:
        resp = requests.get(f"{API_URL}/{path}/{indicator}", timeout=30)
        print(f"Status: {resp.status_code}")
        if resp.status_code != 200:
            print(f"Error: {resp.text[:300]}")
    except Exception as e:
        print(f"Exception: {e}")

if __name__ == "__main__":
    # Test health
    try:
        r = requests.get(f"{API_URL}/", timeout=5)
        print(f"API Health: {r.json()}")
    except:
        print("API non accessible — lance uvicorn d'abord")
        exit()

    for item in FAILED_IOCS:
        test_ioc(item["indicator"], item["type"])

    # Test un hash proprement via endpoint direct
    print("\n--- Test endpoint /hash direct ---")
    test_endpoint("hash", "11e749078065aa2c7c9ebbf35b8c59c9ad4e804bb1240f432c8e6f4c628894b7")