# scan_url.py
import os
import requests
import pandas as pd

# read API key from environment or .env (simple way)
VT_API_KEY = os.getenv('VT_API_KEY')
if not VT_API_KEY:
    try:
        with open('.env') as f:
            for line in f:
                if line.startswith('VT_API_KEY'):
                    VT_API_KEY = line.strip().split('=', 1)[1]
    except FileNotFoundError:
        pass

if not VT_API_KEY:
    raise SystemExit("VT_API_KEY not found. Add it to your environment or .env file.")

HEADERS = {"x-apikey": VT_API_KEY}
BASE = "https://www.virustotal.com/api/v3"


def scan_url(url: str):
    """Send the URL to VirusTotal and return a small summary."""
    resp = requests.post(f"{BASE}/urls", headers=HEADERS, data={"url": url})
    resp.raise_for_status()
    data = resp.json()
    analysis_id = data["data"]["id"]

    analysis_resp = requests.get(f"{BASE}/analyses/{analysis_id}", headers=HEADERS)
    analysis_resp.raise_for_status()
    analysis = analysis_resp.json()

    stats = analysis.get("data", {}).get("attributes", {}).get("stats", {})
    df = pd.DataFrame(list(stats.items()), columns=["category", "count"])
    return df


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python scan_url.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    result = scan_url(url)
    print("\nVirusTotal quick stats for:", url)
    print(result.to_string(index=False))
