import streamlit as st
import requests
import pandas as pd

# Read API key from Streamlit Secrets
VT_API_KEY = st.secrets.get("VT_API_KEY")
if not VT_API_KEY:
    raise SystemExit("❌ VT_API_KEY not found in Streamlit Secrets!")

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
