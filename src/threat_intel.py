import pandas as pd
import requests
import time
import json

# Load your cleaned data
df = pd.read_csv(r'C:\Users\sri🍳\Documents\Network security\honeypot_analysis.csv')

# Extract unique IPs
unique_ips = df['src_ip'].dropna().unique()
print(f"🔍 Analyzing {len(unique_ips)} unique attacker IPs...\n")

# Storage for threat intel results
threat_data = []

# FREE Threat Intelligence APIs (no key needed)
def query_abuseipdb(ip):
    """AbuseIPDB - requires free API key from abuseipdb.com"""
    # Get free key at: https://www.abuseipdb.com/api
    API_KEY = "YOUR_KEY_HERE"  # Replace this
    url = f"https://api.abuseipdb.com/api/v2/check"
    headers = {'Key': API_KEY, 'Accept': 'application/json'}
    params = {'ipAddress': ip, 'maxAgeInDays': 90}
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=5)
        if response.status_code == 200:
            return response.json()['data']
    except:
        return None

def query_virustotal(ip):
    """VirusTotal - requires free API key"""
    API_KEY = "YOUR_VT_KEY"  # Get at virustotal.com
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": API_KEY}
    
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()['data']['attributes']
            return {
                'malicious': data['last_analysis_stats']['malicious'],
                'suspicious': data['last_analysis_stats']['suspicious'],
                'country': data.get('country', 'Unknown')
            }
    except:
        return None

def query_shodan(ip):
    """Shodan - requires free API key"""
    API_KEY = "YOUR_SHODAN_KEY"
    url = f"https://api.shodan.io/shodan/host/{ip}?key={API_KEY}"
    
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                'ports': data.get('ports', []),
                'vulns': list(data.get('vulns', [])),
                'org': data.get('org', 'Unknown')
            }
    except:
        return None

def query_ipapi(ip):
    """Free IP geolocation - NO KEY NEEDED"""
    url = f"http://ip-api.com/json/{ip}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return response.json()
    except:
        return None

# Analyze each IP
for i, ip in enumerate(unique_ips[:20], 1):  # Limit to 20 for testing
    print(f"[{i}/20] Analyzing {ip}...")
    
    ip_data = {'ip': ip}
    
    # Query free API (no key needed)
    geo = query_ipapi(ip)
    if geo:
        ip_data['country'] = geo.get('country', 'Unknown')
        ip_data['city'] = geo.get('city', 'Unknown')
        ip_data['isp'] = geo.get('isp', 'Unknown')
        ip_data['is_proxy'] = geo.get('proxy', False)
    
    # Add to results
    threat_data.append(ip_data)
    time.sleep(0.5)  # Rate limiting

# Save results
threat_df = pd.DataFrame(threat_data)
threat_df.to_csv(r'C:\Users\sri🍳\Documents\Network security\threat_intel_results.csv', index=False)

print(f"\n✅ Threat intel saved! Analyzed {len(threat_data)} IPs")
print(threat_df.head(10))
