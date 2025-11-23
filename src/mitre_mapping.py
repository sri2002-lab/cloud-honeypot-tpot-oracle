import pandas as pd
import json

df = pd.read_csv(r'C:\Users\sri🍳\Documents\Network security\honeypot_analysis.csv')

# Convert port to numeric
df['port_clean'] = pd.to_numeric(df['DestPort (dest_port)'], errors='coerce')
df = df[df['port_clean'].notna()]

# MITRE ATT&CK mapping
port_ttp_map = {
    22: {'id': 'T1021.004', 'name': 'Remote Services: SSH', 'tactic': 'Lateral Movement'},
    2222: {'id': 'T1021.004', 'name': 'Remote Services: SSH', 'tactic': 'Lateral Movement'},
    5900: {'id': 'T1021.005', 'name': 'Remote Services: VNC', 'tactic': 'Lateral Movement'},
    5901: {'id': 'T1021.005', 'name': 'Remote Services: VNC', 'tactic': 'Lateral Movement'},
    5060: {'id': 'T1499', 'name': 'Endpoint Denial of Service', 'tactic': 'Impact'},
    443: {'id': 'T1071.001', 'name': 'Web Protocols', 'tactic': 'Command and Control'},
    80: {'id': 'T1071.001', 'name': 'Web Protocols', 'tactic': 'Command and Control'},
    21: {'id': 'T1071.002', 'name': 'File Transfer Protocols', 'tactic': 'Command and Control'},
    53: {'id': 'T1071.004', 'name': 'DNS', 'tactic': 'Command and Control'},
}

mitre_mappings = []

for port in df['port_clean'].unique():
    port_int = int(port)
    if port_int in port_ttp_map:
        count = len(df[df['port_clean'] == port])
        mapping = port_ttp_map[port_int].copy()
        mapping['port'] = port_int
        mapping['attack_count'] = int(count)
        mapping['countries'] = df[df['port_clean'] == port]['geoip.country_name'].value_counts().head(3).to_dict()
        mitre_mappings.append(mapping)

# Save
with open(r'C:\Users\sri🍳\Documents\Network security\mitre_attack_mapping.json', 'w') as f:
    json.dump(mitre_mappings, f, indent=2)

print("🎯 MITRE ATT&CK Mapping Complete!\n")
print(f"Mapped {len(mitre_mappings)} TTPs from observed attacks:\n")

for m in sorted(mitre_mappings, key=lambda x: x['attack_count'], reverse=True):
    print(f"{m['id']:12} | Port {m['port']:5} | {m['name']:40} | {m['attack_count']:3} attacks")

print(f"\n✅ Saved to mitre_attack_mapping.json")
