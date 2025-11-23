import json
import pandas as pd
from datetime import datetime

print("📝 Generating Comprehensive Technical Report...\n")

# Load all data
df = pd.read_csv(r'C:\Users\sri🍳\Documents\Network security\honeypot_analysis.csv')
threat = pd.read_csv(r'C:\Users\sri🍳\Documents\Network security\threat_intel_results.csv')

with open(r'C:\Users\sri🍳\Documents\Network security\ml_results.json') as f:
    ml_results = json.load(f)

with open(r'C:\Users\sri🍳\Documents\Network security\mitre_attack_mapping.json') as f:
    mitre = json.load(f)

# Generate report
report = f"""
╔════════════════════════════════════════════════════════════════╗
║     HONEYPOT THREAT INTELLIGENCE ANALYSIS REPORT               ║
║     Advanced Cybersecurity Analytics & ML Prediction           ║
╚════════════════════════════════════════════════════════════════╝

Generated: {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}

═══════════════════════════════════════════════════════════════════
1. EXECUTIVE SUMMARY
═══════════════════════════════════════════════════════════════════

Total Attack Events: {len(df):,}
Unique Attacker IPs: {df['src_ip'].nunique()}
Attack Duration: {df['@timestamp'].min()} to {df['@timestamp'].max()}
Geographic Coverage: {df['geoip.country_name'].nunique()} countries

Machine Learning Model Accuracy: {ml_results['accuracy']*100:.1f}%
MITRE ATT&CK TTPs Identified: {len(mitre)}

═══════════════════════════════════════════════════════════════════
2. ATTACK DISTRIBUTION BY CATEGORY
═══════════════════════════════════════════════════════════════════

"""

for cat, count in ml_results['attack_categories'].items():
    pct = (count / ml_results['total_samples']) * 100
    report += f"  {cat:15} : {count:3} attacks ({pct:5.1f}%)\n"

report += f"""
═══════════════════════════════════════════════════════════════════
3. TOP THREAT ACTORS (by attack count)
═══════════════════════════════════════════════════════════════════

"""

top_ips = df['src_ip'].value_counts().head(10)
for idx, (ip, count) in enumerate(top_ips.items(), 1):
    country = df[df['src_ip']==ip]['geoip.country_name'].iloc[0] if len(df[df['src_ip']==ip]) > 0 else 'Unknown'
    report += f"  {idx:2}. {ip:18} | {count:3} attacks | {country}\n"

report += f"""
═══════════════════════════════════════════════════════════════════
4. GEOGRAPHIC THREAT LANDSCAPE
═══════════════════════════════════════════════════════════════════

"""

top_countries = df['geoip.country_name'].value_counts().head(10)
for country, count in top_countries.items():
    pct = (count / len(df)) * 100
    report += f"  {country:20} : {count:3} attacks ({pct:5.1f}%)\n"

report += f"""
═══════════════════════════════════════════════════════════════════
5. MITRE ATT&CK FRAMEWORK MAPPING
═══════════════════════════════════════════════════════════════════

"""

for m in sorted(mitre, key=lambda x: x['attack_count'], reverse=True):
    report += f"  {m['id']:12} | Port {m['port']:5} | {m['name']:40}\n"
    report += f"                Attack Count: {m['attack_count']:3} | Tactic: {m['tactic']}\n\n"

report += f"""
═══════════════════════════════════════════════════════════════════
6. MACHINE LEARNING INSIGHTS
═══════════════════════════════════════════════════════════════════

Model Type: Random Forest Classifier
Accuracy: {ml_results['accuracy']*100:.1f}%
Training Samples: 213
Test Samples: 92

Feature Importance Rankings:
"""

for feat in ml_results['feature_importance']:
    report += f"  {feat['Feature']:20} : {feat['Importance']:.3f}\n"

report += f"""
KEY FINDING: Port number is the strongest attack predictor (60.8% importance),
indicating attackers systematically target specific services.

═══════════════════════════════════════════════════════════════════
7. TARGETED SERVICES ANALYSIS
═══════════════════════════════════════════════════════════════════

"""

port_counts = df['DestPort (dest_port)'].value_counts().head(10)
for port, count in port_counts.items():
    report += f"  Port {str(port):5} : {count:3} attacks\n"

report += f"""
═══════════════════════════════════════════════════════════════════
8. THREAT INTELLIGENCE ENRICHMENT
═══════════════════════════════════════════════════════════════════

ISP Distribution of Threat Actors:
"""

merged_df = df.merge(threat[['ip', 'isp']], left_on='src_ip', right_on='ip', how='left')
top_isps = merged_df['isp'].value_counts().head(5)
for isp, count in top_isps.items():
    if pd.notna(isp):
        report += f"  {isp[:50]:50} : {count:3} attacks\n"

report += f"""
═══════════════════════════════════════════════════════════════════
9. CONCLUSIONS & RECOMMENDATIONS
═══════════════════════════════════════════════════════════════════

1. VNC (Port 5900) is the PRIMARY attack vector with 159 attacks (52%)
   → Recommendation: Block/restrict VNC access, implement MFA

2. Attacks originate from {df['geoip.country_name'].nunique()} countries, indicating distributed threat actors
   → Recommendation: Implement geo-blocking for high-risk regions

3. ML model achieved 95.7% accuracy in attack classification
   → Recommendation: Deploy automated threat detection system

4. 7 distinct MITRE ATT&CK TTPs identified across 3 tactics
   → Recommendation: Align security controls with ATT&CK framework

5. DigitalOcean hosting most threat actors (cloud infrastructure abuse)
   → Recommendation: Enhanced monitoring of cloud-based threats

═══════════════════════════════════════════════════════════════════
END OF REPORT
═══════════════════════════════════════════════════════════════════
"""

# Save report
with open(r'C:\Users\sri🍳\Documents\Network security\COMPREHENSIVE_REPORT.txt', 'w', encoding='utf-8') as f:
    f.write(report)

print(report)
print("\n✅ Report saved to: COMPREHENSIVE_REPORT.txt")
