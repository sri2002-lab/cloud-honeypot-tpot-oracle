import pandas as pd
import os

os.chdir(r'C:\Users\sri🍳\Documents\Network security')

INPUT_FILE = 'kibana_export.csv'
OUTPUT_FILE = 'honeypot_analysis.csv'

print("🔍 Loading honeypot data...")
df = pd.read_csv(INPUT_FILE, on_bad_lines='skip')
print(f"✓ Loaded {len(df):,} rows")

# Use ACTUAL column names from your data
keep_cols = ['@timestamp', 'src_ip', 'dest_ip', 'DestPort (dest_port)',
             'geoip.country_name', 'type', 'proto', 'event_type',
             'username', 'password', 't-pot_hostname']

available = [c for c in keep_cols if c in df.columns]
df_clean = df[available].drop_duplicates()

print(f"✓ Cleaned to {len(df_clean):,} rows with columns: {available}")

# Save
df_clean.to_csv(OUTPUT_FILE, index=False)
print(f"✓ Saved: {OUTPUT_FILE}\n")

# 📊 ATTACK STATISTICS
print("📊 ATTACK STATISTICS:\n")

if 'src_ip' in df_clean.columns:
    print(f"🔹 Unique Attacker IPs: {df_clean['src_ip'].nunique():,}\n")
    print("Top 10 Attacking IPs:")
    print(df_clean['src_ip'].value_counts().head(10).to_string())
    print()

if 'DestPort (dest_port)' in df_clean.columns:
    print("🔹 Top 5 Targeted Ports:")
    print(df_clean['DestPort (dest_port)'].value_counts().head(5).to_string())
    print()

if 'geoip.country_name' in df_clean.columns:
    print("🔹 Top 5 Attack Countries:")
    print(df_clean['geoip.country_name'].value_counts().head(5).to_string())
    print()

if 'type' in df_clean.columns:
    print("🔹 Attack Types:")
    print(df_clean['type'].value_counts().to_string())
    print()

if 'username' in df_clean.columns:
    print(f"🔹 Unique Usernames Attempted: {df_clean['username'].nunique():,}")
    print("Top 10 Usernames:")
    print(df_clean['username'].value_counts().head(10).to_string())

print("\n✅ ANALYSIS COMPLETE!")
