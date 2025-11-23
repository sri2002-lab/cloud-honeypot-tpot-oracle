import pandas as pd
import os

# Ensure the script works from any launch location:
os.chdir(r'C:\Users\sri🍳\Documents\Network security')

INPUT_FILE = 'kibana_export.csv'
OUTPUT_FILE = 'cleaned_honeypot_data.csv'

print("🔍 Processing honeypot data...")

try:
    df = pd.read_csv(INPUT_FILE, on_bad_lines='skip')
    print(f"✓ Loaded {len(df):,} rows")

    cols = ['@timestamp', 'source.ip', 'destination.port', 'event.action', 
            'user.name', 'source.geo.country_name', 'event.dataset']
    cols = [c for c in cols if c in df.columns]
    df = df[cols]

    df = df.drop_duplicates()
    print(f"✓ Cleaned to {len(df):,} rows")

    df.to_csv(OUTPUT_FILE, index=False)
    size_in = os.path.getsize(INPUT_FILE) / (1024*1024)
    size_out = os.path.getsize(OUTPUT_FILE) / (1024*1024)
    print(f"✓ Saved: {size_in:.0f}MB → {size_out:.0f}MB")
    print(f"✓ File: {OUTPUT_FILE}")

except Exception as e:
    print(f"❌ Error: {e}")
