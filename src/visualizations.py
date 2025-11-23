import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

# Load data
df = pd.read_csv(r'C:\Users\sri🍳\Documents\Network security\honeypot_analysis.csv')
threat = pd.read_csv(r'C:\Users\sri🍳\Documents\Network security\threat_intel_results.csv')

# Merge threat intel with attack data
df_merged = df.merge(threat[['ip', 'country', 'city', 'isp']], 
                      left_on='src_ip', right_on='ip', how='left')

print("🎨 Creating visualizations...")

# 1. Interactive Geographic Attack Map
country_counts = df_merged['country'].value_counts().reset_index()
country_counts.columns = ['country', 'attacks']

fig1 = px.choropleth(country_counts, 
                     locations='country',
                     locationmode='country names',
                     color='attacks',
                     hover_name='country',
                     color_continuous_scale='Reds',
                     title='Global Attack Heatmap')
fig1.write_html(r'C:\Users\sri🍳\Documents\Network security\attack_map.html')
print("✓ attack_map.html")

# 2. Port Analysis with ISP breakdown
port_df = df.groupby(['DestPort (dest_port)', 'geoip.country_name']).size().reset_index(name='count')
fig2 = px.bar(port_df.head(50), 
              x='DestPort (dest_port)', 
              y='count',
              color='geoip.country_name',
              title='Targeted Ports by Attack Origin',
              labels={'DestPort (dest_port)': 'Port', 'count': 'Attacks'})
fig2.write_html(r'C:\Users\sri🍳\Documents\Network security\port_analysis.html')
print("✓ port_analysis.html")

# 3. Timeline of attacks
df['@timestamp'] = pd.to_datetime(df['@timestamp'], format='%b %d, %Y @ %H:%M:%S.%f')
fig3 = px.scatter(df, 
                  x='@timestamp', 
                  y='src_ip',
                  color='geoip.country_name',
                  hover_data=['DestPort (dest_port)', 'proto'],
                  title='Attack Timeline - Real-time Activity')
fig3.write_html(r'C:\Users\sri🍳\Documents\Network security\timeline.html')
print("✓ timeline.html")

# 4. ISP Analysis - Show which providers host most attackers
isp_counts = df_merged['isp'].value_counts().head(10).reset_index()
isp_counts.columns = ['isp', 'attacks']
fig4 = px.pie(isp_counts, values='attacks', names='isp', 
              title='Top 10 ISPs Hosting Attackers')
fig4.write_html(r'C:\Users\sri🍳\Documents\Network security\isp_analysis.html')
print("✓ isp_analysis.html")

# 5. Attack Protocol Distribution
proto_counts = df['proto'].value_counts()
fig5 = px.sunburst(
    df, 
    path=['proto', 'geoip.country_name'],
    title='Attack Protocols by Country'
)
fig5.write_html(r'C:\Users\sri🍳\Documents\Network security\protocol_sunburst.html')
print("✓ protocol_sunburst.html")

print("\n✅ ALL VISUALIZATIONS CREATED!")
print("\n📂 Open these HTML files in your browser:")
print("  - attack_map.html")
print("  - port_analysis.html")
print("  - timeline.html")
print("  - isp_analysis.html")
print("  - protocol_sunburst.html")
