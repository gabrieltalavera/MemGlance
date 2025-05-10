import networkx as nx
import matplotlib.pyplot as plt
import pandas as pd
from pyvis.network import Network
import os
import pyvis  # For version checking

# Print pyvis version for debugging
print(f"pyvis version: {pyvis.__version__}")

# Paths
output_dir = "output"
volatility_output_dir = "volatility_output"
pslist_file = os.path.join(volatility_output_dir, "pslist.csv")
netscan_file = os.path.join(volatility_output_dir, "netscan.csv")

# Create output directory
os.makedirs(output_dir, exist_ok=True)

# Load pslist CSV (comma-delimited)
try:
    pslist_df = pd.read_csv(pslist_file, sep=',')
    print("pslist.csv columns:", pslist_df.columns.tolist())  # Debug: Show columns
    # Ensure required columns exist
    required_pslist_cols = ["PID", "PPID", "ImageFileName"]
    if not all(col in pslist_df.columns for col in required_pslist_cols):
        raise ValueError(f"pslist.csv missing required columns: {required_pslist_cols}, found: {pslist_df.columns.tolist()}")
    # Convert PID and PPID to integers, handle potential NaN
    pslist_df["PID"] = pd.to_numeric(pslist_df["PID"], errors="coerce").fillna(0).astype(int)
    pslist_df["PPID"] = pd.to_numeric(pslist_df["PPID"], errors="coerce").fillna(0).astype(int)
except FileNotFoundError:
    print(f"Error: {pslist_file} not found. Please run Volatility pslist plugin with -r csv.")
    exit(1)
except Exception as e:
    print(f"Error loading pslist.csv: {e}")
    exit(1)

# Load netscan CSV (tab-delimited)
try:
    netscan_df = pd.read_csv(netscan_file, sep='\t')
    print("netscan.csv columns:", netscan_df.columns.tolist())  # Debug: Show columns
    # Ensure required columns exist
    required_netscan_cols = ["PID", "ForeignAddr", "ForeignPort"]
    if not all(col in netscan_df.columns for col in required_netscan_cols):
        raise ValueError(f"netscan.csv missing required columns: {required_netscan_cols}, found: {netscan_df.columns.tolist()}")
    # Convert PID and ForeignPort to integers, handle potential NaN or invalid values
    netscan_df["PID"] = pd.to_numeric(netscan_df["PID"], errors="coerce").fillna(0).astype(int)
    netscan_df["ForeignPort"] = pd.to_numeric(netscan_df["ForeignPort"], errors="coerce").fillna(0).astype(int)
    # Filter for TCPv4 connections with valid IPs to reduce noise
    netscan_df = netscan_df[(netscan_df["Proto"] == "TCPv4") & 
                            (netscan_df["ForeignAddr"].str.match(r'^\d+\.\d+\.\d+\.\d+$', na=False)) & 
                            (netscan_df["ForeignAddr"] != "0.0.0.0")]
except FileNotFoundError:
    print(f"Error: {netscan_file} not found. Please run Volatility netscan plugin with -r csv.")
    exit(1)
except Exception as e:
    print(f"Error loading netscan.csv: {e}")
    exit(1)

# Create network graph
G = nx.DiGraph()

# Add process nodes and parent-child edges
for _, row in pslist_df.iterrows():
    pid = row["PID"]
    name = row["ImageFileName"]
    # Color processes with network connections as suspicious (red)
    color = "red" if pid in netscan_df["PID"].values else "lightblue"
    G.add_node(pid, label=f"{name} ({pid})", color=color, shape="circle")
    if row["PPID"] in pslist_df["PID"].values and row["PPID"] != 0:
        G.add_edge(row["PPID"], pid, style="solid")

# Add network connections
for _, row in netscan_df.iterrows():
    pid = row["PID"]
    ip = row["ForeignAddr"]
    # Skip if PID or IP is invalid
    if pid == 0 or not ip:
        continue
    # Color external IPs (not local) as orange
    color = "orange" if not ip.startswith("192.168.") and not ip.startswith("10.") else "lightgreen"
    G.add_node(ip, label=ip, color=color, shape="box")
    G.add_edge(pid, ip, style="dashed", label=f"Port: {row['ForeignPort']}")

# Static visualization with matplotlib
plt.figure(figsize=(12, 8))
pos = nx.spring_layout(G)
node_colors = [G.nodes[node]["color"] for node in G.nodes]
nx.draw(G, pos, with_labels=True, labels=nx.get_node_attributes(G, "label"),
        node_color=node_colors, node_size=1000, font_size=8, arrows=True)
edge_styles = nx.get_edge_attributes(G, "style")
for edge in G.edges:
    style = edge_styles.get(edge, "solid")
    nx.draw_networkx_edges(G, pos, edgelist=[edge], style=style)
edge_labels = nx.get_edge_attributes(G, "label")
nx.draw_networkx_edge_labels(G, pos, edge_labels)
plt.title("Process and Network Connection Graph (Volatility 3 - Triage-Memory)")
plt.savefig(os.path.join(output_dir, "network_graph.png"), format="png", dpi=300)
plt.close()

# Interactive visualization with pyvis
net = Network(directed=True, height="600px", width="100%")
for node, data in G.nodes(data=True):
    net.add_node(node, label=data["label"], color=data["color"], shape=data["shape"])
for source, target, data in G.edges(data=True):
    net.add_edge(source, target, dashes=data["style"] == "dashed", title=data.get("label", ""))
try:
    # Updated for newer pyvis versions: Remove notebook parameter
    net.show(os.path.join(output_dir, "network_graph.html"))
except Exception as e:
    print(f"Warning: pyvis show failed: {e}. Generating HTML manually.")
    html_content = net.generate_html()
    with open(os.path.join(output_dir, "network_graph.html"), "w") as f:
        f.write(html_content)

print(f"Graphs saved to {output_dir}/network_graph.png and {output_dir}/network_graph.html")
