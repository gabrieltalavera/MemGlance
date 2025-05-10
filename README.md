# MemGlance
MemGlance is a Python tool to visualize process hierarchies and network connections using csv data from memory dumps parsed by Volatility 3 , enabling rapid forensic analysis.

![memglance1](https://github.com/user-attachments/assets/3526b2df-6c5e-4f53-8824-a355acf83aca)

## Features
**Rapid Insights:** Delivers a glanceable view of process/network data, highlighting anomalies at a glance.

**Process Hierarchy Visualization:** Displays parent-child relationships (e.g., explorer.exe → wscript.exe → UWkpjFjDzM.exe) using solid edges.

**Network Connection Mapping:** Shows network activity (e.g., PID → IP:Port) with dashed edges, colored by IP type (orange for external, light green for local).

**Suspicious Process Detection:** Marks processes with network connections in red (e.g., UWkpjFjDzM.exe, POWERPNT.EXE).

**Dual Output:**
Static PNG (network_graph.png) for reports and presentations.
Interactive HTML (network_graph.html) for exploration (zoom, hover for port details).

**Volatility 3 Integration:** Processes CSV outputs from windows.pslist.PsList and windows.netscan.NetScan.



